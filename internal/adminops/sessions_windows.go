//go:build windows

package adminops

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Taminum/Owlery/internal/secproto"
)

var (
	wtsapi                 = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSEnumSessions    = wtsapi.NewProc("WTSEnumerateSessionsW")
	procWTSQueryInfo       = wtsapi.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory      = wtsapi.NewProc("WTSFreeMemory")
	procWTSLogoffSession   = wtsapi.NewProc("WTSLogoffSession")
	procWTSDisconnectSess  = wtsapi.NewProc("WTSDisconnectSession")
	wtsStateNames          = []string{"active", "connected", "connecting", "shadow", "disconnected", "idle", "listening", "reset", "down", "init"}
	wtsUserName, wtsClient = uintptr(5), uintptr(10)
)

type sessionInfo struct {
	ID     uint32 `json:"id"`
	User   string `json:"user,omitempty"`
	State  string `json:"state"`
	Client string `json:"client,omitempty"` // the computer a remote session comes from
	Name   string `json:"name,omitempty"`   // console, rdp-tcp#N
}

// wtsString reads one string property of a session.
func wtsString(id uint32, class uintptr) string {
	var buf *uint16
	var n uint32
	r, _, _ := procWTSQueryInfo.Call(0, uintptr(id), class, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || buf == nil {
		return ""
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(buf)))
	return windows.UTF16PtrToString(buf)
}

func listSessions() (any, error) {
	var info unsafe.Pointer
	var count uint32
	if r, _, err := procWTSEnumSessions.Call(0, 0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&count))); r == 0 {
		return nil, fmt.Errorf("список сеансов: %w", err)
	}
	defer procWTSFreeMemory.Call(uintptr(info))
	// WTS_SESSION_INFOW: SessionId uint32, pWinStationName *uint16, State uint32 (laid out with padding on amd64).
	type wtsInfo struct {
		ID    uint32
		Name  *uint16
		State uint32
	}
	var out []sessionInfo
	for _, w := range unsafe.Slice((*wtsInfo)(info), count) {
		if w.State == 6 { // the listener of the RDP service, not a session of anybody
			continue
		}
		s := sessionInfo{ID: w.ID, Name: windows.UTF16PtrToString(w.Name), User: wtsString(w.ID, wtsUserName), Client: wtsString(w.ID, wtsClient)}
		if int(w.State) < len(wtsStateNames) {
			s.State = wtsStateNames[w.State]
		}
		if w.ID == 0 || (s.User == "" && s.State != "active") {
			continue // session 0 is where services run, and a session nobody signed in to has nothing to manage
		}
		out = append(out, s)
	}
	return out, nil
}

func endSession(op string, id uint32) error {
	proc := procWTSLogoffSession
	if op == secproto.AdminSessionDisconn {
		proc = procWTSDisconnectSess
	}
	if r, _, err := proc.Call(0, uintptr(id), 0); r == 0 {
		return fmt.Errorf("не удалось: %w", err)
	}
	return nil
}

// --- event log -----------------------------------------------------------------------------------

type eventQuery struct {
	Log   string `json:"log"`   // System | Application | Security
	Level int    `json:"level"` // 1 critical, 2 error, 3 warning, 4 information: this one and the more serious
	Limit int    `json:"limit"`
}

type eventInfo struct {
	Time     string `json:"time"`
	Log      string `json:"log"`
	Source   string `json:"source"`
	ID       int    `json:"id"`
	Level    string `json:"level"`
	Message  string `json:"message,omitempty"`
	Computer string `json:"computer,omitempty"`
}

type eventXML struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     int `xml:"EventID"`
		Level       int `xml:"Level"`
		TimeCreated struct {
			At string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	Rendering struct {
		Message string `xml:"Message"`
		Level   string `xml:"Level"`
	} `xml:"RenderingInfo"`
}

func listEvents(ctx context.Context, q eventQuery) (any, error) {
	switch q.Log {
	case "System", "Application", "Security":
	case "":
		q.Log = "System"
	default:
		return nil, errors.New("журнал: System, Application или Security")
	}
	if q.Level < 1 || q.Level > 4 {
		q.Level = 3
	}
	if q.Limit < 1 || q.Limit > maxEvents {
		q.Limit = 100
	}
	// The query is built here from numbers and a fixed name, never from text sent by the page.
	var levels []string
	for l := 1; l <= q.Level; l++ {
		levels = append(levels, "Level="+strconv.Itoa(l))
	}
	xpath := "*[System[(" + strings.Join(levels, " or ") + ")]]"
	cmd := exec.CommandContext(ctx, "wevtutil", "qe", q.Log, "/c:"+strconv.Itoa(q.Limit), "/rd:true", "/f:RenderedXml", "/q:"+xpath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	raw, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("журнал не прочитан: %w", err)
	}
	dec := xml.NewDecoder(bytes.NewReader(append(append([]byte("<Events>"), raw...), []byte("</Events>")...)))
	var wrap struct {
		Events []eventXML `xml:"Event"`
	}
	if err := dec.Decode(&wrap); err != nil {
		return nil, fmt.Errorf("журнал не разобрать: %w", err)
	}
	out := make([]eventInfo, 0, len(wrap.Events))
	for _, e := range wrap.Events {
		msg := strings.TrimSpace(e.Rendering.Message)
		if len(msg) > 600 {
			msg = msg[:600] + "…"
		}
		out = append(out, eventInfo{Time: e.System.TimeCreated.At, Log: q.Log, Source: e.System.Provider.Name, ID: e.System.EventID,
			Level: e.Rendering.Level, Message: msg, Computer: e.System.Computer})
	}
	return out, nil
}
