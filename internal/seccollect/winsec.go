package seccollect

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Taminum/Owlery/internal/secproto"
)

// Winsec reads what Windows says about sign-ins from other machines (the Security log) and about Defender (its
// status and its detections). It only reads, through wevtutil and PowerShell started without a shell. The counters
// count from the moment it was made, so a snapshot is only meaningful next to the one before it: the server subtracts.
type Winsec struct {
	run  Runner
	now  func() time.Time
	secN int64 // newest Security event already counted; 0 until the first read
	defN int64 // the same for Defender's log
	idle int

	failed, ok, threatsTotal int64
	sources                  map[string]int
	recentOK                 []secproto.WinLogon
	threats                  []secproto.WinThreat
	defender                 secproto.WinDefender
	defAt                    time.Time
	defOK                    bool // the Defender log exists on this machine
}

const (
	secLog           = "Security"
	defLog           = "Microsoft-Windows-Windows Defender/Operational"
	maxEventsPerRead = 500
	defenderEvery    = 5 * time.Minute
	maxSources       = 2000
)

// NewWinsec makes a reader that runs commands through r. Tests give it a scripted one.
func NewWinsec(r Runner) *Winsec {
	return &Winsec{run: r, now: time.Now, sources: map[string]int{}, defender: secproto.WinDefender{SignatureDays: -1}, defOK: true}
}

type winEvent struct {
	ID   int
	Rec  int64
	At   time.Time
	Data map[string]string
}

type winEventXML struct {
	System struct {
		ID   int `xml:"EventID"`
		Time struct {
			At string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Rec int64 `xml:"EventRecordID"`
	} `xml:"System"`
	Data []struct {
		Name string `xml:"Name,attr"`
		V    string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

// parseEvents reads the XML wevtutil prints: a run of <Event> elements with no root around them.
func parseEvents(out string) []winEvent {
	var wrapped struct {
		Events []winEventXML `xml:"Event"`
	}
	if err := xml.Unmarshal([]byte("<Events>"+toUTF8(out)+"</Events>"), &wrapped); err != nil {
		return nil
	}
	evs := make([]winEvent, 0, len(wrapped.Events))
	for _, e := range wrapped.Events {
		ev := winEvent{ID: e.System.ID, Rec: e.System.Rec, Data: map[string]string{}}
		ev.At, _ = time.Parse(time.RFC3339Nano, e.System.Time.At)
		for _, d := range e.Data {
			ev.Data[d.Name] = strings.TrimSpace(d.V)
		}
		evs = append(evs, ev)
	}
	return evs
}

// toUTF8 makes what wevtutil printed fit for an XML parser. Into a pipe it writes in the console's code page, so a
// Russian account name arrives as cp866 bytes, which are not UTF-8, and one such name used to sink the whole batch.
// Text that is not valid UTF-8 is read as cp866 (the Russian console); anything left over becomes "?".
func toUTF8(s string) string {
	if utf8.ValidString(s) {
		return stripXMLControls(s)
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c < 0x80:
			b.WriteByte(c)
		case c >= 0x80 && c <= 0xAF:
			b.WriteRune(rune(0x410 + int(c-0x80)))
		case c >= 0xE0 && c <= 0xEF:
			b.WriteRune(rune(0x440 + int(c-0xE0)))
		case c == 0xF0:
			b.WriteRune('Ё')
		case c == 0xF1:
			b.WriteRune('ё')
		default:
			b.WriteByte('?')
		}
	}
	return stripXMLControls(b.String())
}

// stripXMLControls drops the control characters XML does not allow; a log entry may carry any text.
func stripXMLControls(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return -1
		}
		return r
	}, s)
}

var recordIDRe = regexp.MustCompile(`<EventRecordID>(\d+)</EventRecordID>`)

// highestRecord finds the biggest record number in text that could not be parsed, so a bad batch is skipped over
// instead of being read again forever.
func highestRecord(out string) int64 {
	var hi int64
	for _, m := range recordIDRe.FindAllStringSubmatch(out, -1) {
		if n, err := strconv.ParseInt(m[1], 10, 64); err == nil && n > hi {
			hi = n
		}
	}
	return hi
}

// remoteAddr says whether s is the address of another machine: empty, "-", loopback and unspecified are not.
func remoteAddr(s string) (string, bool) {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() {
		return "", false
	}
	return ip.String(), true
}

func (w *Winsec) query(ctx context.Context, log, filter string, count int) (Result, []winEvent) {
	args := []string{"qe", log, "/f:xml", "/c:" + strconv.Itoa(count)}
	if filter != "" {
		args = append(args, "/q:"+filter)
	}
	res := w.run.Run(ctx, "wevtutil", args...)
	if res.Err != nil || res.ExitCode != 0 {
		return res, nil
	}
	return res, parseEvents(res.Stdout)
}

// newest asks for the latest event of a log, whatever it is, to know where "now" is.
func (w *Winsec) newest(ctx context.Context, log string) (int64, Result) {
	res := w.run.Run(ctx, "wevtutil", "qe", log, "/f:xml", "/c:1", "/rd:true")
	if res.Err != nil || res.ExitCode != 0 {
		return 0, res
	}
	evs := parseEvents(res.Stdout)
	if len(evs) == 0 {
		return 1, res // an empty log: anything that comes later has a higher number
	}
	return evs[0].Rec, res
}

func (w *Winsec) readSecurity(ctx context.Context) (denied bool, failed bool) {
	if w.secN == 0 {
		n, res := w.newest(ctx, secLog)
		if n == 0 {
			return winDenied(res), true
		}
		w.secN = n
		return false, false
	}
	filter := "*[System[(EventID=4625 or EventID=4624) and EventRecordID>" + strconv.FormatInt(w.secN, 10) + "]]"
	res, evs := w.query(ctx, secLog, filter, maxEventsPerRead)
	if res.Err != nil || res.ExitCode != 0 {
		return winDenied(res), true
	}
	for _, e := range evs {
		if e.Rec > w.secN {
			w.secN = e.Rec
		}
		w.count(e)
	}
	// Text came back but nothing could be read from it: step over it rather than meet the same batch every time.
	if len(evs) == 0 && strings.TrimSpace(res.Stdout) != "" {
		if hi := highestRecord(res.Stdout); hi > w.secN {
			w.secN = hi
		}
	}
	// A cleared log starts numbering again; when nothing new came for a while, check that our place still exists.
	if len(evs) == 0 {
		if w.idle++; w.idle >= 20 {
			w.idle = 0
			if n, _ := w.newest(ctx, secLog); n > 0 && n < w.secN {
				w.secN = n
			}
		}
	} else {
		w.idle = 0
	}
	return false, false
}

func (w *Winsec) count(e winEvent) {
	lt := e.Data["LogonType"]
	ip, remote := remoteAddr(e.Data["IpAddress"])
	switch e.ID {
	case 4625:
		if !remote || (lt != "3" && lt != "10") {
			return
		}
		w.failed++
		w.sources[ip]++
		if len(w.sources) > maxSources {
			w.trimSources()
		}
	case 4624:
		user := e.Data["TargetUserName"]
		if lt != "10" || !remote || user == "" || strings.HasSuffix(user, "$") {
			return
		}
		w.ok++
		w.recentOK = append([]secproto.WinLogon{{ID: e.Rec, User: user, IP: ip, At: e.At}}, w.recentOK...)
		if len(w.recentOK) > secproto.MaxWinsecRecent {
			w.recentOK = w.recentOK[:secproto.MaxWinsecRecent]
		}
	}
}

func (w *Winsec) trimSources() {
	type kv struct {
		ip string
		n  int
	}
	all := make([]kv, 0, len(w.sources))
	for ip, n := range w.sources {
		all = append(all, kv{ip, n})
	}
	sort.Slice(all, func(a, b int) bool { return all[a].n > all[b].n || (all[a].n == all[b].n && all[a].ip < all[b].ip) })
	w.sources = map[string]int{}
	for _, x := range all[:maxSources/2] {
		w.sources[x.ip] = x.n
	}
}

func (w *Winsec) readDefenderLog(ctx context.Context) {
	if !w.defOK {
		return
	}
	if w.defN == 0 {
		n, res := w.newest(ctx, defLog)
		if n == 0 {
			if res.Err != nil || res.ExitCode != 0 {
				w.defOK = false // no such log here: Defender is not in use
			}
			return
		}
		w.defN = n
		return
	}
	filter := "*[System[(EventID=1116 or EventID=1117) and EventRecordID>" + strconv.FormatInt(w.defN, 10) + "]]"
	res, evs := w.query(ctx, defLog, filter, 100)
	if res.Err != nil || res.ExitCode != 0 {
		return
	}
	for _, e := range evs {
		if e.Rec > w.defN {
			w.defN = e.Rec
		}
		if e.ID != 1116 { // 1116 is "found", 1117 is "acted"; one entry per find is enough
			continue
		}
		w.threatsTotal++
		w.threats = append([]secproto.WinThreat{{ID: e.Rec, Name: cut(e.Data["Threat Name"], 120), Severity: cut(e.Data["Severity Name"], 32), Path: cut(e.Data["Path"], 200), At: e.At}}, w.threats...)
		if len(w.threats) > secproto.MaxWinsecRecent {
			w.threats = w.threats[:secproto.MaxWinsecRecent]
		}
	}
}

func cut(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

const defenderScript = `[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); try { $s = Get-MpComputerStatus -ErrorAction Stop; ConvertTo-Json -Compress @{ e = [bool]$s.AntivirusEnabled; r = [bool]$s.RealTimeProtectionEnabled; a = [int]$s.AntivirusSignatureAge } } catch { 'none' }`

func (w *Winsec) readDefenderStatus(ctx context.Context, now time.Time) {
	if !w.defAt.IsZero() && now.Sub(w.defAt) < defenderEvery {
		return
	}
	w.defAt = now
	res := w.run.Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", defenderScript)
	if res.Err != nil || res.ExitCode != 0 {
		return // keep what was known
	}
	var v struct {
		E bool `json:"e"`
		R bool `json:"r"`
		A int  `json:"a"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(res.Stdout)), &v); err != nil {
		w.defender = secproto.WinDefender{SignatureDays: -1} // "none", or something unreadable: not in use here
		return
	}
	w.defender = secproto.WinDefender{Present: true, Enabled: v.E, Realtime: v.R, SignatureDays: v.A}
}

// Collect reads everything new and returns the snapshot.
func (w *Winsec) Collect(ctx context.Context) Snapshot {
	snap := Snapshot{Category: secproto.CatWinsec}
	if denied, failed := w.readSecurity(ctx); failed {
		snap.Status = secproto.StatusError
		if denied {
			snap.Status = secproto.StatusPermissionDenied
		}
		return snap
	}
	now := w.now()
	w.readDefenderLog(ctx)
	w.readDefenderStatus(ctx, now)

	src := make([]secproto.WinSource, 0, len(w.sources))
	for ip, n := range w.sources {
		src = append(src, secproto.WinSource{IP: ip, Failed: n})
	}
	sort.Slice(src, func(a, b int) bool {
		return src[a].Failed > src[b].Failed || (src[a].Failed == src[b].Failed && src[a].IP < src[b].IP)
	})
	if len(src) > secproto.MaxWinsecSources {
		src = src[:secproto.MaxWinsecSources]
	}
	snap.Status = secproto.StatusOK
	snap.Data = secproto.Winsec{
		RemoteFailed: w.failed, RemoteOK: w.ok, Sources: src, RecentOK: append([]secproto.WinLogon{}, w.recentOK...),
		Defender: w.defender, Threats: append([]secproto.WinThreat{}, w.threats...), ThreatsTotal: w.threatsTotal,
	}
	return snap
}

// winDenied: wevtutil exits with 5 (ERROR_ACCESS_DENIED) whatever language its message is in.
func winDenied(r Result) bool {
	return r.ExitCode == 5 || r.denied() || strings.Contains(strings.ToLower(r.Stderr+r.Stdout), "access is denied")
}
