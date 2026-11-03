//go:build windows

package remotehelper

import (
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wtsapi32                       = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformation = wtsapi32.NewProc("WTSQuerySessionInformationW")
	attachMu                       sync.Mutex
	lastAttach                     time.Time
)

const (
	wtsConnectState = 8 // WTS_INFO_CLASS WTSConnectState
	wtsDisconnected = 4 // WTS_CONNECTSTATE_CLASS WTSDisconnected
)

// mySession is the Windows session this helper runs in.
func mySession() uint32 {
	var id uint32
	_ = windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &id)
	return id
}

// connectState is the connection state of a session (WTSActive 0 ... WTSDisconnected 4), or -1 if it cannot be read.
func connectState(sid uint32) int {
	var buf unsafe.Pointer
	var n uint32
	if r, _, _ := procWTSQuerySessionInformation.Call(0, uintptr(sid), wtsConnectState, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n))); r == 0 || buf == nil {
		return -1
	}
	defer windows.WTSFreeMemory(uintptr(buf))
	return int(*(*int32)(buf))
}

// attachToConsole is tried when the screen cannot be read: a remote-desktop session whose client has gone has no display,
// and moving it to the console gives it one. It runs in the helper itself, which is in the very session concerned and
// so cannot be a stale one left over from before the move. The state and the outcome go to the log either way.
func attachToConsole(foll *follower) bool {
	sid := mySession()
	state := connectState(sid)
	slog.Info("screen: cannot read the screen", "session", sid, "connect_state", state)
	if state != wtsDisconnected {
		return false
	}
	attachMu.Lock()
	defer attachMu.Unlock()
	if time.Since(lastAttach) < 20*time.Second {
		return false
	}
	lastAttach = time.Now()
	out, err := exec.Command(os.ExpandEnv(`${SystemRoot}\System32\tscon.exe`), strconv.Itoa(int(sid)), "/dest:console").CombinedOutput()
	slog.Info("screen: attached a disconnected session to the console", "session", sid, "err", err, "out", strings.TrimSpace(string(out)))
	time.Sleep(1500 * time.Millisecond)
	foll.forget()
	slog.Info("screen: after the attach", "session", sid, "connect_state", connectState(sid))
	return true
}

// disconnectedNote is the explanation for a session that could not be shown because nobody is connected to it.
func disconnectedNote() string {
	if connectState(mySession()) == wtsDisconnected {
		return "сеанс отключён (закрыто окно удалённого рабочего стола), и у него нет экрана. Подключитесь к нему через вкладку «Рабочий стол»"
	}
	return ""
}
