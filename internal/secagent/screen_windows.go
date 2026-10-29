//go:build windows

package secagent

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/secshell"
)

// openScreen starts the screen-sharing helper in the signed-in person's own session and relays one session to it. The
// agent runs as the system account in session 0, which cannot see any desktop, so the helper has to be launched into
// the interactive session; running it there as the system account (rather than the person's limited rights) is what
// lets it reach the secure desktop, where UAC prompts and the lock screen are drawn. If nobody is signed in there is no
// session to launch into: the agent says so by not connecting back, and Owlery tells the person.
func (a *agent) openScreen(req secproto.RemoteOpen) {
	exe, err := os.Executable()
	if err != nil {
		a.cfg.Log.Warn("screen: cannot find own path", "err", err)
		return
	}
	sid, why := pickSession(req.Session)
	port := secproto.RemoteHelperPortFor(sid)
	a.cfg.Log.Info("screen: session chosen", "session", sid, "why", why)
	// The helper stays alive after a session, so a second launch would only fail to take the port: start one only when
	// none is listening for this session.
	if portOpen(port) {
		goto relay
	}
	// The helper is this same binary, run as "screen-helper" inside that session.
	if err := startInSession(exe, sid, "screen-helper", "-secret-file", a.cfg.RemoteSecretFile, "-port", strconv.Itoa(port)); err != nil {
		// A helper may already be running from an earlier session; only say something when there is also no one to talk
		// to, which the dial below will find out.
		a.cfg.Log.Warn("screen: launching the helper in the session", "session", sid, "err", err)
	}
	waitForPort(a.runCtx, port, 8*time.Second)
relay:
	if err := secshell.RemoteTunnel(a.runCtx, a.dialBack, a.cfg.RemoteSecretFile, port, req); err != nil {
		a.cfg.Log.Warn("screen", "err", err)
	}
}

// portOpen says whether something is already listening on the loopback port.
func portOpen(port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// waitForPort returns once something is listening on the loopback port, or after the timeout. The freshly launched
// helper takes a moment to start listening.
func waitForPort(ctx interface{ Done() <-chan struct{} }, port int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 300*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// pickSession chooses the Windows session whose screen is shown, and says why. The administrator may be signed in at the
// physical console or over remote desktop (the usual way to work on a server), so the console is not always the answer:
// a person at the console comes first; otherwise the first session with somebody signed in and connected, which is where
// a remote-desktop administrator is; with nobody signed in anywhere, the console, whose sign-in screen is then shown.
func pickSession(wanted uint32) (uint32, string) {
	console := windows.WTSGetActiveConsoleSessionId()
	signedIn := func(id uint32) bool {
		var tok windows.Token
		if windows.WTSQueryUserToken(id, &tok) != nil {
			return false
		}
		tok.Close()
		return true
	}
	var info *windows.WTS_SESSION_INFO
	var count uint32
	listed := windows.WTSEnumerateSessions(0, 0, 1, &info, &count) == nil && info != nil
	if listed {
		defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	}
	// The administrator chose one in the page: honoured only if it is a session that exists, never an arbitrary number.
	if wanted != 0 && listed {
		for _, s := range unsafe.Slice(info, count) {
			if s.SessionID == wanted {
				return wanted, "chosen in the page"
			}
		}
	}
	if console != 0xFFFFFFFF && signedIn(console) {
		return console, "somebody is signed in at the console"
	}
	if listed {
		for _, s := range unsafe.Slice(info, count) {
			// State 0 is active and 1 connected: a disconnected session has no screen to show.
			if s.SessionID != 0 && s.State <= 1 && signedIn(s.SessionID) {
				return s.SessionID, "somebody is signed in over remote desktop"
			}
		}
	}
	if console == 0xFFFFFFFF {
		return 1, "no session found"
	}
	return console, "nobody is signed in: the console's sign-in screen"
}

// startInSession launches exe (with the given arguments) as the system account inside one Windows session, on its
// interactive desktop. It duplicates the agent's own system token, stamps it with the session's id, and creates the
// process with it — the standard way for a session-0 service to put a process on a user's desktop.
func startInSession(exe string, sid uint32, args ...string) error {
	var self windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_SESSIONID, &self); err != nil {
		return fmt.Errorf("opening the agent's token: %w", err)
	}
	defer self.Close()
	var dup windows.Token
	if err := windows.DuplicateTokenEx(self, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &dup); err != nil {
		return fmt.Errorf("duplicating the token: %w", err)
	}
	defer dup.Close()
	s := sid
	if err := windows.SetTokenInformation(dup, windows.TokenSessionId, (*byte)(unsafe.Pointer(&s)), uint32(unsafe.Sizeof(s))); err != nil {
		return fmt.Errorf("moving the token to the session: %w", err)
	}

	appName, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	parts := []string{`"` + exe + `"`}
	for _, a := range args {
		if strings.ContainsAny(a, " \t") {
			a = `"` + a + `"`
		}
		parts = append(parts, a)
	}
	cmdLine, err := windows.UTF16PtrFromString(strings.Join(parts, " "))
	if err != nil {
		return err
	}
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := &windows.StartupInfo{Desktop: desktop}
	si.Cb = uint32(unsafe.Sizeof(*si))
	var pi windows.ProcessInformation
	// CREATE_NO_WINDOW so no console flashes up; the helper is a GUI-subsystem binary and has none anyway.
	if err := windows.CreateProcessAsUser(dup, appName, cmdLine, nil, nil, false, 0x08000000, nil, nil, si, &pi); err != nil {
		return fmt.Errorf("starting the helper in the session: %w", err)
	}
	_ = windows.CloseHandle(pi.Thread)
	_ = windows.CloseHandle(pi.Process)
	return nil
}
