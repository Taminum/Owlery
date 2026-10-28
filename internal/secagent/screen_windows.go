//go:build windows

package secagent

import (
	"fmt"
	"net"
	"strconv"
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
	if err := startInConsoleSession(a.cfg.RemoteHelperExe, "run"); err != nil {
		// A helper may already be running from an earlier session; only say something when there is also no one to talk
		// to, which the dial below will find out.
		a.cfg.Log.Warn("screen: launching the helper in the signed-in session", "err", err)
	}
	waitForPort(a.runCtx, secproto.RemoteHelperPort, 8*time.Second)
	if err := secshell.RemoteTunnel(a.runCtx, a.dialBack, a.cfg.RemoteSecretFile, req); err != nil {
		a.cfg.Log.Warn("screen", "err", err)
	}
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

// startInConsoleSession launches exe (with one argument) as the system account inside the active console session, on
// its interactive desktop. It duplicates the agent's own system token, stamps it with the console session's id, and
// creates the process with it — the standard way for a session-0 service to put a process on the user's desktop.
func startInConsoleSession(exe, arg string) error {
	sid := windows.WTSGetActiveConsoleSessionId()
	if sid == 0xFFFFFFFF {
		return fmt.Errorf("no interactive session (nobody is signed in)")
	}
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
	cmdLine, err := windows.UTF16PtrFromString(`"` + exe + `" ` + arg)
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
