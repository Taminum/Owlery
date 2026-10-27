// Package secshell runs one terminal session on the machine: a shell in a pseudo-terminal (ConPTY on Windows), wired
// to a WebSocket that the machine opens back to Owlery. Binary frames are terminal bytes in both directions; a text
// frame from the server is a resize.
//
// On Linux the agent is not root and a terminal as its user would be of no use, so a small helper that runs as root
// opens the sessions; the agent only passes it the session to open. The helper exists only where its owner installed
// it: without it this machine cannot be given a terminal from Owlery at all.
package secshell

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/aymanbagabas/go-pty"
	"github.com/coder/websocket"

	"github.com/Taminum/Owlery/internal/secproto"
)

// MaxSessions bounds the terminals open on one machine at once.
const MaxSessions = 4

// Dialer connects back to Owlery for one session.
type Dialer struct {
	BaseURL string // wss://host, the same address the agent reports to
	Token   func() (string, error)
	Client  *http.Client
}

func (d Dialer) Dial(ctx context.Context, id string) (*websocket.Conn, error) {
	return d.DialPath(ctx, secproto.ShellPath, id)
}

// DialPath connects back to one of the per-session endpoints (a terminal or a tunnel).
func (d Dialer) DialPath(ctx context.Context, path, id string) (*websocket.Conn, error) {
	tok, err := d.Token()
	if err != nil {
		return nil, err
	}
	u := strings.TrimRight(d.BaseURL, "/") + path + "?id=" + url.QueryEscape(id)
	c, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: d.Client, HTTPHeader: http.Header{"Authorization": {"Bearer " + tok}}})
	if err != nil {
		return nil, err
	}
	c.SetReadLimit(64 << 10)
	return c, nil
}

// Runner opens sessions on this machine, at most MaxSessions at once.
type Runner struct {
	Dial func(ctx context.Context, id string) (*websocket.Conn, error)
	Log  *slog.Logger
	once sync.Once
	slot chan struct{}
}

// Open starts a session in the background and returns at once; a session that cannot start says so in the log.
func (r *Runner) Open(ctx context.Context, req secproto.ShellOpen) {
	r.once.Do(func() { r.slot = make(chan struct{}, MaxSessions) })
	select {
	case r.slot <- struct{}{}:
	default:
		r.Log.Warn("terminal refused: too many open", "id", req.ID)
		return
	}
	go func() {
		defer func() { <-r.slot }()
		dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		c, err := r.Dial(dctx, req.ID)
		cancel()
		if err != nil {
			r.Log.Warn("terminal: could not connect back", "id", req.ID, "err", err)
			return
		}
		r.Log.Info("terminal opened", "id", req.ID)
		err = Serve(ctx, c, req.Cols, req.Rows)
		r.Log.Info("terminal closed", "id", req.ID, "err", err)
	}()
}

// Serve runs a shell for one connection until either side ends.
func Serve(ctx context.Context, c *websocket.Conn, cols, rows int) error {
	sh, err := openShell(cols, rows)
	if err != nil {
		_ = c.Write(ctx, websocket.MessageBinary, []byte("\r\nOwlery: "+err.Error()+"\r\n"))
		c.Close(websocket.StatusInternalError, "no shell")
		return err
	}
	defer sh.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Shell output to the connection.
	go func() {
		defer cancel()
		buf := make([]byte, 32<<10)
		for {
			n, err := sh.pty.Read(buf)
			if n > 0 {
				if c.Write(ctx, websocket.MessageBinary, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	// The shell ends: so does the session.
	go func() {
		_ = sh.cmd.Wait()
		cancel()
	}()
	for {
		typ, b, err := c.Read(ctx)
		if err != nil {
			c.Close(websocket.StatusNormalClosure, "")
			return nil
		}
		if typ == websocket.MessageText {
			var rs secproto.ShellResize
			if json.Unmarshal(b, &rs) == nil && rs.Type == "resize" && rs.Cols > 0 && rs.Rows > 0 && rs.Cols <= 1000 && rs.Rows <= 500 {
				_ = sh.pty.Resize(rs.Cols, rs.Rows)
			}
			continue
		}
		if _, err := sh.pty.Write(b); err != nil {
			return err
		}
	}
}

type shell struct {
	pty pty.Pty
	cmd *pty.Cmd
}

func openShell(cols, rows int) (*shell, error) {
	if cols <= 0 || cols > 1000 {
		cols = 120
	}
	if rows <= 0 || rows > 500 {
		rows = 32
	}
	p, err := pty.New()
	if err != nil {
		return nil, fmt.Errorf("pseudo-terminal: %w", err)
	}
	path, args := pickShell()
	cmd := p.Command(path, args...)
	// xterm draws in the browser: colours, line editing and clearing follow TERM.
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	if runtime.GOOS != "windows" {
		if home, err := os.UserHomeDir(); err == nil {
			cmd.Dir = home
		}
	}
	if err := p.Resize(cols, rows); err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("window size: %w", err)
	}
	if err := cmd.Start(); err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("%s did not start: %w", path, err)
	}
	return &shell{pty: p, cmd: cmd}, nil
}

// pickShell takes the machine's own shell: PowerShell on Windows, the login shell of root (or bash) elsewhere.
func pickShell() (string, []string) {
	if runtime.GOOS == "windows" {
		for _, c := range []string{"pwsh.exe", "powershell.exe"} {
			if p, err := exec.LookPath(c); err == nil {
				return p, []string{"-NoLogo"}
			}
		}
		return "cmd.exe", nil
	}
	if sh := strings.TrimSpace(os.Getenv("SHELL")); sh != "" {
		if _, err := os.Stat(sh); err == nil {
			return sh, []string{"-l"}
		}
	}
	for _, c := range []string{"/bin/bash", "/bin/sh"} {
		if _, err := os.Stat(c); err == nil {
			return c, []string{"-l"}
		}
	}
	return "/bin/sh", nil
}

func (s *shell) Close() {
	_ = s.pty.Close()
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
}

// Ask passes a session to the helper over its Unix socket. The helper answers "ok" once it has taken it.
func Ask(ctx context.Context, socket string, req secproto.ShellOpen) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	b, _ := json.Marshal(req)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return err
	}
	line, err := bufio.NewReader(io.LimitReader(c, 256)).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != "ok" {
		return errors.New("the terminal helper refused: " + strings.TrimSpace(line))
	}
	return nil
}

// ServeHelper takes session requests on l, one per connection, and opens each with the runner.
func ServeHelper(ctx context.Context, l net.Listener, r *Runner) error {
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			line, err := bufio.NewReader(io.LimitReader(c, 1024)).ReadString('\n')
			if err != nil {
				return
			}
			var req secproto.ShellOpen
			if json.Unmarshal([]byte(line), &req) != nil || req.Type != "shell_open" || req.ID == "" || len(req.ID) > 64 {
				_, _ = c.Write([]byte("bad request\n"))
				return
			}
			r.Open(ctx, req)
			_, _ = c.Write([]byte("ok\n"))
		}()
	}
}
