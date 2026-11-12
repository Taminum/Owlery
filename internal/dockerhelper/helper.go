// Package dockerhelper is the one place that talks to Docker on behalf of the security agent. The agent has no access
// to Docker's socket (which is as strong as root): it can only ask this helper, over a Unix socket, for two things,
// the last lines of one container's log and a restart of one container. The helper checks the name against a fixed
// pattern and against the containers that exist, never builds a shell command, and never passes anything but the
// name as an argument.
//
// The helper runs as its own unprivileged user that is in the docker group.
package dockerhelper

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Taminum/Owlery/internal/seccollect"
)

const (
	OpLogs    = "logs"
	OpRestart = "restart"
)

const (
	CodeOK          = "ok"
	CodeBadRequest  = "bad_request"
	CodeNoSuch      = "no_such_container"
	CodeNotAllowed  = "not_allowed"
	CodeCommand     = "command_error"
	CodeUnavailable = "helper_unavailable"
)

const (
	maxRequestBytes = 1 << 10
	MaxTail         = 1000
	DefaultTail     = 200
	MaxLog          = 256 << 10
)

type Request struct {
	Op   string `json:"op"`
	Name string `json:"name,omitempty"`
	Tail int    `json:"tail,omitempty"`
}

type Response struct {
	OK        bool   `json:"ok"`
	Code      string `json:"code,omitempty"`
	Log       string `json:"log,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Running   bool   `json:"running,omitempty"`
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// ValidName reports whether s may name a container at all. Whether it exists is checked against Docker.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// Server answers requests on a Unix socket.
type Server struct {
	Runner seccollect.Runner
	Bin    string   // the docker path or name
	Deny   []string // containers that may be read but never restarted (the panel's own, for instance)
	mu     sync.Mutex
}

func (s *Server) docker(ctx context.Context, args ...string) seccollect.Result {
	return s.Runner.Run(ctx, s.Bin, args...)
}

func (s *Server) exists(ctx context.Context, name string) (bool, bool) {
	r := s.docker(ctx, "ps", "-a", "--format", "{{.Names}}")
	if r.Err != nil || r.ExitCode != 0 {
		return false, false
	}
	for _, n := range strings.Fields(r.Stdout) {
		if n == name {
			return true, true
		}
	}
	return false, true
}

func (s *Server) denied(name string) bool {
	for _, d := range s.Deny {
		if d == name {
			return true
		}
	}
	return false
}

// Handle answers one request.
func (s *Server) Handle(ctx context.Context, rq Request) Response {
	if rq.Op != OpLogs && rq.Op != OpRestart {
		return Response{Code: CodeBadRequest}
	}
	if !ValidName(rq.Name) {
		return Response{Code: CodeBadRequest}
	}
	ok, known := s.exists(ctx, rq.Name)
	if !known {
		return Response{Code: CodeCommand}
	}
	if !ok {
		return Response{Code: CodeNoSuch}
	}
	if rq.Op == OpLogs {
		return s.logs(ctx, rq)
	}
	if s.denied(rq.Name) {
		return Response{Code: CodeNotAllowed}
	}
	return s.restart(ctx, rq.Name)
}

func (s *Server) logs(ctx context.Context, rq Request) Response {
	tail := rq.Tail
	if tail <= 0 {
		tail = DefaultTail
	}
	if tail > MaxTail {
		tail = MaxTail
	}
	r := s.docker(ctx, "logs", "--tail", strconv.Itoa(tail), "--timestamps", rq.Name)
	if r.Err != nil || r.ExitCode != 0 {
		return Response{Code: CodeCommand}
	}
	// A container writes errors to its second stream; both belong in the reading, and the lines are not interleaved in time here.
	out := r.Stdout
	if r.Stderr != "" {
		out += r.Stderr
	}
	cut := false
	if len(out) > MaxLog {
		out, cut = out[len(out)-MaxLog:], true
		if i := strings.IndexByte(out, '\n'); i >= 0 {
			out = out[i+1:]
		}
	}
	return Response{OK: true, Code: CodeOK, Log: strings.ToValidUTF8(out, "?"), Truncated: cut}
}

func (s *Server) restart(ctx context.Context, name string) Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.docker(ctx, "restart", "--time", "20", name); r.Err != nil || r.ExitCode != 0 {
		return Response{Code: CodeCommand}
	}
	r := s.docker(ctx, "inspect", "--format", "{{.State.Running}}", name)
	return Response{OK: true, Code: CodeOK, Running: r.Err == nil && strings.TrimSpace(r.Stdout) == "true"}
}

// Serve accepts connections until ctx ends. Each connection carries one request and one response.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	go func() { <-ctx.Done(); l.Close() }()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.conn(ctx, c)
	}
}

func (s *Server) conn(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	var rq Request
	dec := json.NewDecoder(io.LimitReader(c, maxRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rq); err != nil {
		_ = json.NewEncoder(c).Encode(Response{Code: CodeBadRequest})
		return
	}
	_ = json.NewEncoder(c).Encode(s.Handle(ctx, rq))
}

// Listen creates the socket with the given mode.
func Listen(path string, mode os.FileMode) (net.Listener, error) {
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Client asks a helper.
type Client struct{ Path string }

func (c Client) Do(ctx context.Context, rq Request) (Response, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return Response{Code: CodeUnavailable}, err
	}
	defer conn.Close()
	dl, ok := ctx.Deadline()
	if !ok || time.Until(dl) > 60*time.Second {
		dl = time.Now().Add(60 * time.Second)
	}
	_ = conn.SetDeadline(dl)
	if err := json.NewEncoder(conn).Encode(rq); err != nil {
		return Response{Code: CodeUnavailable}, err
	}
	var rs Response
	if err := json.NewDecoder(io.LimitReader(conn, 2<<20)).Decode(&rs); err != nil {
		return Response{Code: CodeUnavailable}, err
	}
	return rs, nil
}

// Available reports whether a helper answers on the socket (an unknown name still proves it does).
func (c Client) Available(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rs, err := c.Do(ctx, Request{Op: OpLogs, Name: "-"})
	return err == nil && rs.Code != CodeUnavailable
}
