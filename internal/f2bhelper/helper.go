// Package f2bhelper is the one place that talks to Fail2ban's control socket on behalf of the security
// agent. The agent itself has no access to that socket: it can only ask this helper, over a Unix socket,
// for five things (the status, the status of one jail, the listing of banned addresses, ban one address, unban one address), and the helper
// checks every field before it runs anything.
//
// The helper runs as its own unprivileged user that is allowed to use Fail2ban's socket. It runs
// "fail2ban-client" with a fixed argument list and no shell, and it never passes text it was given to
// anything but an argument that it has parsed into an address or matched against a fixed pattern first.
package f2bhelper

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Taminum/RemnaScope/internal/seccollect"
)

// Operations the helper offers. There are no others.
const (
	OpStatus = "status" // "fail2ban-client status"
	OpJail   = "jail"   // "fail2ban-client status <jail>"
	OpBanned = "banned" // "fail2ban-client banned": every banned address, in one listing
	OpBan    = "ban"    // "fail2ban-client set <jail> banip <ip>"
	OpUnban  = "unban"  // "fail2ban-client set <jail> unbanip <ip>"
)

// Result codes of a ban or an unban.
const (
	CodeExecuted     = "executed"
	CodeAlreadyDone  = "already_done"
	CodeNoSuchJail   = "no_such_jail"
	CodeBadRequest   = "bad_request"
	CodeProtectedIP  = "protected_address"
	CodeCommandError = "command_error"
	CodeUnverified   = "unverified"
	CodeUnavailable  = "helper_unavailable"
)

const maxRequestBytes = 1 << 10

type Request struct {
	Op   string `json:"op"`
	Jail string `json:"jail,omitempty"`
	IP   string `json:"ip,omitempty"`
}

type Response struct {
	OK       bool   `json:"ok"`
	Code     string `json:"code,omitempty"`
	Out      string `json:"out,omitempty"`      // status and jail: what fail2ban-client printed
	ExitCode int    `json:"exit,omitempty"`     // status and jail: its exit code
	Denied   bool   `json:"denied,omitempty"`   // status and jail: it was not allowed to read the socket
	Missing  bool   `json:"missing,omitempty"`  // status and jail: fail2ban-client is not installed
	Verified bool   `json:"verified,omitempty"` // ban and unban: the state was read again and is as wanted
}

var jailRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// ValidJail reports whether s may name a jail at all. Whether the jail exists is checked against Fail2ban.
func ValidJail(s string) bool { return jailRe.MatchString(s) }

// ParseIP returns the canonical address, or false. Addresses that no ban makes sense for, or that would cut
// the host off from itself, are refused: unspecified, loopback, multicast and the broadcast address.
func ParseIP(s string) (netip.Addr, string) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, CodeBadRequest
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.Addr{}, CodeProtectedIP
	}
	return a, ""
}

// Server answers requests on a Unix socket.
type Server struct {
	Runner seccollect.Runner
	Bin    string     // the fail2ban-client path or name
	mu     sync.Mutex // one change at a time: a ban and an unban of the same address must not interleave
}

func (s *Server) fc(ctx context.Context, args ...string) seccollect.Result {
	return s.Runner.Run(ctx, s.Bin, args...)
}

// Handle answers one request.
func (s *Server) Handle(ctx context.Context, rq Request) Response {
	switch rq.Op {
	case OpStatus:
		return s.passThrough(ctx, "status")
	case OpBanned:
		return s.passThrough(ctx, "banned")
	case OpJail:
		if !ValidJail(rq.Jail) {
			return Response{Code: CodeBadRequest}
		}
		return s.passThrough(ctx, "status", rq.Jail)
	case OpBan, OpUnban:
		return s.change(ctx, rq)
	}
	return Response{Code: CodeBadRequest}
}

func (s *Server) passThrough(ctx context.Context, args ...string) Response {
	r := s.fc(ctx, args...)
	if r.Err != nil {
		return Response{Missing: seccollect.NotFound(r), Code: CodeCommandError}
	}
	return Response{OK: true, Out: r.Stdout, ExitCode: r.ExitCode, Denied: seccollect.Denied(r)}
}

func (s *Server) jails(ctx context.Context) ([]string, bool) {
	r := s.fc(ctx, "status")
	if r.Err != nil || r.ExitCode != 0 {
		return nil, false
	}
	return seccollect.ParseJailList(r.Stdout)
}

func (s *Server) banned(ctx context.Context, jail string, ip netip.Addr) (bool, bool) {
	r := s.fc(ctx, "status", jail)
	if r.Err != nil || r.ExitCode != 0 {
		return false, false
	}
	j, ok := seccollect.ParseJailStatus(jail, r.Stdout)
	if !ok {
		return false, false
	}
	for _, e := range j.BannedIPs {
		if a, err := netip.ParseAddr(e); err == nil && a.Unmap() == ip {
			return true, true
		}
	}
	return false, true
}

func (s *Server) change(ctx context.Context, rq Request) Response {
	if !ValidJail(rq.Jail) {
		return Response{Code: CodeBadRequest}
	}
	ip, code := ParseIP(rq.IP)
	if code != "" {
		return Response{Code: code}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	names, ok := s.jails(ctx)
	if !ok {
		return Response{Code: CodeCommandError}
	}
	known := false
	for _, n := range names {
		if n == rq.Jail {
			known = true
		}
	}
	if !known {
		return Response{Code: CodeNoSuchJail}
	}
	want := rq.Op == OpBan
	was, ok := s.banned(ctx, rq.Jail, ip)
	if !ok {
		return Response{Code: CodeCommandError}
	}
	if was == want {
		return Response{OK: true, Code: CodeAlreadyDone, Verified: true}
	}
	verb := "unbanip"
	if want {
		verb = "banip"
	}
	if r := s.fc(ctx, "set", rq.Jail, verb, ip.String()); r.Err != nil || r.ExitCode != 0 {
		return Response{Code: CodeCommandError}
	}
	now, ok := s.banned(ctx, rq.Jail, ip)
	if !ok || now != want {
		return Response{OK: true, Code: CodeUnverified}
	}
	return Response{OK: true, Code: CodeExecuted, Verified: true}
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
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	var rq Request
	dec := json.NewDecoder(io.LimitReader(c, maxRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rq); err != nil {
		_ = json.NewEncoder(c).Encode(Response{Code: CodeBadRequest})
		return
	}
	_ = json.NewEncoder(c).Encode(s.Handle(ctx, rq))
}

// Listen creates the socket with the given mode. The socket's group is set by the service manager
// (RuntimeDirectory and the group of the unit), not here.
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
	if !ok || time.Until(dl) > 30*time.Second {
		dl = time.Now().Add(30 * time.Second)
	}
	_ = conn.SetDeadline(dl)
	if err := json.NewEncoder(conn).Encode(rq); err != nil {
		return Response{Code: CodeUnavailable}, err
	}
	var rs Response
	if err := json.NewDecoder(io.LimitReader(conn, 4<<20)).Decode(&rs); err != nil {
		return Response{Code: CodeUnavailable}, err
	}
	return rs, nil
}

// Available reports whether a helper answers on the socket.
func (c Client) Available(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rs, err := c.Do(ctx, Request{Op: OpStatus})
	return err == nil && rs.OK
}

// Runner makes the Fail2ban collector read through the helper: "fail2ban-client status [jail]" becomes a
// request, and anything else goes to Next unchanged. The agent then needs no access to the socket.
type Runner struct {
	Client Client
	Bin    string
	Next   seccollect.Runner
}

func (r Runner) Run(ctx context.Context, name string, args ...string) seccollect.Result {
	if name != r.Bin {
		return r.Next.Run(ctx, name, args...)
	}
	rq := Request{Op: OpStatus}
	switch {
	case len(args) == 1 && args[0] == "status":
	case len(args) == 1 && args[0] == "banned":
		rq = Request{Op: OpBanned}
	case len(args) == 2 && args[0] == "status":
		rq = Request{Op: OpJail, Jail: args[1]}
	default:
		return seccollect.Result{Err: errors.New("f2bhelper: only status is read through the helper"), ExitCode: 1}
	}
	rs, err := r.Client.Do(ctx, rq)
	if err != nil {
		return seccollect.Result{Err: err}
	}
	if rs.Missing {
		return seccollect.Result{Err: seccollect.ErrNotInstalled}
	}
	if !rs.OK {
		return seccollect.Result{Err: errors.New("f2bhelper: " + rs.Code)}
	}
	res := seccollect.Result{Stdout: rs.Out, ExitCode: rs.ExitCode}
	if rs.Denied {
		res.Stderr = "Permission denied"
	}
	return res
}
