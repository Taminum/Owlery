package f2bhelper

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/seccollect"
)

// fakeF2B behaves like fail2ban-client for one or two jails and records every command it was given.
type fakeF2B struct {
	mu       sync.Mutex
	jails    map[string][]string
	calls    [][]string
	ignore   bool // a ban or unban is accepted but changes nothing
	failSet  bool
	notFound bool
}

func (f *fakeF2B) Run(_ context.Context, name string, args ...string) seccollect.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.notFound {
		return seccollect.Result{Err: seccollect.ErrNotInstalled}
	}
	switch {
	case len(args) == 1 && args[0] == "status":
		var names []string
		for n := range f.jails {
			names = append(names, n)
		}
		return seccollect.Result{Stdout: "Status\n|- Number of jail:\t1\n`- Jail list:\t" + strings.Join(names, ", ") + "\n"}
	case len(args) == 2 && args[0] == "status":
		ips, ok := f.jails[args[1]]
		if !ok {
			return seccollect.Result{ExitCode: 255, Stderr: "Sorry but the jail '" + args[1] + "' does not exist"}
		}
		return seccollect.Result{Stdout: "Status for the jail: " + args[1] + "\n|- Filter\n|  |- Currently failed:\t0\n|  |- Total failed:\t0\n|  `- File list:\t/x\n`- Actions\n   |- Currently banned:\t" +
			itoa(len(ips)) + "\n   |- Total banned:\t0\n   `- Banned IP list:\t" + strings.Join(ips, " ") + "\n"}
	case len(args) == 4 && args[0] == "set" && (args[2] == "banip" || args[2] == "unbanip"):
		if f.failSet {
			return seccollect.Result{ExitCode: 1, Stderr: "boom"}
		}
		if f.ignore {
			return seccollect.Result{Stdout: "1\n"}
		}
		jail, ip := args[1], args[3]
		cur := f.jails[jail]
		var next []string
		for _, e := range cur {
			if e != ip {
				next = append(next, e)
			}
		}
		if args[2] == "banip" {
			next = append(next, ip)
		}
		f.jails[jail] = next
		return seccollect.Result{Stdout: "1\n"}
	}
	return seccollect.Result{ExitCode: 1, Stderr: "unexpected command"}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for ; n > 0; n /= 10 {
		d = append([]byte{byte('0' + n%10)}, d...)
	}
	return string(d)
}

func newFake() *fakeF2B {
	return &fakeF2B{jails: map[string][]string{"sshd": {"203.0.113.5"}, "nginx": nil}}
}

func (f *fakeF2B) sets() (n int) {
	for _, c := range f.calls {
		if len(c) > 1 && c[1] == "set" {
			n++
		}
	}
	return
}

func TestBanAndUnbanAreCheckedAndVerified(t *testing.T) {
	f := newFake()
	s := &Server{Runner: f, Bin: "f2b"}
	ctx := context.Background()

	if r := s.Handle(ctx, Request{Op: OpBan, Jail: "sshd", IP: "198.51.100.9"}); !r.OK || r.Code != CodeExecuted || !r.Verified {
		t.Fatalf("%+v", r)
	}
	if got := f.jails["sshd"]; len(got) != 2 || got[1] != "198.51.100.9" {
		t.Fatalf("%v", got)
	}
	// Banning what is banned changes nothing and runs no set command.
	before := f.sets()
	if r := s.Handle(ctx, Request{Op: OpBan, Jail: "sshd", IP: "198.51.100.9"}); r.Code != CodeAlreadyDone || !r.Verified || f.sets() != before {
		t.Fatalf("%+v sets %d->%d", r, before, f.sets())
	}
	if r := s.Handle(ctx, Request{Op: OpUnban, Jail: "sshd", IP: "198.51.100.9"}); r.Code != CodeExecuted || !r.Verified {
		t.Fatalf("%+v", r)
	}
	if r := s.Handle(ctx, Request{Op: OpUnban, Jail: "sshd", IP: "198.51.100.9"}); r.Code != CodeAlreadyDone || f.sets() != before+1 {
		t.Fatalf("an unban of what is not banned must change nothing: %+v", r)
	}
	// IPv6, and an IPv4-mapped address that names the same host as the IPv4 one.
	if r := s.Handle(ctx, Request{Op: OpBan, Jail: "nginx", IP: "2001:DB8::1"}); r.Code != CodeExecuted {
		t.Fatalf("%+v", r)
	}
	if r := s.Handle(ctx, Request{Op: OpUnban, Jail: "sshd", IP: "::ffff:203.0.113.5"}); r.Code != CodeExecuted || len(f.jails["sshd"]) != 0 {
		t.Fatalf("a mapped address must be the same host: %+v %v", r, f.jails["sshd"])
	}
}

func TestEveryFieldIsRefusedBeforeAnythingRuns(t *testing.T) {
	f := newFake()
	s := &Server{Runner: f, Bin: "f2b"}
	ctx := context.Background()
	for name, rq := range map[string]Request{
		"option as jail":    {Op: OpBan, Jail: "--help", IP: "198.51.100.9"},
		"shell in jail":     {Op: OpBan, Jail: "sshd; id", IP: "198.51.100.9"},
		"space in jail":     {Op: OpBan, Jail: "ssh d", IP: "198.51.100.9"},
		"empty jail":        {Op: OpBan, Jail: "", IP: "198.51.100.9"},
		"long jail":         {Op: OpBan, Jail: strings.Repeat("a", 65), IP: "198.51.100.9"},
		"not an ip":         {Op: OpBan, Jail: "sshd", IP: "example.com"},
		"option as ip":      {Op: OpBan, Jail: "sshd", IP: "-h"},
		"ip with a command": {Op: OpBan, Jail: "sshd", IP: "198.51.100.9 -j"},
		"cidr":              {Op: OpBan, Jail: "sshd", IP: "198.51.100.0/24"},
		"zone":              {Op: OpBan, Jail: "sshd", IP: "fe80::1%eth0"},
		"unknown op":        {Op: "reload", Jail: "sshd", IP: "198.51.100.9"},
		"no op":             {},
	} {
		if r := s.Handle(ctx, rq); r.OK || (r.Code != CodeBadRequest) {
			t.Errorf("%s: %+v", name, r)
		}
	}
	for name, ip := range map[string]string{"loopback": "127.0.0.1", "loopback6": "::1", "unspecified": "0.0.0.0", "unspecified6": "::", "multicast": "224.0.0.1", "broadcast": "255.255.255.255"} {
		if r := s.Handle(ctx, Request{Op: OpBan, Jail: "sshd", IP: ip}); r.Code != CodeProtectedIP {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if r := s.Handle(ctx, Request{Op: OpBan, Jail: "nope", IP: "198.51.100.9"}); r.Code != CodeNoSuchJail {
		t.Errorf("%+v", r)
	}
	if f.sets() != 0 {
		t.Fatalf("a refused request ran a set command: %v", f.calls)
	}
	// Whatever was asked, the only commands that ran have the fixed shape.
	for _, c := range f.calls {
		ok := len(c) == 2 && c[1] == "status" || len(c) == 3 && c[1] == "status"
		if !ok {
			t.Errorf("an unexpected command: %v", c)
		}
	}
}

func TestFailuresAreNotReportedAsSuccess(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.failSet = true
	if r := (&Server{Runner: f, Bin: "f2b"}).Handle(ctx, Request{Op: OpBan, Jail: "sshd", IP: "198.51.100.9"}); r.OK || r.Code != CodeCommandError {
		t.Fatalf("%+v", r)
	}
	f = newFake()
	f.ignore = true
	r := (&Server{Runner: f, Bin: "f2b"}).Handle(ctx, Request{Op: OpBan, Jail: "sshd", IP: "198.51.100.9"})
	if r.Code != CodeUnverified || r.Verified {
		t.Fatalf("a command that changed nothing must not be verified: %+v", r)
	}
	f = newFake()
	f.notFound = true
	if r := (&Server{Runner: f, Bin: "f2b"}).Handle(ctx, Request{Op: OpBan, Jail: "sshd", IP: "198.51.100.9"}); r.OK {
		t.Fatalf("%+v", r)
	}
	if r := (&Server{Runner: f, Bin: "f2b"}).Handle(ctx, Request{Op: OpStatus}); !r.Missing {
		t.Fatalf("%+v", r)
	}
}

func TestOverTheSocketAndThroughTheCollectorRunner(t *testing.T) {
	f := newFake()
	s := &Server{Runner: f, Bin: "f2b"}
	dir, err := os.MkdirTemp("", "f2b")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "h.sock")
	l, err := Listen(path, 0o660)
	if err != nil {
		t.Skipf("no unix sockets here: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx, l); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	c := Client{Path: path}
	if !c.Available(ctx) {
		t.Fatal("the helper does not answer")
	}
	rs, err := c.Do(ctx, Request{Op: OpBan, Jail: "sshd", IP: "198.51.100.9"})
	if err != nil || rs.Code != CodeExecuted {
		t.Fatalf("%+v %v", rs, err)
	}

	// The collector reads Fail2ban through the helper, and never runs the command itself.
	panicRunner := runnerFunc(func(string) { t.Error("the agent ran a command of its own") })
	snap := seccollect.Fail2ban(ctx, Runner{Client: c, Bin: "fail2ban-client", Next: panicRunner}, "fail2ban-client")
	if snap.Status != "ok" {
		t.Fatalf("%+v", snap)
	}
	// Anything but a status read is refused by the routing runner.
	if r := (Runner{Client: c, Bin: "fail2ban-client", Next: panicRunner}).Run(ctx, "fail2ban-client", "set", "sshd", "banip", "1.2.3.4"); r.Err == nil {
		t.Fatal("a set command went through the read path")
	}

	// A line that is not JSON, an unknown field and an oversize request are all refused.
	for _, raw := range []string{"hello\n", `{"op":"status","exec":"id"}` + "\n", `{"op":"ban","jail":"` + strings.Repeat("a", 4000) + `"}` + "\n"} {
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte(raw))
		buf := make([]byte, 512)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := conn.Read(buf)
		conn.Close()
		if !strings.Contains(string(buf[:n]), `"code":"bad_request"`) {
			t.Errorf("%.30q: %q", raw, buf[:n])
		}
	}
	// And with the helper gone the client says so.
	cancel()
	<-done
	if (Client{Path: path}).Available(context.Background()) {
		t.Fatal("a stopped helper looks available")
	}
}

type runnerFunc func(name string)

func (f runnerFunc) Run(_ context.Context, name string, _ ...string) seccollect.Result {
	f(name)
	return seccollect.Result{Err: seccollect.ErrNotInstalled}
}
