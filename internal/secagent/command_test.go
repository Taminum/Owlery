package secagent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/f2bhelper"
	"github.com/Taminum/RemnaScope/internal/seccollect"
	"github.com/Taminum/RemnaScope/internal/secproto"
)

// tinyF2B is a fail2ban-client with one jail, enough to carry out a ban and read it back.
type tinyF2B struct {
	mu     sync.Mutex
	banned []string
	sets   int
}

func (f *tinyF2B) Run(_ context.Context, _ string, args ...string) seccollect.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case len(args) == 1 && args[0] == "status":
		return seccollect.Result{Stdout: "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n"}
	case len(args) == 2 && args[0] == "status" && args[1] == "sshd":
		return seccollect.Result{Stdout: "|  |- Currently failed:\t0\n|  |- Total failed:\t0\n   |- Currently banned:\t0\n   |- Total banned:\t0\n   `- Banned IP list:\t" + strings.Join(f.banned, " ") + "\n"}
	case len(args) == 4 && args[0] == "set":
		f.sets++
		var next []string
		for _, e := range f.banned {
			if e != args[3] {
				next = append(next, e)
			}
		}
		if args[2] == "banip" {
			next = append(next, args[3])
		}
		f.banned = next
		return seccollect.Result{Stdout: "1\n"}
	}
	return seccollect.Result{ExitCode: 1}
}

func startHelper(t *testing.T) (*tinyF2B, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "sa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &tinyF2B{}
	path := filepath.Join(dir, "h.sock")
	l, err := f2bhelper.Listen(path, 0o660)
	if err != nil {
		t.Skipf("no unix sockets here: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = (&f2bhelper.Server{Runner: f, Bin: "f2b"}).Serve(ctx, l); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return f, path
}

func newAgent(t *testing.T, sock, state string) *agent {
	t.Helper()
	a := &agent{helper: f2bhelper.Client{Path: sock}}
	if state != "" {
		d, err := openExecuted(state)
		if err != nil {
			t.Fatal(err)
		}
		a.done = d
		t.Cleanup(func() { d.Close() })
	}
	return a
}

func cmd(id, op, jail, ip string, ttl int) secproto.Command {
	return secproto.Command{Type: "command", ID: id, Op: op, Jail: jail, IP: ip, TTLSeconds: ttl}
}

const id1 = "11111111-1111-4111-8111-111111111111"

func TestACommandIsCarriedOutOnceEvenAcrossARestart(t *testing.T) {
	f, sock := startHelper(t)
	state := t.TempDir()
	a := newAgent(t, sock, state)
	ctx := context.Background()
	now := time.Now()

	r := a.carryOut(ctx, cmd(id1, "ban", "sshd", "198.51.100.9", 30), now, true)
	if r.Status != secproto.CmdExecuted || !r.Verified || r.ID != id1 {
		t.Fatalf("%+v", r)
	}
	// The same ID again, as if the server (or an attacker) sent it twice: not run a second time.
	if r := a.carryOut(ctx, cmd(id1, "ban", "sshd", "198.51.100.9", 30), now, true); r.Status != secproto.CmdDuplicate || f.sets != 1 {
		t.Fatalf("%+v sets %d", r, f.sets)
	}
	// After a restart the memory is read back from disk, and the ID is still known.
	b := newAgent(t, sock, state)
	if r := b.carryOut(ctx, cmd(id1, "ban", "sshd", "198.51.100.9", 30), now, true); r.Status != secproto.CmdDuplicate || f.sets != 1 {
		t.Fatalf("a restart forgot a command: %+v sets %d", r, f.sets)
	}
	// Even the opposite request under the same ID is a duplicate, never an unban.
	if r := b.carryOut(ctx, cmd(id1, "unban", "sshd", "198.51.100.9", 30), now, true); r.Status != secproto.CmdDuplicate || len(f.banned) != 1 {
		t.Fatalf("%+v %v", r, f.banned)
	}
	// A new ID may do the opposite.
	if r := b.carryOut(ctx, cmd("22222222-2222-4222-8222-222222222222", "unban", "sshd", "198.51.100.9", 30), now, true); r.Status != secproto.CmdExecuted || len(f.banned) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestACommandThatIsNotValidOrNotWantedDoesNothing(t *testing.T) {
	f, sock := startHelper(t)
	a := newAgent(t, sock, t.TempDir())
	ctx := context.Background()
	now := time.Now()
	for name, c := range map[string]secproto.Command{
		"bad id":         cmd("x", "ban", "sshd", "198.51.100.9", 30),
		"unknown op":     cmd(id1, "reload", "sshd", "198.51.100.9", 30),
		"option as jail": cmd(id1, "ban", "--help", "198.51.100.9", 30),
		"not an ip":      cmd(id1, "ban", "sshd", "example.com", 30),
		"loopback":       cmd(id1, "ban", "sshd", "127.0.0.1", 30),
		"no ttl":         cmd(id1, "ban", "sshd", "198.51.100.9", 0),
		"huge ttl":       cmd(id1, "ban", "sshd", "198.51.100.9", 3600),
		"wrong type":     {Type: "ban", ID: id1, Op: "ban", Jail: "sshd", IP: "198.51.100.9", TTLSeconds: 30},
	} {
		if r := a.carryOut(ctx, c, now, true); r.Status != secproto.CmdRejected {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// Not enabled on this connection: refused whatever it says.
	if r := a.carryOut(ctx, cmd(id1, "ban", "sshd", "198.51.100.9", 30), now, false); r.Status != secproto.CmdRejected || r.Code != "not_enabled" {
		t.Fatalf("%+v", r)
	}
	// Late: it took longer than its time to live before it could start.
	if r := a.carryOut(ctx, cmd(id1, "ban", "sshd", "198.51.100.9", 5), now.Add(-10*time.Second), true); r.Status != secproto.CmdExpired {
		t.Fatalf("%+v", r)
	}
	// An unknown jail is the helper's refusal, and the ID is spent but nothing was changed.
	if r := a.carryOut(ctx, cmd(id1, "ban", "nope", "198.51.100.9", 30), now, true); r.Status != secproto.CmdRejected || r.Code != f2bhelper.CodeNoSuchJail {
		t.Fatalf("%+v", r)
	}
	if f.sets != 0 {
		t.Fatalf("a refused command changed something: %d", f.sets)
	}
}

func TestACommandWithAnUnreachableHelperFailsAndIsNotSuccess(t *testing.T) {
	a := newAgent(t, filepath.Join(t.TempDir(), "gone.sock"), t.TempDir())
	if a.canBan(context.Background()) {
		t.Fatal("ban must not be announced when the helper does not answer")
	}
	r := a.carryOut(context.Background(), cmd(id1, "ban", "sshd", "198.51.100.9", 5), time.Now(), true)
	if r.Status != secproto.CmdFailed || r.Verified {
		t.Fatalf("%+v", r)
	}
}

func TestBanIsAnnouncedOnlyWithHelperAndAStateDirectory(t *testing.T) {
	_, sock := startHelper(t)
	ctx := context.Background()
	has := func(caps []string) bool {
		for _, c := range caps {
			if c == secproto.CapFail2banBan {
				return true
			}
		}
		return false
	}
	with := newAgent(t, sock, t.TempDir())
	if !with.canBan(ctx) || !has(with.capabilities(true)) {
		t.Fatal("a helper and a state directory should enable ban")
	}
	if noState := newAgent(t, sock, ""); noState.canBan(ctx) {
		t.Fatal("without a state directory a command could run twice, so ban stays off")
	}
	if has(with.capabilities(false)) {
		t.Fatal("the capability must follow the decision")
	}
}

func TestTheExecutedListStaysBounded(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	for i := 0; i < keepExecuted+50; i++ {
		lines = append(lines, "aaaaaaaa-0000-4000-8000-"+strings.Repeat("0", 12-len(itoa(i)))+itoa(i))
	}
	if err := os.WriteFile(filepath.Join(dir, "executed-commands"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := openExecuted(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	if len(e.ids) != keepExecuted || e.ids[lines[0]] || !e.ids[lines[len(lines)-1]] {
		t.Fatalf("%d ids; oldest kept %v", len(e.ids), e.ids[lines[0]])
	}
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
