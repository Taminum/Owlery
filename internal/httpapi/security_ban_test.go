package httpapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/f2bhelper"
	"github.com/Taminum/RemnaScope/internal/secagent"
	"github.com/Taminum/RemnaScope/internal/seccollect"
	"github.com/Taminum/RemnaScope/internal/secproto"
	"github.com/Taminum/RemnaScope/internal/store"
)

// banFake is a fail2ban-client with one jail whose banned list the test can see.
type banFake struct {
	mu     sync.Mutex
	banned []string
	sets   int
}

func (f *banFake) Run(_ context.Context, _ string, args ...string) seccollect.Result {
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

func (f *banFake) snapshot() (banned []string, sets int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.banned...), f.sets
}

type cmdResp struct {
	Command struct {
		ID         string  `json:"id"`
		State      string  `json:"state"`
		Verified   bool    `json:"verified"`
		Final      bool    `json:"final"`
		ResultCode *string `json:"result_code"`
	} `json:"command"`
	Repeated bool `json:"repeated"`
}

type fail2banResp struct {
	State  string `json:"state"`
	Manage *struct {
		Allowed bool   `json:"allowed"`
		Ready   bool   `json:"ready"`
		Reason  string `json:"reason"`
	} `json:"manage"`
}

func TestBanAndUnbanEndToEnd(t *testing.T) {
	w := newAgentWorld(t)
	w.h.srv.cmdLimit = auth.NewLimiter(1000, 1000) // the limit itself is tried below
	vpsID := mkVPS(t, w, "Helsinki", "203.0.113.7", "")
	base := "/api/v1/security/vps/" + vpsID
	_, ab := w.owner.do("POST", base+"/agent", nil)
	token := parse[struct {
		Token string `json:"token"`
	}](t, ab).Token

	// The host: a Fail2ban behind a helper on a Unix socket, and an agent that may only ask the helper.
	f2b := &banFake{banned: []string{"203.0.113.5"}}
	dir, err := os.MkdirTemp("", "ban")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "h.sock")
	l, err := f2bhelper.Listen(sock, 0o660)
	if err != nil {
		t.Skipf("no unix sockets here: %v", err)
	}
	hctx, hstop := context.WithCancel(context.Background())
	hdone := make(chan struct{})
	go func() { _ = (&f2bhelper.Server{Runner: f2b, Bin: "fail2ban-client"}).Serve(hctx, l); close(hdone) }()
	t.Cleanup(func() { hstop(); <-hdone })

	tokFile := filepath.Join(dir, "token")
	_ = os.WriteFile(tokFile, []byte(token), 0o600)
	host := &secFakeHost{out: map[string]seccollect.Result{"ss -H -tulnp": {Stdout: "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n"}, "nft list ruleset": {Stdout: "table inet filter {\n}\n"}}}
	actx, astop := context.WithCancel(context.Background())
	adone := make(chan struct{})
	go func() {
		defer close(adone)
		_ = secagent.Run(actx, secagent.Config{ServerURL: "ws" + strings.TrimPrefix(w.h.ts.URL, "http"), TokenFile: tokFile, AllowInsecure: true,
			Interval: 150 * time.Millisecond, Version: "test", Runner: host, HelperSocket: sock, StateDir: filepath.Join(dir, "state")})
	}()
	stopAgent := func() { astop(); <-adone }
	t.Cleanup(func() { astop(); <-adone })

	get := func() fail2banResp {
		_, b := w.owner.get(base + "/fail2ban")
		return parse[fail2banResp](t, b)
	}
	eventually(t, "the agent to be ready for commands", func() bool {
		f := get()
		return f.State == "ok" && f.Manage != nil && f.Manage.Ready
	})
	post := func(c *client, action string, body map[string]any) (int, []byte) {
		return c.do("POST", base+"/fail2ban/"+action, body)
	}
	settled := func(id string) cmdResp {
		var r cmdResp
		eventually(t, "the command to finish", func() bool {
			_, b := w.owner.get("/api/v1/security/commands/" + id)
			r = parse[cmdResp](t, b)
			return r.Command.Final
		})
		return r
	}

	// Only the owner may ban; a panel role cannot even see an unlinked server.
	if st, _ := post(w.adm, "ban", map[string]any{"jail": "sshd", "ip": "93.184.216.9", "idempotency_key": "key-00000001"}); st != 404 {
		t.Errorf("a panel admin on an unlinked server: %d", st)
	}
	if st, _ := w.owner.do("POST", base+"/links", map[string]any{"panel_id": w.work.ID}); st != 201 {
		t.Fatal(st)
	}
	if st, _ := post(w.adm, "ban", map[string]any{"jail": "sshd", "ip": "93.184.216.9", "idempotency_key": "key-00000001"}); st != 403 {
		t.Errorf("a panel admin may not ban: %d", st)
	}
	if st, _ := post(w.h.anon(), "ban", map[string]any{}); st != 401 {
		t.Errorf("anonymous: %d", st)
	}
	_, mb := w.adm.get(base + "/fail2ban")
	if f := parse[fail2banResp](t, mb); f.Manage == nil || f.Manage.Allowed || f.Manage.Reason != "not_owner" {
		t.Errorf("the screen must be told the admin cannot manage: %+v", f.Manage)
	}

	// Every field is checked on the server too.
	for name, body := range map[string]map[string]any{
		"no key":       {"jail": "sshd", "ip": "93.184.216.9"},
		"short key":    {"jail": "sshd", "ip": "93.184.216.9", "idempotency_key": "x"},
		"option jail":  {"jail": "--help", "ip": "93.184.216.9", "idempotency_key": "key-00000002"},
		"not an ip":    {"jail": "sshd", "ip": "example.com", "idempotency_key": "key-00000003"},
		"cidr":         {"jail": "sshd", "ip": "93.184.216.0/24", "idempotency_key": "key-00000004"},
		"loopback":     {"jail": "sshd", "ip": "127.0.0.1", "idempotency_key": "key-00000005"},
		"unknown jail": {"jail": "nope", "ip": "93.184.216.9", "idempotency_key": "key-00000006"},
		"extra field":  {"jail": "sshd", "ip": "93.184.216.9", "idempotency_key": "key-00000007", "cmd": "id"},
	} {
		if st, b := post(w.owner, "ban", body); st != 422 && st != 400 {
			t.Errorf("%s: %d %s", name, st, b)
		}
	}
	if st, _ := post(w.owner, "reload", map[string]any{"jail": "sshd", "ip": "93.184.216.9", "idempotency_key": "key-00000008"}); st != 404 {
		t.Errorf("an unknown action: %d", st)
	}
	// A private address is a warning that needs confirming; confirmed, it goes through.
	st, rb := post(w.owner, "ban", map[string]any{"jail": "sshd", "ip": "10.0.0.5", "idempotency_key": "key-00000009"})
	if st != 409 || errCode(rb) != "risk" || !strings.Contains(string(rb), "private_address") {
		t.Fatalf("%d %s", st, rb)
	}
	if _, sets := f2b.snapshot(); sets != 0 {
		t.Fatalf("a refused request reached Fail2ban: %d", sets)
	}

	// A ban is accepted at once, carried out by the agent through the helper, and verified.
	st, b := post(w.owner, "ban", map[string]any{"jail": "sshd", "ip": "93.184.216.9", "idempotency_key": "key-0000000a"})
	if st != 202 {
		t.Fatalf("%d %s", st, b)
	}
	c := parse[cmdResp](t, b)
	done := settled(c.Command.ID)
	if done.Command.State != "executed" || !done.Command.Verified {
		t.Fatalf("%+v", done)
	}
	if banned, _ := f2b.snapshot(); len(banned) != 2 || banned[1] != "93.184.216.9" {
		t.Fatalf("%v", banned)
	}

	// Sending the same request again returns the same command and runs nothing a second time.
	_, setsBefore := f2b.snapshot()
	st, b = post(w.owner, "ban", map[string]any{"jail": "sshd", "ip": "93.184.216.9", "idempotency_key": "key-0000000a"})
	if rr := parse[cmdResp](t, b); st != 200 || !rr.Repeated || rr.Command.ID != c.Command.ID {
		t.Fatalf("%d %s", st, b)
	}
	if _, sets := f2b.snapshot(); sets != setsBefore {
		t.Fatalf("a repeat ran again: %d -> %d", setsBefore, sets)
	}
	if st, _ := post(w.owner, "ban", map[string]any{"jail": "sshd", "ip": "93.184.216.77", "idempotency_key": "key-0000000a"}); st != 409 {
		t.Errorf("the same key for a different command: %d", st)
	}

	// The journal then records the ban as the change it is, and the audit trail has intent and outcome.
	eventually(t, "the journal to show the ban", func() bool {
		_, eb := w.owner.get(base + "/events?category=fail2ban")
		for _, e := range parse[struct {
			Items []struct {
				Type    string          `json:"type"`
				Payload json.RawMessage `json:"payload"`
			} `json:"items"`
		}](t, eb).Items {
			if e.Type == "fail2ban.ban" && strings.Contains(string(e.Payload), "93.184.216.9") {
				return true
			}
		}
		return false
	})
	count := func(q string, args ...any) (n int) { _ = w.h.st.Pool().QueryRow(ctx, q, args...).Scan(&n); return }
	if n := count(`SELECT count(*) FROM audit_log WHERE action='security.fail2ban.command' AND object_id=$1`, vpsID); n != 1 {
		t.Errorf("intent entries: %d", n)
	}
	eventually(t, "the outcome in the audit trail", func() bool {
		return count(`SELECT count(*) FROM audit_log WHERE action='security.fail2ban.command_result' AND object_id=$1 AND metadata->>'state'='executed'`, vpsID) == 1
	})

	// A flood of commands for one server is slowed down: the second in a moment is refused.
	w.h.srv.cmdLimit = auth.NewLimiter(0.0001, 1)
	st, b = post(w.owner, "ban", map[string]any{"jail": "sshd", "ip": "93.184.216.20", "idempotency_key": "key-0000000e"})
	if st != 202 {
		t.Fatalf("%d %s", st, b)
	}
	settled(parse[cmdResp](t, b).Command.ID)
	if st, b := post(w.owner, "ban", map[string]any{"jail": "sshd", "ip": "93.184.216.21", "idempotency_key": "key-0000000f"}); st != 429 {
		t.Fatalf("%d %s", st, b)
	}
	w.h.srv.cmdLimit = auth.NewLimiter(1000, 1000)

	// Unban, then unban again: the second finds nothing to do and says so.
	st, b = post(w.owner, "unban", map[string]any{"jail": "sshd", "ip": "93.184.216.9", "idempotency_key": "key-0000000b"})
	if st != 202 {
		t.Fatalf("%d %s", st, b)
	}
	if d := settled(parse[cmdResp](t, b).Command.ID); d.Command.State != "executed" {
		t.Fatalf("%+v", d)
	}
	st, b = post(w.owner, "unban", map[string]any{"jail": "sshd", "ip": "93.184.216.9", "idempotency_key": "key-0000000c"})
	if d := settled(parse[cmdResp](t, b).Command.ID); st != 202 || d.Command.State != "already_done" {
		t.Fatalf("%d %+v", st, d)
	}

	// With the agent gone nothing can be sent, and nothing is queued for later.
	stopAgent()
	eventually(t, "the server to see the agent leave", func() bool {
		f := get()
		return f.Manage != nil && !f.Manage.Ready && f.Manage.Reason == "agent_offline"
	})
	st, b = post(w.owner, "ban", map[string]any{"jail": "sshd", "ip": "93.184.216.50", "idempotency_key": "key-0000000d"})
	if st != 409 || errCode(b) != "agent_offline" {
		t.Fatalf("%d %s", st, b)
	}
	if n := count(`SELECT count(*) FROM security_commands WHERE ip='93.184.216.50'`); n != 0 {
		t.Errorf("a command was queued for an offline agent: %d", n)
	}
	_, lb := w.owner.get(base + "/commands")
	if l := parse[struct {
		Items []map[string]any `json:"items"`
	}](t, lb); len(l.Items) != 4 {
		t.Errorf("commands listed: %d", len(l.Items))
	}
}

func TestACommandAnswerIsAcceptedOnlyOnceAndOnlyFromItsAgent(t *testing.T) {
	w := newAgentWorld(t)
	v1 := mkVPS(t, w, "One", "203.0.113.1", "")
	v2 := mkVPS(t, w, "Two", "203.0.113.2", "")
	enrol := func(v string) string {
		_, b := w.owner.do("POST", "/api/v1/security/vps/"+v+"/agent", nil)
		return parse[struct {
			Agent struct {
				ID string `json:"id"`
			} `json:"agent"`
		}](t, b).Agent.ID
	}
	a1, a2 := enrol(v1), enrol(v2)
	all := store.Scope{All: true}
	now := time.Now().UTC()
	mk := func(key string) store.SecCommand {
		c, _, err := w.h.st.CreateCommand(ctx, all, v1, store.CommandInput{Action: "ban", Jail: "sshd", IP: "93.184.216.9", IdempotencyKey: key, TTL: 30 * time.Second}, now)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := mk("key-aaaaaaaa")
	res := func(id, status string, verified bool) secproto.CommandResult {
		return secproto.CommandResult{Type: "command_result", ID: id, Status: status, Verified: verified}
	}
	// Another server's agent cannot answer it.
	if _, err := w.h.st.CompleteCommand(ctx, a2, res(c.ID, "executed", true), now); err == nil {
		t.Fatal("a foreign agent settled a command")
	}
	done, err := w.h.st.CompleteCommand(ctx, a1, res(c.ID, "executed", true), now)
	if err != nil || done.State != "executed" || !done.Verified {
		t.Fatalf("%+v %v", done, err)
	}
	// A second answer, even a contradicting one, changes nothing.
	if _, err := w.h.st.CompleteCommand(ctx, a1, res(c.ID, "failed", false), now); err == nil {
		t.Fatal("a command was settled twice")
	}
	// "Executed" that the agent could not verify is stored as unknown, never as success.
	d2 := mk("key-bbbbbbbb")
	if x, err := w.h.st.CompleteCommand(ctx, a1, res(d2.ID, "executed", false), now); err != nil || x.State != "unknown" || x.Verified {
		t.Fatalf("%+v %v", x, err)
	}
}

func TestAnUnansweredCommandBecomesUnknownAndTheStateSettlesIt(t *testing.T) {
	w := newAgentWorld(t)
	v := mkVPS(t, w, "Quiet", "203.0.113.1", "")
	if st, _ := w.owner.do("POST", "/api/v1/security/vps/"+v+"/agent", nil); st != 201 {
		t.Fatal(st)
	}
	all := store.Scope{All: true}
	t0 := time.Now().UTC().Add(-5 * time.Minute)
	mk := func(key, action, ip string) store.SecCommand {
		c, _, err := w.h.st.CreateCommand(ctx, all, v, store.CommandInput{Action: action, Jail: "sshd", IP: ip, IdempotencyKey: key, TTL: 30 * time.Second}, t0)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.h.st.MarkSent(ctx, c.ID, t0); err != nil {
			t.Fatal(err)
		}
		return c
	}
	banned := mk("key-cccccccc", "ban", "93.184.216.9")
	notDone := mk("key-dddddddd", "ban", "93.184.216.10")
	stillPending := mk("key-eeeeeeee", "ban", "93.184.216.11")
	if _, err := w.h.st.Pool().Exec(ctx, `UPDATE security_commands SET deadline = now() + interval '1 minute' WHERE id=$1`, stillPending.ID); err != nil {
		t.Fatal(err)
	}
	state := func(id string) string {
		var s string
		_ = w.h.st.Pool().QueryRow(ctx, `SELECT state FROM security_commands WHERE id=$1`, id).Scan(&s)
		return s
	}

	// Past its deadline with no answer: unknown, not executed. One still inside its time stays pending.
	if _, err := w.h.st.SettleCommands(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if state(banned.ID) != "unknown" || state(stillPending.ID) != "pending" {
		t.Fatalf("%s %s", state(banned.ID), state(stillPending.ID))
	}

	// Fail2ban's state, read after the command was sent, shows one address banned and the other not.
	data, _ := json.Marshal(secproto.Fail2ban{Jails: []secproto.Jail{{Name: "sshd", BannedIPs: []string{"93.184.216.9"}}}})
	if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO security_snapshot_state (vps_id, category, status, source_hash, observed_at, received_at, data) VALUES ($1,'fail2ban','ok','h',now(),now(),$2)`, v, data); err != nil {
		t.Fatal(err)
	}
	if _, err := w.h.st.SettleCommands(ctx, time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if state(banned.ID) != "confirmed_by_state" {
		t.Fatalf("the state shows the ban: %s", state(banned.ID))
	}
	if state(notDone.ID) != "failed" {
		t.Fatalf("a state read well after the deadline without the ban ends it as failed: %s", state(notDone.ID))
	}
}
