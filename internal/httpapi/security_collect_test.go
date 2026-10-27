package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Taminum/Owlery/internal/secagent"
	"github.com/Taminum/Owlery/internal/seccollect"
	"github.com/Taminum/Owlery/internal/secproto"
)

// secFakeHost is a machine whose command output the test controls.
type secFakeHost struct {
	mu  sync.Mutex
	out map[string]seccollect.Result
}

func (f *secFakeHost) set(cmd string, r seccollect.Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.out[cmd] = r
}

func (f *secFakeHost) Run(_ context.Context, name string, args ...string) seccollect.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.out[name+" "+strings.Join(args, " ")]; ok {
		return r
	}
	return seccollect.Result{Err: os.ErrNotExist}
}

const (
	f2bList  = "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n"
	f2bJail1 = "Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t0\n|  |- Total failed:\t4\n|  `- File list:\t/var/log/auth.log\n`- Actions\n   |- Currently banned:\t1\n   |- Total banned:\t1\n   `- Banned IP list:\t203.0.113.5\n"
	f2bJail2 = "Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t0\n|  |- Total failed:\t5\n|  `- File list:\t/var/log/auth.log\n`- Actions\n   |- Currently banned:\t1\n   |- Total banned:\t2\n   `- Banned IP list:\t198.51.100.9\n"
)

type catResp struct {
	Category string          `json:"category"`
	State    string          `json:"state"`
	Status   string          `json:"status"`
	Data     json.RawMessage `json:"data"`
	Agent    *struct {
		Online bool `json:"online"`
	} `json:"agent"`
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if ok() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestSecurityAgentReportsAndChangesBecomeEvents(t *testing.T) {
	w := newAgentWorld(t)
	_, b := w.owner.do("POST", "/api/v1/security/vps", map[string]any{"name": "Helsinki"})
	v := parse[vpsResp](t, b)
	base := "/api/v1/security/vps/" + v.ID

	// Before an agent exists every category says so, never "ok" and never zero.
	_, cb := w.owner.get(base + "/fail2ban")
	if c := parse[catResp](t, cb); c.State != "agent_required" || string(c.Data) != "null" {
		t.Fatalf("%+v", c)
	}

	st, ab := w.owner.do("POST", base+"/agent", nil)
	if st != 201 {
		t.Fatalf("enrol: %d %s", st, ab)
	}
	enrol := parse[struct {
		Token string `json:"token"`
	}](t, ab)
	if st, _ := w.owner.do("POST", base+"/agent", nil); st != 409 {
		t.Errorf("a second live agent: %d", st)
	}
	if st, _ := w.viewer.do("POST", base+"/agent", nil); st != 404 {
		t.Errorf("a viewer of an unlinked server must not even see it: %d", st)
	}

	host := &secFakeHost{out: map[string]seccollect.Result{
		"fail2ban-client status":      {Stdout: f2bList},
		"fail2ban-client status sshd": {Stdout: f2bJail1},
		"ss -H -tulnp":                {Stdout: "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n"},
		"nft list ruleset":            {Stdout: "table inet filter {\n}\n"},
	}}
	tokFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokFile, []byte(enrol.Token), 0o600); err != nil {
		t.Fatal(err)
	}
	actx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = secagent.Run(actx, secagent.Config{ServerURL: "ws" + strings.TrimPrefix(w.h.ts.URL, "http"), TokenFile: tokFile, AllowInsecure: true,
			Interval: 150 * time.Millisecond, Version: "test", Runner: host})
	}()
	defer func() { stop(); <-done }()

	get := func(cat string) catResp {
		_, b := w.owner.get(base + "/" + cat)
		return parse[catResp](t, b)
	}
	eventually(t, "the first reports", func() bool {
		return get("fail2ban").State == "ok" && get("ports").State == "ok" && get("firewall").State == "ok"
	})
	f := get("fail2ban")
	if f.Agent == nil || !f.Agent.Online || !strings.Contains(string(f.Data), "203.0.113.5") {
		t.Fatalf("%+v %s", f, f.Data)
	}

	// The first reports were the baseline: they explain nothing, so the journal is still empty.
	_, eb := w.owner.get(base + "/events")
	if ev := parse[struct {
		Items []map[string]any `json:"items"`
	}](t, eb); len(ev.Items) != 0 {
		t.Fatalf("the baseline produced events: %v", ev.Items)
	}

	// A ban lifted and another placed, a new listener, a rule added.
	host.set("fail2ban-client status sshd", seccollect.Result{Stdout: f2bJail2})
	host.set("ss -H -tulnp", seccollect.Result{Stdout: "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 4096 0.0.0.0:9000 0.0.0.0:*\n"})
	host.set("nft list ruleset", seccollect.Result{Stdout: "table inet filter {\n\tchain input {\n\t\ttcp dport 22 accept\n\t}\n}\n"})
	want := []string{"fail2ban.ban", "fail2ban.unban", "port.local_added", "firewall.rules_changed"}
	var types map[string]int
	eventually(t, "the journal to explain the changes", func() bool {
		_, eb := w.owner.get(base + "/events")
		types = map[string]int{}
		for _, e := range parse[struct {
			Items []struct {
				Type   string `json:"type"`
				Source string `json:"source"`
			} `json:"items"`
		}](t, eb).Items {
			types[e.Type]++
			if e.Source != "state_diff" {
				t.Errorf("an event must say where it came from: %+v", e)
			}
		}
		for _, k := range want {
			if types[k] != 1 {
				return false
			}
		}
		return true
	})
	time.Sleep(500 * time.Millisecond) // several more identical reports: no more events
	_, eb = w.owner.get(base + "/events?category=fail2ban")
	if ev := parse[struct {
		Items []map[string]any `json:"items"`
	}](t, eb); len(ev.Items) != 2 {
		t.Fatalf("repeated identical reports must not repeat events: %d", len(ev.Items))
	}

	// A host that stops allowing the read is reported as such; its bans are not "lifted".
	host.set("fail2ban-client status", seccollect.Result{Stderr: "ERROR Permission denied to socket", ExitCode: 255})
	eventually(t, "permission_denied", func() bool { return get("fail2ban").State == "permission_denied" })
	_, eb = w.owner.get(base + "/events?category=fail2ban")
	if ev := parse[struct {
		Items []struct {
			Type string `json:"type"`
		} `json:"items"`
	}](t, eb); len(ev.Items) != 3 || ev.Items[0].Type != "fail2ban.state_changed" {
		t.Fatalf("%+v", ev.Items)
	}

	// Revoking cuts the agent off, and its data is kept but no longer fresh forever.
	if st, _ := w.owner.do("DELETE", base+"/agent", nil); st != 204 {
		t.Fatalf("revoke: %d", st)
	}
	eventually(t, "the agent to be refused", func() bool {
		hdr := http.Header{"Authorization": {"Bearer " + enrol.Token}}
		_, resp, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(w.h.ts.URL, "http")+secproto.Path, &websocket.DialOptions{HTTPHeader: hdr})
		return err != nil && resp != nil && resp.StatusCode == 401
	})
}

func TestSecurityIngestRejectsBadInputAndRepeats(t *testing.T) {
	w := newAgentWorld(t)
	_, b := w.owner.do("POST", "/api/v1/security/vps", map[string]any{"name": "Oslo"})
	v := parse[vpsResp](t, b)
	_, ab := w.owner.do("POST", "/api/v1/security/vps/"+v.ID+"/agent", nil)
	token := parse[struct {
		Token string `json:"token"`
	}](t, ab).Token
	url := "ws" + strings.TrimPrefix(w.h.ts.URL, "http") + secproto.Path
	ctx := context.Background()

	// No credential, a wrong one, and a browser Origin are all refused before the upgrade.
	for name, hdr := range map[string]http.Header{
		"none": {}, "wrong": {"Authorization": {"Bearer " + strings.Split(token, ".")[0] + ".wrongwrongwrongwrongwrong"}}, "origin": {"Authorization": {"Bearer " + token}, "Origin": {"https://evil.example"}},
	} {
		if _, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: hdr}); err == nil || resp == nil || resp.StatusCode < 400 {
			t.Errorf("%s was not refused", name)
		}
	}

	dial := func() (*websocket.Conn, func(v any), func() map[string]any) {
		c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + token}}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.CloseNow() })
		send := func(v any) {
			b, _ := json.Marshal(v)
			if err := c.Write(ctx, websocket.MessageText, b); err != nil {
				t.Fatal(err)
			}
		}
		recv := func() map[string]any {
			rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_, b, err := c.Read(rctx)
			if err != nil {
				return map[string]any{"closed": err.Error()}
			}
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			return m
		}
		send(secproto.Hello{Type: "hello", ProtoVersion: secproto.Version, AgentVersion: "t", Epoch: "e1", Capabilities: []string{"fail2ban_read", "future_cap"}})
		if m := recv(); m["type"] != "welcome" {
			t.Fatalf("%v", m)
		}
		return c, send, recv
	}
	snap := func(seq int64, cat, status string, data string) secproto.Snapshot {
		s := secproto.Snapshot{Type: "snapshot", Seq: seq, Category: cat, Schema: 1, ObservedAt: time.Now().UTC(), Status: status}
		if data != "" {
			s.Data = json.RawMessage(data)
		}
		return s
	}

	_, send, recv := dial()
	send(snap(1, "firewall", "ok", `{"backend":"nft","rules":"table x"}`))
	if m := recv(); m["ack_seq"] != float64(1) || m["stored"] != true {
		t.Fatalf("%v", m)
	}
	// The same sequence again is acknowledged but not stored a second time.
	send(snap(1, "firewall", "ok", `{"backend":"nft","rules":"table y"}`))
	if m := recv(); m["ack_seq"] != float64(1) || m["stored"] != false {
		t.Fatalf("%v", m)
	}
	_, fb := w.owner.get("/api/v1/security/vps/" + v.ID + "/firewall")
	if !strings.Contains(string(parse[catResp](t, fb).Data), "table x") {
		t.Fatalf("a replay changed the stored state: %s", fb)
	}

	// Malformed or hostile snapshots end the session instead of being stored.
	for name, bad := range map[string]secproto.Snapshot{
		"unknown category": snap(2, "shell", "ok", `{}`),
		"unknown status":   snap(2, "firewall", "fine", `{"backend":"nft","rules":""}`),
		"unknown field":    snap(2, "firewall", "ok", `{"backend":"nft","rules":"","exec":"rm -rf /"}`),
		"huge rules":       snap(2, "firewall", "ok", `{"backend":"nft","rules":"`+strings.Repeat("a", secproto.MaxRulesBytes+1)+`"}`),
		"bad port":         snap(2, "sockets", "ok", `{"listeners":[{"proto":"tcp","addr":"x","port":70000}],"process_info":false}`),
		"zero seq":         snap(0, "firewall", "ok", `{"backend":"nft","rules":""}`),
		"ok with no data":  snap(2, "fail2ban", "ok", ``),
	} {
		_, send, recv := dial()
		send(bad)
		if m := recv(); m["type"] != "error" && m["closed"] == nil {
			t.Errorf("%s was accepted: %v", name, m)
		}
	}
	// An unknown message type is refused too.
	_, send2, recv2 := dial()
	send2(map[string]any{"type": "run", "cmd": "id"})
	if m := recv2(); m["type"] != "error" && m["closed"] == nil {
		t.Errorf("%v", m)
	}
}

func TestSecurityDataFollowsServerVisibility(t *testing.T) {
	w := newAgentWorld(t)
	_, b := w.owner.do("POST", "/api/v1/security/vps", map[string]any{"name": "Private"})
	v := parse[vpsResp](t, b)
	for _, p := range []string{"/fail2ban", "/ports", "/firewall", "/events", "/agent"} {
		if st, _ := w.adm.get("/api/v1/security/vps/" + v.ID + p); st != 404 {
			t.Errorf("%s of an unlinked server for a panel admin: %d", p, st)
		}
		if st, _ := w.h.anon().get("/api/v1/security/vps/" + v.ID + p); st != 401 {
			t.Errorf("%s anonymous: %d", p, st)
		}
	}
	if st, _ := w.owner.get("/api/v1/security/vps/" + v.ID + "/events?limit=0"); st != 400 {
		t.Errorf("limit 0: %d", st)
	}
	if st, _ := w.owner.get("/api/v1/security/vps/" + v.ID + "/events?category=shell"); st != 400 {
		t.Errorf("bad category: %d", st)
	}
}

func TestArchivingAServerRevokesItsAgent(t *testing.T) {
	w := newAgentWorld(t)
	_, b := w.owner.do("POST", "/api/v1/security/vps", map[string]any{"name": "Gone soon"})
	v := parse[vpsResp](t, b)
	_, ab := w.owner.do("POST", "/api/v1/security/vps/"+v.ID+"/agent", nil)
	token := parse[struct {
		Token string `json:"token"`
	}](t, ab).Token
	url := "ws" + strings.TrimPrefix(w.h.ts.URL, "http") + secproto.Path
	hdr := http.Header{"Authorization": {"Bearer " + token}}

	c, _, err := websocket.Dial(context.Background(), url, &websocket.DialOptions{HTTPHeader: hdr})
	if err != nil {
		t.Fatalf("a live agent must connect: %v", err)
	}
	c.CloseNow()

	if st, _ := w.owner.do("DELETE", "/api/v1/security/vps/"+v.ID, nil); st != 204 {
		t.Fatalf("archive: %d", st)
	}
	if _, resp, err := websocket.Dial(context.Background(), url, &websocket.DialOptions{HTTPHeader: hdr}); err == nil || resp == nil || resp.StatusCode != 401 {
		t.Fatalf("an archived server's agent must be refused: %v %v", err, resp)
	}
}
