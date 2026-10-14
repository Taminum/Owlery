package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Taminum/RemnaScope/internal/demo"
	"github.com/Taminum/RemnaScope/internal/ingestproto"
	"github.com/Taminum/RemnaScope/internal/remnawave"
	"github.com/Taminum/RemnaScope/internal/store"
)

type agentOut struct {
	Agent store.Agent `json:"agent"`
	Token string      `json:"token"`
}

// syncPanel runs a real sync so nodes and users exist, as they would after the scheduler ran.
func (w *world) syncAll() {
	w.h.t.Helper()
	for _, p := range []panelDTO{w.home, w.work} {
		if _, err := w.h.srv.Sync.SyncPanel(ctx, p.ID, "manual"); err != nil {
			w.h.t.Fatal(err)
		}
	}
}

func newAgentWorld(t *testing.T) *world {
	t.Helper()
	h := newHarness(t)
	h.remote["home.example.com"] = &fakePanel{
		nodes: []remnawave.Node{{RemoteUUID: "h1", Name: "home-a"}, {RemoteUUID: "h2", Name: "home-b"}},
		users: []remnawave.User{{RemoteUUID: "2", Username: "alexandra", Status: "ACTIVE"}, {RemoteUUID: "4", Username: "openwrt", Status: "ACTIVE"}},
	}
	h.remote["work.example.com"] = &fakePanel{
		nodes: []remnawave.Node{{RemoteUUID: "w1", Name: "work-1"}},
		users: []remnawave.User{{RemoteUUID: "2", Username: "someone-else", Status: "ACTIVE"}},
	}
	h.account("owner", true)
	owner := h.login("owner")
	w := &world{h: h, owner: owner}
	w.home = h.createPanel(owner, "Home", "home.example.com", tokGood)
	w.work = h.createPanel(owner, "Work", "work.example.com", tokGood2)
	w.syncAll()
	h.account("viewer", false, store.Membership{PanelID: w.work.ID, Role: "viewer"})
	h.account("operator", false, store.Membership{PanelID: w.work.ID, Role: "operator"})
	h.account("padmin", false, store.Membership{PanelID: w.work.ID, Role: "admin"})
	w.viewer, w.op, w.adm = h.login("viewer"), h.login("operator"), h.login("padmin")
	return w
}

func nodeID(t *testing.T, c *client, panelID, name string) string {
	t.Helper()
	_, b := c.get("/api/v1/panels/" + panelID + "/nodes")
	for _, n := range parse[struct {
		Nodes []store.Node `json:"nodes"`
	}](t, b).Nodes {
		if n.Name == name {
			return n.ID
		}
	}
	t.Fatalf("node %s not found in %s", name, b)
	return ""
}

func enroll(t *testing.T, c *client, panelID, node string) agentOut {
	t.Helper()
	st, b := c.do("POST", "/api/v1/panels/"+panelID+"/agents", map[string]any{"node_id": node, "name": "agent for " + node[:4]})
	if st != 201 {
		t.Fatalf("enrol: %d %s", st, b)
	}
	return parse[agentOut](t, b)
}

func sampleLines(t *testing.T) []string {
	t.Helper()
	f, err := os.Open("../xraylog/testdata/sample_sanitized.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// push connects as the agent through the real public route and sends lines.
func push(t *testing.T, h *harness, token string, from int64, lines []string) ingestproto.Ack {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(h.ts.URL, "http") + ingestproto.Path
	c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + token}}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.CloseNow()
	send := func(v any) {
		b, _ := json.Marshal(v)
		if err := c.Write(ctx, websocket.MessageText, b); err != nil {
			t.Fatal(err)
		}
	}
	recv := func(v any) {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_, b, err := c.Read(rctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(b, v)
	}
	send(ingestproto.Hello{Type: "hello", ProtoVersion: ingestproto.Version, AgentVersion: "test", Epoch: "e1", SourceID: "test"})
	var w ingestproto.Welcome
	recv(&w)
	items := make([]ingestproto.Item, len(lines))
	for i, l := range lines {
		items[i] = ingestproto.Item{Seq: from + int64(i), Line: l}
	}
	send(ingestproto.Batch{Type: "batch", BatchID: "b", Items: items})
	var ack ingestproto.Ack
	recv(&ack)
	return ack
}

func TestEnrollingAgentsFollowsTheRoleLadder(t *testing.T) {
	w := newAgentWorld(t)
	node := nodeID(t, w.owner, w.work.ID, "work-1")
	path := "/api/v1/panels/" + w.work.ID + "/agents"
	body := map[string]any{"node_id": node}

	if st, _ := w.viewer.do("POST", path, body); st != 403 {
		t.Fatalf("viewer enrol: %d", st)
	}
	if st, _ := w.op.do("POST", path, body); st != 403 {
		t.Fatalf("operator enrol: %d", st)
	}
	if st, _ := w.viewer.get(path); st != 403 {
		t.Fatalf("viewer list: %d", st)
	}
	if st, _ := w.op.get(path); st != 200 {
		t.Fatalf("operator may see agent status: %d", st)
	}
	a := enroll(t, w.adm, w.work.ID, node)
	if !strings.HasPrefix(a.Token, a.Agent.ID+".") || len(a.Token) < 60 {
		t.Fatalf("token shape: %q", a.Token)
	}
	if st, b := w.adm.do("POST", path, body); st != 409 || errCode(b) != "agent_exists" {
		t.Fatalf("one agent per node: %d %s", st, b)
	}
	// Home stays out of reach.
	homeNode := nodeID(t, w.owner, w.home.ID, "home-a")
	if st, _ := w.adm.do("POST", "/api/v1/panels/"+w.home.ID+"/agents", map[string]any{"node_id": homeNode}); st != 404 {
		t.Fatalf("a Work admin enrolling on Home: %d", st)
	}
	if st, _ := w.adm.do("POST", path, map[string]any{"node_id": homeNode}); st != 404 {
		t.Fatalf("a node of another panel: %d", st)
	}
	if st, b := w.owner.do("POST", "/api/v1/panels/"+demo.Panels[0].ID+"/agents", map[string]any{"node_id": node}); st != 409 || errCode(b) != "demo_panel" {
		t.Fatalf("demo panels have no agents: %d %s", st, b)
	}
}

func TestTheAgentCredentialIsShownOnceAndNeverStoredReadable(t *testing.T) {
	w := newAgentWorld(t)
	a := enroll(t, w.owner, w.work.ID, nodeID(t, w.owner, w.work.ID, "work-1"))
	secret := strings.SplitN(a.Token, ".", 2)[1]

	for _, path := range []string{"/api/v1/panels/" + w.work.ID + "/agents", "/api/v1/audit", "/api/v1/scope", "/api/v1/panels"} {
		st, b := w.owner.get(path)
		if st != 200 || strings.Contains(string(b), secret) || strings.Contains(string(b), "token_hash") {
			t.Fatalf("%s leaks the credential or its hash: %d", path, st)
		}
	}
	var stored bool
	_ = w.h.st.Pool().QueryRow(ctx, `SELECT position($1::bytea in token_hash) > 0 FROM agents WHERE id=$2`, secret, a.Agent.ID).Scan(&stored)
	if stored {
		t.Fatal("the secret must not be stored in the clear")
	}
	if strings.Contains(w.h.logs.String(), secret) {
		t.Fatal("the secret reached the logs")
	}
	var audited int
	_ = w.h.st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='agent.create' AND metadata::text NOT LIKE '%'||$1||'%'`, secret).Scan(&audited)
	if audited != 1 {
		t.Fatalf("enrolling must be audited without the secret, found %d", audited)
	}
}

func TestRevokingAnAgentCutsItOffAtOnce(t *testing.T) {
	w := newAgentWorld(t)
	a := enroll(t, w.owner, w.work.ID, nodeID(t, w.owner, w.work.ID, "work-1"))
	lines := sampleLines(t)[:10]
	if ack := push(t, w.h, a.Token, 1, lines); ack.Accepted != 10 {
		t.Fatalf("%+v", ack)
	}
	if st, _ := w.op.do("DELETE", "/api/v1/panels/"+w.work.ID+"/agents/"+a.Agent.ID, nil); st != 403 {
		t.Fatalf("operator revoke: %d", st)
	}
	if st, _ := w.adm.do("DELETE", "/api/v1/panels/"+w.work.ID+"/agents/"+a.Agent.ID, nil); st != 204 {
		t.Fatalf("admin revoke: %d", st)
	}
	_, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(w.h.ts.URL, "http")+ingestproto.Path, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + a.Token}}})
	if err == nil || resp == nil || resp.StatusCode != 401 {
		t.Fatalf("a revoked credential must be refused: %v", err)
	}
	if st, _ := w.adm.do("DELETE", "/api/v1/panels/"+w.work.ID+"/agents/"+a.Agent.ID, nil); st != 404 {
		t.Fatalf("second revoke: %d", st)
	}
	// The node can be enrolled again with a fresh credential.
	enroll(t, w.adm, w.work.ID, nodeID(t, w.owner, w.work.ID, "work-1"))
}

func TestTheIngestRouteIsOutsideSessionAndCSRFButNotOpen(t *testing.T) {
	w := newAgentWorld(t)
	url := "ws" + strings.TrimPrefix(w.h.ts.URL, "http") + ingestproto.Path
	for name, hdr := range map[string]http.Header{
		"no credential": {},
		"a user session cookie is not an agent credential": {"Cookie": {CookieSession + "=whatever"}},
	} {
		_, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: hdr})
		if err == nil || resp == nil || resp.StatusCode != 401 {
			t.Fatalf("%s: %v", name, err)
		}
	}
	a := enroll(t, w.owner, w.work.ID, nodeID(t, w.owner, w.work.ID, "work-1"))
	_, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + a.Token}, "Origin": {"https://evil.example"}}})
	if err == nil || resp.StatusCode != 403 {
		t.Fatalf("a browser origin must be refused: %v", err)
	}
	// An agent credential opens nothing else.
	req, _ := http.NewRequest("GET", w.h.ts.URL+"/api/v1/panels", nil)
	req.Header.Set("Authorization", "Bearer "+a.Token)
	r, _ := http.DefaultClient.Do(req)
	r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatalf("the API must not accept an agent credential: %d", r.StatusCode)
	}
}

func TestEventsReachTheOverviewHonestlyAndStayInTheirPanel(t *testing.T) {
	w := newAgentWorld(t)
	homeAgent := enroll(t, w.owner, w.home.ID, nodeID(t, w.owner, w.home.ID, "home-a"))
	workAgent := enroll(t, w.owner, w.work.ID, nodeID(t, w.owner, w.work.ID, "work-1"))

	over := func(c *client, q string) demo.Overview {
		st, b := c.get("/api/v1/overview?range=30d" + q)
		if st != 200 {
			t.Fatalf("%d %s", st, b)
		}
		return parse[demo.Overview](t, b)
	}

	// An agent exists but has sent nothing yet: said plainly, no numbers.
	ov := over(w.owner, "&panel_ids="+w.home.ID)
	if ov.Meta.State != "no_data" || ov.Meta.Reason != "no_events" || ov.Meta.Demo || ov.Connections.Total != 0 {
		t.Fatalf("%+v", ov.Meta)
	}

	lines := sampleLines(t) // 120 sanitised real-shaped lines; timestamps are Oct 9 2026
	if ack := push(t, w.h, homeAgent.Token, 1, lines); ack.Accepted != 120 {
		t.Fatalf("%+v", ack)
	}
	if ack := push(t, w.h, workAgent.Token, 1, lines[:40]); ack.Accepted != 40 {
		t.Fatalf("%+v", ack)
	}
	w.h.advance(0)
	from, to := "2026-10-09T00:00:00Z", "2026-10-10T00:00:00Z"
	q := "&from=" + from + "&to=" + to
	get := func(c *client, panel string) demo.Overview {
		st, b := c.get("/api/v1/overview?from=" + from + "&to=" + to + panel)
		if st != 200 {
			t.Fatalf("%d %s", st, b)
		}
		return parse[demo.Overview](t, b)
	}
	_ = q

	home := get(w.owner, "&panel_ids="+w.home.ID)
	if home.Meta.State != "ok" || home.Meta.Demo || home.Connections.Total != 120 || home.Connections.TCP+home.Connections.UDP != 120 ||
		home.Connections.MetricKind != demo.KindConnections || home.Traffic.MetricKind != demo.KindBytes || home.Traffic.UpBytes != 0 || len(home.Traffic.Series) != 0 {
		t.Fatalf("%+v %+v", home.Meta, home.Connections)
	}
	tl := 0
	for _, p := range home.Timeline {
		tl += p.TCP + p.UDP
	}
	if tl != 120 || home.UniqueHosts.Value == 0 || len(home.TopHosts) == 0 || len(home.Recent) == 0 {
		t.Fatalf("timeline=%d hosts=%d", tl, home.UniqueHosts.Value)
	}
	sum := 0
	for _, r := range home.TopPorts {
		sum += r.Count
	}
	if sum != 120 {
		t.Fatalf("ports (with 'other') must add up to the total: %d", sum)
	}
	// Coverage: home-a has an agent, home-b does not, and that is shown instead of hidden.
	if home.Meta.Coverage.Pct != 50 || !hasGap(home, "home-b (no_agent)") {
		t.Fatalf("coverage %+v", home.Meta.Coverage)
	}
	if home.Nodes.Reporting != 1 || home.Nodes.Total != 2 {
		t.Fatalf("%+v", home.Nodes)
	}

	// Users resolve through the panel's own table; the router id and system lines are named as such.
	byLabel := map[string]demo.Row{}
	for _, u := range home.Users {
		byLabel[u.Label] = u
	}
	if byLabel["alexandra"].Count == 0 || byLabel["система"].Count == 0 {
		t.Fatalf("users: %+v", home.Users)
	}
	if u, ok := byLabel["id 3"]; !ok || u.Note != "не сопоставлен" {
		t.Fatalf("email 3 is not a user of this panel and must be shown as an unresolved id: %+v", home.Users)
	}

	// Work holds its own 40 events; the same raw email "2" resolves to Work's user, not Home's.
	work := get(w.owner, "&panel_ids="+w.work.ID)
	if work.Connections.Total != 40 {
		t.Fatalf("work total %d", work.Connections.Total)
	}
	for _, u := range work.Users {
		if u.PanelID != w.work.ID || u.Label == "alexandra" {
			t.Fatalf("a Home user leaked into Work: %+v", u)
		}
	}
	both := get(w.owner, "&panel_ids="+w.home.ID+","+w.work.ID)
	if both.Connections.Total != 160 {
		t.Fatalf("aggregate %d", both.Connections.Total)
	}

	// The Work viewer sees only Work, with account names masked.
	if st, b := w.viewer.get("/api/v1/overview?from=" + from + "&to=" + to + "&panel_ids=" + w.home.ID); st != 403 || errCode(b) != "panel_forbidden" {
		t.Fatalf("%d %s", st, b)
	}
	vw := get(w.viewer, "")
	if vw.Connections.Total != 40 || len(vw.Meta.PanelIDs) != 1 || vw.Meta.PanelIDs[0] != w.work.ID {
		t.Fatalf("the viewer's default scope must be Work only: %+v", vw.Meta)
	}
	for _, u := range vw.Users {
		if u.Label == "someone-else" {
			t.Fatalf("a viewer must not see account names: %+v", u)
		}
	}
	op := get(w.op, "")
	var sawName bool
	for _, u := range op.Users {
		sawName = sawName || u.Label == "someone-else"
	}
	if !sawName {
		t.Fatalf("an operator sees names: %+v", op.Users)
	}
	// Node filter narrows to that node's events; another panel's node is refused.
	workNode := nodeID(t, w.owner, w.work.ID, "work-1")
	if n := get(w.owner, "&panel_ids="+w.work.ID+"&node_ids="+workNode); n.Connections.Total != 40 {
		t.Fatalf("%d", n.Connections.Total)
	}
	if st, _ := w.owner.get("/api/v1/overview?from=" + from + "&to=" + to + "&panel_ids=" + w.work.ID + "&node_ids=" + nodeID(t, w.owner, w.home.ID, "home-a")); st != 400 {
		t.Fatalf("%d", st)
	}
	// Outside the window nothing shows up, and it says so.
	if empty := get(w.owner, "&panel_ids="+w.home.ID+"&from=x"); false {
		_ = empty
	}
	st, b := w.owner.get("/api/v1/overview?from=2026-11-01T00:00:00Z&to=2026-11-02T00:00:00Z&panel_ids=" + w.home.ID)
	later := parse[demo.Overview](t, b)
	if st != 200 || later.Meta.State != "no_data" || later.Connections.Total != 0 {
		t.Fatalf("%d %+v", st, later.Meta)
	}
}

func hasGap(ov demo.Overview, name string) bool {
	for _, g := range ov.Meta.Coverage.Gaps {
		if g.NodeName == name {
			return true
		}
	}
	return false
}

func TestAgentMetadataNeverShowsOtherPanelsToAScopedUser(t *testing.T) {
	w := newAgentWorld(t)
	enroll(t, w.owner, w.home.ID, nodeID(t, w.owner, w.home.ID, "home-a"))
	if st, _ := w.op.get("/api/v1/panels/" + w.home.ID + "/agents"); st != 404 {
		t.Fatalf("a Work operator listing Home's agents: %d", st)
	}
	_, b := w.owner.get("/api/v1/panels/" + w.home.ID + "/agents")
	if !bytes.Contains(b, []byte("home-a")) {
		t.Fatalf("%s", b)
	}
}

var nullList = regexp.MustCompile(`"(ts|v|series|gaps|timeline|top_hosts|top_ips|top_ports|services|users|recent|node_ids|panel_ids|nodes_preview)":null`)

// A JSON null where the UI expects an array crashes the page (this happened in production).
func TestNoOverviewShapeEverContainsANullList(t *testing.T) {
	w := newAgentWorld(t)
	homeAgent := enroll(t, w.owner, w.home.ID, nodeID(t, w.owner, w.home.ID, "home-a"))
	check := func(name, path string) {
		t.Helper()
		st, b := w.owner.get(path)
		if st != 200 {
			t.Fatalf("%s: %d %s", name, st, b)
		}
		if m := nullList.Find(b); m != nil {
			t.Errorf("%s: a list is null in the JSON: %s", name, m)
		}
	}
	w2 := "&from=2026-10-09T00:00:00Z&to=2026-10-10T00:00:00Z"
	check("agent but no events", "/api/v1/overview?range=24h&panel_ids="+w.home.ID)
	check("no agents at all", "/api/v1/overview?range=24h&panel_ids="+w.work.ID)
	check("demo", "/api/v1/overview?range=24h&panel_ids="+demo.Panels[0].ID)
	check("demo empty state", "/api/v1/overview?range=24h&panel_ids="+demo.Panels[0].ID+"&demo_state=empty")
	if ack := push(t, w.h, homeAgent.Token, 1, sampleLines(t)); ack.Accepted != 120 {
		t.Fatalf("%+v", ack)
	}
	check("real events", "/api/v1/overview?panel_ids="+w.home.ID+w2[0:0]+"&from=2026-10-09T00:00:00Z&to=2026-10-10T00:00:00Z")
	check("real events, a window without any", "/api/v1/overview?panel_ids="+w.home.ID+"&from=2026-11-01T00:00:00Z&to=2026-11-02T00:00:00Z")
}
