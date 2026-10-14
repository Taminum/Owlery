package ingest

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/ingestproto"
	"github.com/Taminum/RemnaScope/internal/store"
	"github.com/Taminum/RemnaScope/internal/store/storetest"
)

var ctx = context.Background()

const secret = "agent-secret-0123456789abcdef"

type env struct {
	st    *store.Store
	panel store.Panel
	agent store.Agent
	srv   *httptest.Server
	wsURL string
	user2 string
}

func newEnv(t *testing.T, tune func(*Server)) *env {
	t.Helper()
	st := storetest.New(t)
	p, err := st.CreatePanel(ctx, store.NewPanelID(), store.PanelInput{Name: "home", BaseURL: "https://home.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_, _ = st.UpsertNodes(ctx, p.ID, now, []store.NodeRecord{{RemoteUUID: "n", Name: "node-1"}})
	_, _ = st.UpsertUsers(ctx, p.ID, now, []store.UserRecord{{RemoteUUID: "2", Username: "alice"}, {RemoteUUID: "4", Username: "router"}})
	nodes, _ := st.ListNodes(ctx, store.Scope{All: true}, p.ID, false)
	a, err := st.CreateAgent(ctx, store.Scope{All: true}, p.ID, nodes[0].ID, "a", "node", "", store.HashAgentSecret(secret))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Store: st}
	if tune != nil {
		tune(s)
	}
	srv := httptest.NewUnstartedServer(s.Handler())
	srv.Start()
	t.Cleanup(srv.Close)
	return &env{st: st, panel: p, agent: a, srv: srv, wsURL: "ws" + strings.TrimPrefix(srv.URL, "http")}
}

func (e *env) dial(t *testing.T, token string, hdr ...string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	h := http.Header{}
	if token != "" {
		h.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		h.Set(hdr[i], hdr[i+1])
	}
	c, resp, err := websocket.Dial(ctx, e.wsURL, &websocket.DialOptions{HTTPHeader: h})
	if c != nil {
		c.SetReadLimit(1 << 20)
		t.Cleanup(func() { c.CloseNow() })
	}
	return c, resp, err
}

func (e *env) token() string { return e.agent.ID + "." + secret }

func write(t *testing.T, c *websocket.Conn, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := c.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
}

func read[T any](t *testing.T, c *websocket.Conn) T {
	t.Helper()
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, b, err := c.Read(rctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	return v
}

func hello(t *testing.T, c *websocket.Conn, epoch string) ingestproto.Welcome {
	t.Helper()
	write(t, c, ingestproto.Hello{Type: "hello", ProtoVersion: ingestproto.Version, AgentVersion: "test", Epoch: epoch, SourceID: "test:/var/log/xray/current"})
	return read[ingestproto.Welcome](t, c)
}

func sampleItems(t *testing.T, from int64, n int) []ingestproto.Item {
	t.Helper()
	f, err := os.Open("../xraylog/testdata/sample_sanitized.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []ingestproto.Item
	sc := bufio.NewScanner(f)
	for i := int64(0); sc.Scan() && len(out) < n; i++ {
		out = append(out, ingestproto.Item{Seq: from + int64(len(out)), Line: sc.Text()})
	}
	return out
}

func countRows(t *testing.T, st *store.Store) int {
	var n int
	_ = st.Pool().QueryRow(ctx, `SELECT count(*) FROM connection_events`).Scan(&n)
	return n
}

func TestOnlyAValidAgentCanConnectAndAllFailuresLookTheSame(t *testing.T) {
	e := newEnv(t, nil)
	_ = e.st.RevokeAgent(ctx, store.Scope{All: true}, e.panel.ID, e.agent.ID)
	live := newEnv(t, nil)
	bodies := map[string]string{}
	for name, tok := range map[string]string{
		"none":         "",
		"garbage":      "nonsense",
		"no dot":       "abcdefabcdefabcdefabcdefabcdef",
		"wrong secret": live.agent.ID + ".wrong-secret-0123456789abcdef",
		"unknown id":   "00000000-0000-4000-8000-000000000000." + secret,
		"short secret": live.agent.ID + ".short",
		"other agent":  e.agent.ID + "." + secret, // valid secret, but for a different environment's agent id
	} {
		_, resp, err := live.dial(t, tok)
		if err == nil || resp == nil || resp.StatusCode != 401 {
			t.Fatalf("%s: want 401, got %v %v", name, resp, err)
		}
		bodies[name] = resp.Header.Get("WWW-Authenticate")
	}
	for name, h := range bodies {
		if h != bodies["none"] {
			t.Errorf("%s answers differently", name)
		}
	}
	if _, resp, err := e.dial(t, e.token()); err == nil || resp.StatusCode != 401 {
		t.Fatalf("a revoked agent must be refused at the door: %v", err)
	}
	if c, _, err := live.dial(t, live.token()); err != nil {
		t.Fatalf("the real agent must connect: %v", err)
	} else {
		c.CloseNow()
	}
}

func TestBrowsersAndPlainRequestsAreRefused(t *testing.T) {
	e := newEnv(t, nil)
	if _, resp, err := e.dial(t, e.token(), "Origin", "https://evil.example"); err == nil || resp.StatusCode != 403 {
		t.Fatalf("a request with an Origin must be refused: %v", err)
	}
	req, _ := http.NewRequest("GET", e.srv.URL, nil)
	req.Header.Set("Authorization", "Bearer "+e.token())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == 200 || resp.StatusCode == 101 {
		t.Fatalf("a plain GET is not a WebSocket upgrade: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("POST", e.srv.URL, nil)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Fatalf("POST: %d", resp.StatusCode)
	}
}

func TestConnectionAttemptsAreRateLimited(t *testing.T) {
	e := newEnv(t, func(s *Server) {
		s.Limiter = auth.NewLimiter(0.001, 3)
		s.ClientIP = func(*http.Request) netip.Addr { return netip.MustParseAddr("203.0.113.9") }
	})
	var last int
	for i := 0; i < 6; i++ {
		_, resp, _ := e.dial(t, "bad")
		last = resp.StatusCode
	}
	if last != 429 {
		t.Fatalf("got %d", last)
	}
}

func TestRealLinesFlowThroughHelloBatchAck(t *testing.T) {
	e := newEnv(t, nil)
	c, _, err := e.dial(t, e.token())
	if err != nil {
		t.Fatal(err)
	}
	w := hello(t, c, "epoch-1")
	if w.AckSeq != 0 || w.MaxBatchLines != ingestproto.MaxBatchLines {
		t.Fatalf("%+v", w)
	}
	items := sampleItems(t, 1, 120)
	items = append(items, ingestproto.Item{Seq: 121, Line: "this is not an access log line"})
	write(t, c, ingestproto.Batch{Type: "batch", BatchID: "b1", Items: items, SpoolBytes: 1234})
	ack := read[ingestproto.Ack](t, c)
	if ack.Type != "ack" || ack.BatchID != "b1" || ack.AckSeq != 121 || ack.Accepted != 120 || ack.ParseErrors != 1 || ack.Duplicates != 0 {
		t.Fatalf("%+v", ack)
	}
	if n := countRows(t, e.st); n != 120 {
		t.Fatalf("%d rows", n)
	}
	var resolved, unresolved, internal int
	_ = e.st.Pool().QueryRow(ctx, `SELECT count(*) FILTER (WHERE user_id IS NOT NULL), count(*) FILTER (WHERE user_id IS NULL AND NOT internal), count(*) FILTER (WHERE internal) FROM connection_events`).Scan(&resolved, &unresolved, &internal)
	if resolved == 0 || internal == 0 || resolved+unresolved+internal != 120 {
		t.Fatalf("resolved=%d unresolved=%d internal=%d", resolved, unresolved, internal)
	}
	agents, _ := e.st.ListAgents(ctx, store.Scope{All: true}, e.panel.ID)
	if agents[0].Status != "active" || agents[0].LastAckSeq != 121 || agents[0].SpoolBytes != 1234 || agents[0].ParseErrors != 1 {
		t.Fatalf("%+v", agents[0])
	}
}

func TestResentBatchIsAcknowledgedWithoutDoubleCounting(t *testing.T) {
	e := newEnv(t, nil)
	c, _, _ := e.dial(t, e.token())
	hello(t, c, "e")
	b := ingestproto.Batch{Type: "batch", BatchID: "b1", Items: sampleItems(t, 1, 40)}
	write(t, c, b)
	read[ingestproto.Ack](t, c)
	// The connection drops before the agent saw the ack; it reconnects and resends from its spool.
	c.CloseNow()
	c2, _, _ := e.dial(t, e.token())
	w := hello(t, c2, "e")
	if w.AckSeq != 40 {
		t.Fatalf("welcome must tell the agent what was committed: %d", w.AckSeq)
	}
	b.BatchID = "b1-again"
	write(t, c2, b)
	ack := read[ingestproto.Ack](t, c2)
	if ack.Accepted != 0 || ack.Duplicates != 40 || ack.AckSeq != 40 {
		t.Fatalf("%+v", ack)
	}
	if n := countRows(t, e.st); n != 40 {
		t.Fatalf("%d rows", n)
	}
}

func TestSequenceGapClosesTheSessionAndStoresNothing(t *testing.T) {
	e := newEnv(t, nil)
	c, _, _ := e.dial(t, e.token())
	hello(t, c, "e")
	write(t, c, ingestproto.Batch{Type: "batch", BatchID: "b", Items: sampleItems(t, 10, 5)}) // starts at 10, nothing acked
	er := read[ingestproto.Error](t, c)
	if er.Code != "seq_gap" || er.ExpectedSeq != 1 {
		t.Fatalf("%+v", er)
	}
	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, _, err := c.Read(rctx)
	if websocket.CloseStatus(err) != websocket.StatusCode(ingestproto.CloseSeqGap) {
		t.Fatalf("close status %v (%v)", websocket.CloseStatus(err), err)
	}
	if countRows(t, e.st) != 0 {
		t.Fatal("rows stored from a refused batch")
	}
}

func TestMalformedTrafficIsRefused(t *testing.T) {
	long := ingestproto.Item{Seq: 1, Line: strings.Repeat("x", ingestproto.MaxLineBytes+1)}
	tooMany := make([]ingestproto.Item, ingestproto.MaxBatchLines+1)
	for i := range tooMany {
		tooMany[i] = ingestproto.Item{Seq: int64(i + 1), Line: "x"}
	}
	cases := map[string]any{
		"hello missing":      ingestproto.Batch{Type: "batch", BatchID: "b", Items: sampleItems(t, 1, 1)},
		"unknown type":       map[string]string{"type": "explode"},
		"empty batch":        ingestproto.Batch{Type: "batch", BatchID: "b"},
		"no batch id":        ingestproto.Batch{Type: "batch", Items: sampleItems(t, 1, 1)},
		"too many lines":     ingestproto.Batch{Type: "batch", BatchID: "b", Items: tooMany},
		"line too long":      ingestproto.Batch{Type: "batch", BatchID: "b", Items: []ingestproto.Item{long}},
		"non-contiguous":     ingestproto.Batch{Type: "batch", BatchID: "b", Items: []ingestproto.Item{{Seq: 1, Line: "x"}, {Seq: 3, Line: "x"}}},
		"zero sequence":      ingestproto.Batch{Type: "batch", BatchID: "b", Items: []ingestproto.Item{{Seq: 0, Line: "x"}}},
		"negative spool":     ingestproto.Batch{Type: "batch", BatchID: "b", Items: sampleItems(t, 1, 1), SpoolBytes: -1},
		"hostile gap reason": ingestproto.Batch{Type: "batch", BatchID: "b", Items: sampleItems(t, 1, 1), Gaps: []ingestproto.Gap{{Reason: "'; drop table"}}},
		"not json":           "plain text",
	}
	for name, msg := range cases {
		e := newEnv(t, nil)
		c, _, _ := e.dial(t, e.token())
		if name != "hello missing" {
			hello(t, c, "e")
		}
		var b []byte
		if s, ok := msg.(string); ok {
			b = []byte(s)
		} else {
			b, _ = json.Marshal(msg)
		}
		if err := c.Write(ctx, websocket.MessageText, b); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		var closed bool
		for i := 0; i < 3 && !closed; i++ {
			_, _, err := c.Read(rctx)
			closed = err != nil
		}
		cancel()
		if !closed {
			t.Errorf("%s: the session must be closed", name)
		}
		if countRows(t, e.st) != 0 {
			t.Errorf("%s: rows were stored", name)
		}
	}
}

func TestOversizedMessageIsRefused(t *testing.T) {
	e := newEnv(t, nil)
	c, _, _ := e.dial(t, e.token())
	hello(t, c, "e")
	big := make([]byte, ingestproto.MaxMessageBytes+10)
	for i := range big {
		big[i] = 'a'
	}
	_ = c.Write(ctx, websocket.MessageText, big)
	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, _, err := c.Read(rctx); err == nil {
		t.Fatal("an oversized frame must end the session")
	}
}

func TestRevokingTheAgentEndsItsSession(t *testing.T) {
	e := newEnv(t, nil)
	c, _, _ := e.dial(t, e.token())
	hello(t, c, "e")
	if err := e.st.RevokeAgent(ctx, store.Scope{All: true}, e.panel.ID, e.agent.ID); err != nil {
		t.Fatal(err)
	}
	write(t, c, ingestproto.Batch{Type: "batch", BatchID: "b", Items: sampleItems(t, 1, 3)})
	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, _, err := c.Read(rctx)
	if websocket.CloseStatus(err) != websocket.StatusCode(ingestproto.CloseRevoked) {
		t.Fatalf("%v", err)
	}
	if countRows(t, e.st) != 0 {
		t.Fatal("a revoked agent stored data")
	}
}

func TestPingKeepsTheAgentAliveAndRecordsItsSpool(t *testing.T) {
	e := newEnv(t, func(s *Server) { s.IdleTimeout = 400 * time.Millisecond })
	c, _, _ := e.dial(t, e.token())
	hello(t, c, "e")
	for i := 0; i < 4; i++ {
		time.Sleep(200 * time.Millisecond)
		write(t, c, ingestproto.Ping{Type: "ping", SpoolBytes: int64(100 * (i + 1))})
		if p := read[ingestproto.Pong](t, c); p.Type != "pong" {
			t.Fatalf("%+v", p)
		}
	}
	a, _ := e.st.ListAgents(ctx, store.Scope{All: true}, e.panel.ID)
	if a[0].SpoolBytes != 400 {
		t.Fatalf("%d", a[0].SpoolBytes)
	}
	// Silence past the idle limit ends the session.
	time.Sleep(700 * time.Millisecond)
	write(t, c, ingestproto.Ping{Type: "ping"})
	rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, _, err := c.Read(rctx); err == nil {
		t.Fatal("an idle session must be closed")
	}
}

func TestLongSessionsSurviveTheHTTPServersWriteTimeout(t *testing.T) {
	st := storetest.New(t)
	p, _ := st.CreatePanel(ctx, store.NewPanelID(), store.PanelInput{Name: "p", BaseURL: "https://p.example.com"}, nil)
	_, _ = st.UpsertNodes(ctx, p.ID, time.Now().UTC(), []store.NodeRecord{{RemoteUUID: "n", Name: "n"}})
	nodes, _ := st.ListNodes(ctx, store.Scope{All: true}, p.ID, false)
	a, _ := st.CreateAgent(ctx, store.Scope{All: true}, p.ID, nodes[0].ID, "a", "node", "", store.HashAgentSecret(secret))
	srv := httptest.NewUnstartedServer((&Server{Store: st}).Handler())
	srv.Config.ReadTimeout, srv.Config.WriteTimeout = time.Second, time.Second // the production server has such limits
	srv.Start()
	defer srv.Close()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + a.ID + "." + secret}}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	hello(t, c, "e")
	time.Sleep(2500 * time.Millisecond)
	write(t, c, ingestproto.Batch{Type: "batch", BatchID: "late", Items: sampleItems(t, 1, 5)})
	if ack := read[ingestproto.Ack](t, c); ack.Accepted != 5 {
		t.Fatalf("a session older than the HTTP write timeout must keep working: %+v", ack)
	}
}

// A router agent sends router records, not Xray lines: records are stored as devices, anything
// else counts as a parse error, and a node agent's Xray lines never become device rows.
func TestRouterAgentBatch(t *testing.T) {
	e := newEnv(t, nil)
	nodes, _ := e.st.ListNodes(ctx, store.Scope{All: true}, e.panel.ID, false)
	ra, err := e.st.CreateAgent(ctx, store.Scope{All: true}, e.panel.ID, nodes[0].ID, "router", "router", "", store.HashAgentSecret(secret))
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := e.dial(t, ra.ID+"."+secret)
	if err != nil {
		t.Fatal(err)
	}
	hello(t, c, "ep1")
	now := time.Now().UTC()
	good := fmt.Sprintf(`{"v":1,"id":"c1","t":%q,"u":%q,"src":"192.168.1.176","h":"api.example.com","di":"1.2.3.4","dp":443,"p":"tcp","up":5,"dn":9}`,
		now.Add(-time.Minute).Format(time.RFC3339), now.Format(time.RFC3339))
	bad := `{"v":1,"id":"c2","t":"x"}`
	xrayLine := sampleItems(t, 1, 1)[0].Line
	write(t, c, ingestproto.Batch{Type: "batch", BatchID: "b1", Items: []ingestproto.Item{{Seq: 1, Line: good}, {Seq: 2, Line: bad}, {Seq: 3, Line: xrayLine}}})
	ack := read[ingestproto.Ack](t, c)
	if ack.Accepted != 1 || ack.ParseErrors != 2 || ack.AckSeq != 3 {
		t.Fatalf("ack: %+v", ack)
	}
	q := store.AnalyticsQuery{PanelIDs: []string{e.panel.ID}, From: now.Add(-time.Hour), To: now.Add(time.Hour)}
	rows, err := e.st.DevicesAnalytics(ctx, q)
	if err != nil || len(rows) != 1 || rows[0].Up != 5 || rows[0].Down != 9 {
		t.Fatalf("devices: %+v %v", rows, err)
	}
	// Router records never reach the node event counts.
	if ev, _ := e.st.EventsOverview(ctx, store.EventsQuery{PanelIDs: []string{e.panel.ID}, From: now.Add(-time.Hour), To: now.Add(time.Hour)}); ev.TCP+ev.UDP != 0 {
		t.Fatalf("router data leaked into node events: %+v", ev)
	}
}
