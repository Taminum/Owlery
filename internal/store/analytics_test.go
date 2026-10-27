package store_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/store"
	"github.com/Taminum/Owlery/internal/store/storetest"
	"github.com/Taminum/Owlery/internal/xraylog"
)

type aEnv struct {
	s          *store.Store
	home, work store.Panel
	homeAgent  store.Agent
	workAgent  store.Agent
	homeNodes  []store.Node
	q          store.AnalyticsQuery
	seq        map[string]int64
}

func evt(host, ip string, port int, proto, email string, internal bool, sec int) *xraylog.Event {
	e := &xraylog.Event{Time: time.Date(2026, 10, 9, 12, 0, sec, 0, time.UTC), ClientIP: netip.MustParseAddr("198.51.100.7"), Protocol: proto,
		DestHost: host, DestPort: port, InboundTag: "Steal", OutboundTag: "DIRECT", Arrow: "->", Email: email, Internal: internal}
	if ip != "" {
		e.DestIP = netip.MustParseAddr(ip)
	}
	return e
}

func (a *aEnv) push(t *testing.T, ag store.Agent, evs ...*xraylog.Event) {
	t.Helper()
	var lines []store.Line
	for _, e := range evs {
		a.seq[ag.ID]++
		lines = append(lines, line(a.seq[ag.ID], e))
	}
	if _, err := a.s.CommitBatch(ctx, store.Commit{AgentID: ag.ID, Lines: lines}); err != nil {
		t.Fatal(err)
	}
}

func newAnalyticsEnv(t *testing.T) *aEnv {
	t.Helper()
	s := storetest.New(t)
	home, work := mkPanel(t, s, "home"), mkPanel(t, s, "work")
	now := time.Now().UTC()
	_, _ = s.UpsertNodes(ctx, home.ID, now, []store.NodeRecord{{RemoteUUID: "h1", Name: "home-a"}, {RemoteUUID: "h2", Name: "home-b"}})
	_, _ = s.UpsertNodes(ctx, work.ID, now, []store.NodeRecord{{RemoteUUID: "w1", Name: "work-1"}})
	_, _ = s.UpsertUsers(ctx, home.ID, now, []store.UserRecord{{RemoteUUID: "2", Username: "alice"}, {RemoteUUID: "4", Username: "router"}})
	_, _ = s.UpsertUsers(ctx, work.ID, now, []store.UserRecord{{RemoteUUID: "2", Username: "carol"}})
	hn, _ := s.ListNodes(ctx, store.Scope{All: true}, home.ID, false)
	wn, _ := s.ListNodes(ctx, store.Scope{All: true}, work.ID, false)
	mk := func(p store.Panel, n store.Node) store.Agent {
		a, err := s.CreateAgent(ctx, store.Scope{All: true}, p.ID, n.ID, n.Name, "node", "", store.HashAgentSecret(n.Name))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = s.AgentHello(ctx, a.ID, "e", "v", "s")
		return a
	}
	e := &aEnv{s: s, home: home, work: work, homeNodes: hn, seq: map[string]int64{}}
	e.homeAgent, e.workAgent = mk(home, hn[0]), mk(work, wn[0])
	e.q = store.AnalyticsQuery{PanelIDs: []string{home.ID}, From: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), Granularity: time.Hour}

	e.push(t, e.homeAgent,
		evt("www.google.com", "", 443, "tcp", "2", false, 1),
		evt("www.google.com", "", 443, "tcp", "2", false, 2),
		evt("fonts.gstatic.com", "", 443, "tcp", "2", false, 3),
		evt("i.ytimg.com", "", 443, "tcp", "4", false, 4),
		evt("api.telegram.org", "", 443, "tcp", "4", false, 5),
		evt("notgoogle.com", "", 443, "tcp", "4", false, 6),           // must NOT match the google.com rule
		evt("google.com.evil.example", "", 443, "tcp", "4", false, 7), // nor this
		evt("", "9.9.9.9", 53, "udp", "4", false, 8),                  // an IP stays an IP
		evt("", "1.1.1.1", 53, "udp", "", true, 9),                    // the node's own DNS lookup
		evt("rare.example.test", "", 8443, "tcp", "99", false, 10),    // unresolved raw id
	)
	e.push(t, e.workAgent, evt("secret.work.example.test", "", 443, "tcp", "2", false, 1), evt("www.google.com", "", 443, "tcp", "2", false, 2))
	return e
}

func byKey(rows []store.DestRow) map[string]store.DestRow {
	m := map[string]store.DestRow{}
	for _, r := range rows {
		m[r.Key] = r
	}
	return m
}

func TestDestinationsByHostClassifyByDomainOnly(t *testing.T) {
	e := newAnalyticsEnv(t)
	e.q.GroupBy = "host"
	rows, groups, total, err := e.s.Destinations(ctx, e.q)
	if err != nil {
		t.Fatal(err)
	}
	m := byKey(rows)
	if total != 10 || groups != len(rows) {
		t.Fatalf("total %d groups %d rows %d", total, groups, len(rows))
	}
	if g := m["www.google.com"]; g.Connections != 2 || g.Kind != "domain" || g.Service != "Google" || g.Confidence != "high" || g.Users != 1 {
		t.Fatalf("%+v", g)
	}
	if m["fonts.gstatic.com"].Service != "Google" || m["i.ytimg.com"].Service != "YouTube" || m["api.telegram.org"].Service != "Telegram" {
		t.Fatalf("subdomains must follow their parent domain: %+v", m)
	}
	for _, k := range []string{"notgoogle.com", "google.com.evil.example", "rare.example.test"} {
		if m[k].Service != "" {
			t.Errorf("%s must not be classified, got %q", k, m[k].Service)
		}
	}
	if ip := m["9.9.9.9"]; ip.Kind != "ip" || ip.Service != "" || ip.Connections != 1 {
		t.Fatalf("an IP is never mapped to a service: %+v", ip)
	}
	if rows[0].Key != "www.google.com" {
		t.Fatalf("most connections first: %v", rows[0].Key)
	}
}

func TestDestinationsByServiceAndByIP(t *testing.T) {
	e := newAnalyticsEnv(t)
	e.q.GroupBy = "service"
	rows, _, total, err := e.s.Destinations(ctx, e.q)
	if err != nil || total != 10 {
		t.Fatalf("%v total=%d", err, total)
	}
	m := byKey(rows)
	if g := m["Google"]; g.Connections != 3 || g.Kind != "service" || g.Users != 1 {
		t.Fatalf("google.com x2 + gstatic: %+v", g)
	}
	if m["Не определён"].Connections != 3 || m["IP без домена"].Connections != 2 {
		t.Fatalf("%+v", m)
	}
	e.q.GroupBy = "ip"
	rows, _, _, _ = e.s.Destinations(ctx, e.q)
	if len(rows) != 2 || rows[0].Key != "1.1.1.1" || rows[1].Key != "9.9.9.9" || rows[0].Kind != "ip" {
		t.Fatalf("%+v", rows)
	}
}

func TestDestinationSearchIsLiteralAndSafe(t *testing.T) {
	e := newAnalyticsEnv(t)
	e.q.GroupBy = "host"
	e.q.Search = "gstatic"
	rows, groups, _, _ := e.s.Destinations(ctx, e.q)
	if len(rows) != 1 || groups != 1 || rows[0].Key != "fonts.gstatic.com" {
		t.Fatalf("%+v", rows)
	}
	for _, evil := range []string{"%", "_", "'; DROP TABLE connection_events; --", `\`, "%' OR '1'='1", "x_y"} {
		e.q.Search = evil
		rows, _, _, err := e.s.Destinations(ctx, e.q)
		if err != nil {
			t.Fatalf("%q must be harmless: %v", evil, err)
		}
		if len(rows) != 0 {
			t.Errorf("%q matched %d rows: wildcards must be literal", evil, len(rows))
		}
	}
	var n int
	_ = e.s.Pool().QueryRow(ctx, `SELECT count(*) FROM connection_events`).Scan(&n)
	if n != 12 {
		t.Fatalf("the table is intact: %d", n)
	}
}

func TestDestinationsPaginateAndNeverCrossPanels(t *testing.T) {
	e := newAnalyticsEnv(t)
	e.q.GroupBy = "host"
	e.q.Limit = 3
	p1, groups, total, _ := e.s.Destinations(ctx, e.q)
	e.q.Offset = 3
	p2, _, _, _ := e.s.Destinations(ctx, e.q)
	if len(p1) != 3 || len(p2) != 3 || groups != 9 || total != 10 || p1[0].Key == p2[0].Key {
		t.Fatalf("pages %d/%d groups %d total %d", len(p1), len(p2), groups, total)
	}
	e.q.Limit, e.q.Offset = 50, 0
	rows, _, _, _ := e.s.Destinations(ctx, e.q)
	for _, r := range rows {
		if r.Key == "secret.work.example.test" {
			t.Fatal("Work's destination leaked into Home's analyzer")
		}
	}
	e.q.PanelIDs = []string{e.work.ID}
	rows, _, total, _ = e.s.Destinations(ctx, e.q)
	if total != 2 || len(rows) != 2 {
		t.Fatalf("work sees its own two lines: %d", total)
	}
	e.q.PanelIDs = nil
	if rows, _, total, _ = e.s.Destinations(ctx, e.q); total != 0 || len(rows) != 0 {
		t.Fatal("no panels in scope means no data")
	}
}

func TestNodeFilterNarrowsTheAnalyzer(t *testing.T) {
	e := newAnalyticsEnv(t)
	e.q.GroupBy = "host"
	e.q.NodeIDs = []string{e.homeNodes[1].ID} // home-b has no agent and no events
	if _, _, total, _ := e.s.Destinations(ctx, e.q); total != 0 {
		t.Fatalf("%d", total)
	}
	e.q.NodeIDs = []string{e.homeNodes[0].ID}
	if _, _, total, _ := e.s.Destinations(ctx, e.q); total != 10 {
		t.Fatalf("%d", total)
	}
}

func TestUsersAreResolvedOnlyThroughTheirOwnPanel(t *testing.T) {
	e := newAnalyticsEnv(t)
	rows, total, err := e.s.UsersAnalytics(ctx, e.q)
	if err != nil || total != 10 {
		t.Fatalf("%v %d", err, total)
	}
	by := map[string]store.UserRow{}
	for _, r := range rows {
		k := r.Name
		switch {
		case r.Internal:
			k = "system"
		case r.UserID == "":
			k = "raw:" + r.Email
		}
		by[k] = r
	}
	if by["alice"].Connections != 3 || by["router"].Connections != 5 || by["system"].Connections != 1 || by["raw:99"].Connections != 1 {
		t.Fatalf("%+v", by)
	}
	if by["router"].UDP != 1 || by["router"].Destinations != 5 {
		t.Fatalf("%+v", by["router"])
	}
	for _, r := range rows {
		if r.Name == "carol" || r.PanelID != e.home.ID {
			t.Fatalf("Work's user leaked into Home: %+v", r)
		}
	}
	if rows[0].Name != "router" {
		t.Fatalf("busiest first: %s", rows[0].Name)
	}
}

func TestUserDetailForAUserAnUnresolvedIdAndSystemTraffic(t *testing.T) {
	e := newAnalyticsEnv(t)
	rows, _, _ := e.s.UsersAnalytics(ctx, e.q)
	var aliceID string
	for _, r := range rows {
		if r.Name == "alice" {
			aliceID = r.UserID
		}
	}
	d, err := e.s.UserDetail(ctx, e.q, store.UserKey{PanelID: e.home.ID, UserID: aliceID})
	if err != nil || d.Total != 3 || d.TCP != 3 || len(d.Hosts) != 2 || d.Hosts[0].Key != "www.google.com" || d.Hosts[0].Service != "Google" || d.Hosts[0].Count != 2 {
		t.Fatalf("%+v %v", d, err)
	}
	if len(d.Buckets) != 1 || d.Buckets[0].TCP != 3 || len(d.Nodes) != 1 || d.Nodes[0].Key != "home-a" || d.Ports[0].Key != "443" {
		t.Fatalf("%+v", d)
	}
	raw, _ := e.s.UserDetail(ctx, e.q, store.UserKey{PanelID: e.home.ID, Email: "99"})
	if raw.Total != 1 || raw.Hosts[0].Key != "rare.example.test" {
		t.Fatalf("%+v", raw)
	}
	sys, _ := e.s.UserDetail(ctx, e.q, store.UserKey{PanelID: e.home.ID, Internal: true})
	if sys.Total != 1 || sys.UDP != 1 {
		t.Fatalf("%+v", sys)
	}
	// The same raw id in the other panel is a different person.
	carolRaw, _ := e.s.UserDetail(ctx, e.q, store.UserKey{PanelID: e.work.ID, Email: "2"})
	if carolRaw.Total != 0 {
		t.Fatalf("a key is only ever interpreted inside its own panel, and 2 is a resolved user in Work: %+v", carolRaw)
	}
	if _, err := e.s.UserDetail(ctx, e.q, store.UserKey{PanelID: "nope"}); err == nil {
		t.Fatal("a bad panel id must be refused")
	}
}

func TestNodesAnalyticsShowsQuietAndAgentlessNodes(t *testing.T) {
	e := newAnalyticsEnv(t)
	rows, err := e.s.NodesAnalytics(ctx, e.q)
	if err != nil || len(rows) != 2 {
		t.Fatalf("%v %d", err, len(rows))
	}
	var a, b store.NodeAnalytics
	for _, r := range rows {
		if r.NodeName == "home-a" {
			a = r
		} else {
			b = r
		}
	}
	if a.Connections != 10 || !a.HasAgent || a.Users != 4 || a.UDP != 2 || a.LastEvent == nil {
		t.Fatalf("%+v", a)
	}
	if b.Connections != 0 || b.HasAgent || b.LastEvent != nil {
		t.Fatalf("a node with no agent must show up, empty, not vanish: %+v", b)
	}
}

func TestServiceRulesAreSeededAndVersioned(t *testing.T) {
	e := newAnalyticsEnv(t)
	var n, versions int
	_ = e.s.Pool().QueryRow(ctx, `SELECT count(*), count(DISTINCT rule_version) FROM service_rules WHERE enabled`).Scan(&n, &versions)
	if n < 100 || versions != 1 {
		t.Fatalf("%d rules in %d versions", n, versions)
	}
}
