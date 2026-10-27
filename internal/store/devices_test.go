package store_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/routerlog"
	"github.com/Taminum/Owlery/internal/store"
	"github.com/Taminum/Owlery/internal/store/storetest"
)

func devEvt(id, dev, host, ip string, up, down int64, min int) *routerlog.Event {
	start := time.Date(2026, 10, 9, 12, min, 0, 0, time.UTC)
	e := &routerlog.Event{ID: id, Start: start, Seen: start.Add(30 * time.Second), Device: netip.MustParseAddr(dev), Host: host, Port: 443, Protocol: "tcp", Up: up, Down: down}
	if ip != "" {
		e.DestIP = netip.MustParseAddr(ip)
	}
	return e
}

func TestDeviceCommitAnalyticsAndIsolation(t *testing.T) {
	s := storetest.New(t)
	home, work := mkPanel(t, s, "home"), mkPanel(t, s, "work")
	now := time.Now().UTC()
	_, _ = s.UpsertNodes(ctx, home.ID, now, []store.NodeRecord{{RemoteUUID: "h1", Name: "home-a"}})
	_, _ = s.UpsertNodes(ctx, work.ID, now, []store.NodeRecord{{RemoteUUID: "w1", Name: "work-1"}})
	hn, _ := s.ListNodes(ctx, store.Scope{All: true}, home.ID, false)
	wn, _ := s.ListNodes(ctx, store.Scope{All: true}, work.ID, false)

	mk := func(p store.Panel, n store.Node, kind string) store.Agent {
		a, err := s.CreateAgent(ctx, store.Scope{All: true}, p.ID, n.ID, "r-"+p.ID[:4], kind, "", store.HashAgentSecret(p.ID))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = s.AgentHello(ctx, a.ID, "e", "v", "s")
		return a
	}
	// A router agent does not take the node's one agent slot.
	nodeAgent, routerAgent := mk(home, hn[0], "node"), mk(home, hn[0], "router")
	if routerAgent.Kind != "router" || nodeAgent.Kind != "node" {
		t.Fatalf("kinds: %q %q", nodeAgent.Kind, routerAgent.Kind)
	}
	workRouter := mk(work, wn[0], "router")

	// A router agent attached to a node must not make that node appear twice, or look like it has
	// a second agent.
	seen, err := s.NodesInScope(ctx, []string{home.ID}, nil)
	if err != nil || len(seen) != 1 || !seen[0].HasAgent {
		t.Fatalf("NodesInScope with a router agent: %+v %v", seen, err)
	}

	ln := func(seq int64, e *routerlog.Event) store.Line {
		return store.Line{Seq: seq, Device: e, FP: []byte{byte(seq)}}
	}
	commit := func(a store.Agent, lines ...store.Line) store.CommitResult {
		t.Helper()
		r, err := s.CommitBatch(ctx, store.Commit{AgentID: a.ID, Lines: lines})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	d1 := devEvt("c1", "192.168.1.176", "www.google.com", "1.1.1.1", 100, 1000, 1)
	d1.DeviceName = "Home"
	commit(routerAgent,
		ln(1, d1),
		ln(2, devEvt("c2", "192.168.1.176", "", "9.9.9.9", 5, 5, 2)), // no sniffed domain: stays an IP
		ln(3, devEvt("c3", "192.168.1.202", "api.telegram.org", "2.2.2.2", 10, 20, 3)),
	)
	commit(workRouter, ln(1, devEvt("w1", "192.168.1.9", "secret.work.example.test", "3.3.3.3", 1, 1, 1)))

	// The same connection reported again later with larger counters, then a stale smaller report:
	// the counters only go forward and the connection is not counted twice.
	up := devEvt("c1", "192.168.1.176", "www.google.com", "1.1.1.1", 150, 4000, 1)
	up.Seen = up.Start.Add(2 * time.Minute)
	commit(routerAgent, ln(4, up))
	stale := devEvt("c1", "192.168.1.176", "www.google.com", "1.1.1.1", 1, 1, 1)
	commit(routerAgent, ln(5, stale))

	q := store.AnalyticsQuery{PanelIDs: []string{home.ID}, From: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), Granularity: time.Hour}
	rows, err := s.DevicesAnalytics(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("home must see only its two devices, got %+v", rows)
	}
	h := rows[0] // most bytes first
	if h.IP.String() != "192.168.1.176" || h.Name != "Home" || h.Connections != 2 || h.Up != 155 || h.Down != 4005 || h.NoDomain != 1 || h.Destinations != 2 {
		t.Fatalf("home device: %+v", h)
	}
	if rows[1].IP.String() != "192.168.1.202" || rows[1].Connections != 1 {
		t.Fatalf("second device: %+v", rows[1])
	}

	det, err := s.DeviceDetailFor(ctx, q, home.ID, netip.MustParseAddr("192.168.1.176"))
	if err != nil {
		t.Fatal(err)
	}
	if det.Connections != 2 || len(det.Hosts) != 2 || det.Hosts[0].Key != "www.google.com" || det.Hosts[0].Service != "Google" {
		t.Fatalf("detail: %+v", det)
	}
	for _, h := range det.Hosts {
		if h.Key == "9.9.9.9" && h.Service != "" {
			t.Fatalf("an IP must not get a service: %+v", h)
		}
	}
	if len(det.Timeline) == 0 {
		t.Fatal("timeline empty")
	}

	// The other panel's device is not reachable through this panel's scope.
	other, err := s.DeviceDetailFor(ctx, q, home.ID, netip.MustParseAddr("192.168.1.9"))
	if err != nil || other.Connections != 0 {
		t.Fatalf("leak across panels: %+v err=%v", other, err)
	}
	wq := q
	wq.PanelIDs = []string{work.ID}
	if r, _ := s.DevicesAnalytics(ctx, wq); len(r) != 1 || r[0].IP.String() != "192.168.1.9" {
		t.Fatalf("work: %+v", r)
	}

	ok, err := s.HasRouterAgent(ctx, []string{home.ID})
	if err != nil || !ok {
		t.Fatalf("HasRouterAgent: %v %v", ok, err)
	}
	if err := s.RevokeAgent(ctx, store.Scope{All: true}, home.ID, routerAgent.ID); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.HasRouterAgent(ctx, []string{home.ID}); ok {
		t.Fatal("revoked router agent still counted")
	}
}

func TestDevicePurgeFollowsRetention(t *testing.T) {
	s := storetest.New(t)
	p := mkPanel(t, s, "home")
	now := time.Now().UTC()
	_, _ = s.UpsertNodes(ctx, p.ID, now, []store.NodeRecord{{RemoteUUID: "h1", Name: "n"}})
	n, _ := s.ListNodes(ctx, store.Scope{All: true}, p.ID, false)
	a, err := s.CreateAgent(ctx, store.Scope{All: true}, p.ID, n[0].ID, "r", "router", "", store.HashAgentSecret("x"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.AgentHello(ctx, a.ID, "e", "v", "s")
	old := &routerlog.Event{ID: "o", Start: now.AddDate(0, 0, -400), Seen: now.AddDate(0, 0, -400), Device: netip.MustParseAddr("192.168.1.2"), Host: "a.test", Port: 1, Protocol: "tcp"}
	cur := &routerlog.Event{ID: "n", Start: now.Add(-time.Hour), Seen: now.Add(-time.Hour), Device: netip.MustParseAddr("192.168.1.2"), Host: "a.test", Port: 1, Protocol: "tcp"}
	if _, err := s.CommitBatch(ctx, store.Commit{AgentID: a.ID, Lines: []store.Line{{Seq: 1, Device: old, FP: []byte{1}}, {Seq: 2, Device: cur, FP: []byte{2}}}}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.PurgeExpiredDevices(ctx, now); err != nil || got != 1 {
		t.Fatalf("purged %d err %v", got, err)
	}
}

// Behind a router the exit nodes see one user and bare IPs. With covers_user set, the domain
// view takes that traffic from the router (domain, bytes) and drops the nodes' copy of it, so it is
// counted once; other users' node events are untouched, and node filters leave the router out.
func TestDestinationsMixRouterAndNodes(t *testing.T) {
	e := newAnalyticsEnv(t)
	router, err := e.s.CreateAgent(ctx, store.Scope{All: true}, e.home.ID, e.homeNodes[0].ID, "OpenWrt", "router", "4", store.HashAgentSecret("rt"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = e.s.AgentHello(ctx, router.ID, "e", "v", "s")
	e.q.GroupBy = "host"

	before, _, totalBefore, _ := e.s.Destinations(ctx, e.q)
	if totalBefore != 10 {
		t.Fatalf("baseline %d", totalBefore)
	}
	_ = before

	r1 := devEvt("a", "192.168.1.176", "www.pixiv.net", "1.2.3.4", 100, 900, 1)
	r2 := devEvt("b", "192.168.1.176", "www.google.com", "1.1.1.1", 10, 90, 2)
	if _, err := e.s.CommitBatch(ctx, store.Commit{AgentID: router.ID, Lines: []store.Line{{Seq: 1, Device: r1, FP: []byte{1}}, {Seq: 2, Device: r2, FP: []byte{2}}}}); err != nil {
		t.Fatal(err)
	}
	rows, _, total, err := e.s.Destinations(ctx, e.q)
	if err != nil {
		t.Fatal(err)
	}
	m := byKey(rows)
	if m["www.pixiv.net"].RouterConns != 1 || m["www.pixiv.net"].Bytes != 1000 {
		t.Fatalf("router domain missing or without bytes: %+v", m["www.pixiv.net"])
	}
	// The google line from the router adds to the nodes' google lines (user 2, not covered).
	if g := m["www.google.com"]; g.Connections != 3 || g.RouterConns != 1 || g.Bytes != 100 {
		t.Fatalf("google: %+v", g)
	}
	// User 4's node events are gone (they started before the router's first record, so only
	// events at or after it are dropped): check by counting what is left of user 4 after `since`.
	if total < totalBefore-8 || total > totalBefore+2 {
		t.Fatalf("total %d (before %d)", total, totalBefore)
	}
	// A node filter means "only these nodes": the router belongs to none.
	nq := e.q
	nq.NodeIDs = []string{e.homeNodes[0].ID}
	nrows, _, _, _ := e.s.Destinations(ctx, nq)
	for _, r := range nrows {
		if r.RouterConns != 0 {
			t.Fatalf("router rows leaked into a node-filtered view: %+v", r)
		}
	}
}

// A batch may carry several records of one connection (opened, refreshed, closed). They must be
// stored as one row with the largest counters, not rejected as a whole.
func TestABatchWithTheSameConnectionTwiceIsStoredOnce(t *testing.T) {
	s := storetest.New(t)
	p := mkPanel(t, s, "home")
	now := time.Now().UTC()
	_, _ = s.UpsertNodes(ctx, p.ID, now, []store.NodeRecord{{RemoteUUID: "h1", Name: "n"}})
	n, _ := s.ListNodes(ctx, store.Scope{All: true}, p.ID, false)
	a, err := s.CreateAgent(ctx, store.Scope{All: true}, p.ID, n[0].ID, "r", "router", "", store.HashAgentSecret("x"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.AgentHello(ctx, a.ID, "e", "v", "s")
	opened := devEvt("c1", "192.168.1.5", "", "1.2.3.4", 10, 20, 1)
	refreshed := devEvt("c1", "192.168.1.5", "www.pixiv.net", "1.2.3.4", 500, 900, 1)
	refreshed.Seen = refreshed.Start.Add(45 * time.Second)
	closed := devEvt("c1", "192.168.1.5", "", "1.2.3.4", 400, 1200, 1) // a stale-looking up counter, a larger down counter
	closed.Seen = closed.Start.Add(30 * time.Second)
	other := devEvt("c2", "192.168.1.6", "a.test", "5.6.7.8", 1, 1, 2)
	res, err := s.CommitBatch(ctx, store.Commit{AgentID: a.ID, Lines: []store.Line{
		{Seq: 1, Device: opened, FP: []byte{1}}, {Seq: 2, Device: refreshed, FP: []byte{2}}, {Seq: 3, Device: closed, FP: []byte{3}}, {Seq: 4, Device: other, FP: []byte{4}},
	}})
	if err != nil {
		t.Fatalf("the batch must not be refused: %v", err)
	}
	if res.AckSeq != 4 {
		t.Fatalf("all four lines are acknowledged: %+v", res)
	}
	var cnt int
	var up, down int64
	var host *string
	var seen time.Time
	if err := s.Pool().QueryRow(ctx, `SELECT count(*), max(up_bytes), max(down_bytes), max(destination_host), max(updated_at) FROM device_connections WHERE conn_key='c1'`).Scan(&cnt, &up, &down, &host, &seen); err != nil {
		t.Fatal(err)
	}
	if cnt != 1 || up != 500 || down != 1200 || host == nil || *host != "www.pixiv.net" || !seen.Equal(refreshed.Seen) {
		t.Fatalf("merged row: n=%d up=%d down=%d host=%v seen=%v", cnt, up, down, host, seen)
	}
}
