package store_test

import (
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

// The half-hour sums must tell the overview exactly what the events tell it: same totals, same timeline, same tops,
// same users. A line that arrives late is counted once its half-hour is recounted, and a node filter narrows both alike.
func TestTheOverviewFromHalfHourSumsEqualsTheOneFromEvents(t *testing.T) {
	e := newAnalyticsEnv(t)
	const hour = 3600
	e.push(t, e.homeAgent,
		evt("a.example.org", "", 443, "tcp", "2", false, 0), // evt counts seconds from 2026-10-09 12:00 UTC
		evt("a.example.org", "", 443, "tcp", "2", false, 40*60),
		evt("a.example.org", "", 443, "udp", "99", false, 3*hour), // a user the panel does not know
		evt("b.example.org", "", 80, "tcp", "2", false, 3*hour+5),
		evt("", "203.0.113.9", 53, "udp", "", true, 5*hour), // the node's own traffic, by address only
		evt("c.example.org", "198.51.100.20", 443, "tcp", "2", false, 20*hour),
	)
	e.push(t, e.workAgent, evt("a.example.org", "", 443, "tcp", "2", false, 7*hour))

	now := time.Date(2026, 10, 10, 12, 10, 0, 0, time.UTC)
	fill := func() {
		t.Helper()
		for i := 0; ; i++ {
			more, err := e.s.RollupTick(ctx, now)
			if err != nil {
				t.Fatal(err)
			}
			if !more {
				return
			}
			if i > 200 {
				t.Fatal("the filling never ends")
			}
		}
	}
	fill()

	q := store.EventsQuery{PanelIDs: []string{e.home.ID, e.work.ID}, From: time.Date(2026, 10, 9, 0, 10, 0, 0, time.UTC), To: now, Granularity: 30 * time.Minute, Top: 5}
	same := func(what string, q store.EventsQuery) store.EventsOverview {
		t.Helper()
		exact := q
		exact.Exact = true
		// a window answered from the sums starts on the half-hour, so the events are asked for the same one
		exact.From = q.From.Truncate(store.RollupStep)
		raw, err := e.s.EventsOverview(ctx, exact)
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.s.EventsOverview(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		byKey := func(r []store.CountRow) []store.CountRow {
			out := append([]store.CountRow(nil), r...)
			sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
			return out
		}
		for name, pair := range map[string][2]any{
			"tcp": {raw.TCP, got.TCP}, "udp": {raw.UDP, got.UDP}, "hosts seen": {raw.UniqueHosts, got.UniqueHosts}, "addresses seen": {raw.UniqueIPs, got.UniqueIPs},
			"nodes": {raw.NodesWithEvents, got.NodesWithEvents}, "timeline": {raw.Buckets, got.Buckets}, "top hosts": {raw.Hosts, got.Hosts}, "top addresses": {raw.IPs, got.IPs},
			"top ports": {raw.Ports, got.Ports}, "users": {byKey(raw.Users), byKey(got.Users)}, "recent": {raw.Recent, got.Recent},
		} {
			if !reflect.DeepEqual(pair[0], pair[1]) {
				t.Fatalf("%s, %s: the events say %+v, the sums say %+v", what, name, pair[0], pair[1])
			}
		}
		return got
	}
	all := same("both panels", q)
	if all.TCP+all.UDP < 7 || all.UniqueHosts < 3 || len(all.Users) < 3 {
		t.Fatalf("the window holds less than was put in: %+v", all)
	}

	one := q
	one.PanelIDs, one.NodeIDs = []string{e.home.ID}, []string{e.homeNodes[0].ID}
	same("one node", one)

	// a line that an agent kept while it was cut off: the sums do not have it until its half-hour is recounted
	e.push(t, e.homeAgent, evt("late.example.org", "", 443, "tcp", "2", false, -6*hour))
	stale, err := e.s.EventsOverview(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if stale.TCP != all.TCP {
		t.Fatalf("the late line was counted before its half-hour was recounted: %d, was %d", stale.TCP, all.TCP)
	}
	fill()
	if after := same("after the late line", q); after.TCP != all.TCP+1 {
		t.Fatalf("the late line is still missing: %d, was %d", after.TCP, all.TCP)
	}

	// a window the sums do not reach, and a short one, are counted from the events
	early := q
	early.From = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	same("from before the first event", early)
	short := q
	short.From = now.Add(-2 * time.Hour)
	same("two hours", short)

	// and it really is the sums that answer: change one, and the answer changes with it
	if _, err := e.s.Pool().Exec(ctx, `UPDATE event_rollup SET n = n + 1000 WHERE kind = 1 AND key = 'tcp' AND bucket = (SELECT min(bucket) FROM event_rollup WHERE kind = 1 AND key = 'tcp')`); err != nil {
		t.Fatal(err)
	}
	if moved, _ := e.s.EventsOverview(ctx, q); moved.TCP < all.TCP+1000 {
		t.Fatalf("the long window was not answered from the sums: %d", moved.TCP)
	}
}

// The devices of a window are kept like the other heavy answers: asked again, they are not counted again, and a
// question that differs in anything is a different one.
func TestDevicesAnalyticsIsKeptForTheSameQuestion(t *testing.T) {
	e := newAnalyticsEnv(t)
	router, err := e.s.CreateAgent(ctx, store.Scope{All: true}, e.home.ID, e.homeNodes[0].ID, "OpenWrt", "router", "4", store.HashAgentSecret("rt"))
	if err != nil {
		t.Fatal(err)
	}
	day := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	add := func(key string) {
		t.Helper()
		if _, err := e.s.Pool().Exec(ctx, `INSERT INTO device_connections (panel_id, agent_id, conn_key, started_at, updated_at, device_ip, destination_host, destination_port, protocol, up_bytes, down_bytes)
			VALUES ($1, $2, $3, $4, $4, '192.168.1.10', 'x.example.org', 443, 'tcp', 10, 20)`, e.home.ID, router.ID, key, day.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	old := store.SetAnalyticsCacheTTL(time.Hour)
	t.Cleanup(func() { store.SetAnalyticsCacheTTL(old) })
	q := store.AnalyticsQuery{PanelIDs: []string{e.home.ID}, From: day, To: day.Add(24 * time.Hour)}
	add("one")
	first, err := e.s.DevicesAnalytics(ctx, q)
	if err != nil || len(first) != 1 || first[0].Connections != 1 {
		t.Fatalf("first: %+v %v", first, err)
	}
	add("two")
	if again, _ := e.s.DevicesAnalytics(ctx, q); again[0].Connections != 1 {
		t.Fatalf("the same question was counted again: %+v", again)
	}
	other := q
	other.To = day.Add(25 * time.Hour)
	if fresh, _ := e.s.DevicesAnalytics(ctx, other); fresh[0].Connections != 2 {
		t.Fatalf("another window got the kept answer: %+v", fresh)
	}
}
