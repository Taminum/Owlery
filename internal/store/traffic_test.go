package store_test

import (
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/store"
	"github.com/Taminum/Owlery/internal/store/storetest"
)

func TestTrafficDeltasAndResets(t *testing.T) {
	s := storetest.New(t)
	home, work := mkPanel(t, s, "home"), mkPanel(t, s, "work")
	now := time.Now().UTC()
	_, _ = s.UpsertNodes(ctx, home.ID, now, []store.NodeRecord{{RemoteUUID: "n1", Name: "alpha"}, {RemoteUUID: "n2", Name: "beta"}})
	_, _ = s.UpsertNodes(ctx, work.ID, now, []store.NodeRecord{{RemoteUUID: "w1", Name: "work-1"}})
	_, _ = s.UpsertUsers(ctx, home.ID, now, []store.UserRecord{{RemoteUUID: "2", Username: "alice"}, {RemoteUUID: "4", Username: "router"}})
	t0 := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	at := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	rec := func(p store.Panel, node bool, at time.Time, cs ...store.Counter) {
		t.Helper()
		var err error
		if node {
			_, err = s.RecordNodeCounters(ctx, p.ID, at, cs)
		} else {
			_, err = s.RecordUserCounters(ctx, p.ID, at, cs)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	n := func(id string, b int64) store.Counter {
		return store.Counter{RemoteUUID: id, Bytes: b, Source: store.SrcNodeUsed}
	}
	// alpha: 1000 -> 1500 -> 1800 -> reset to 200 -> 500; beta: only one sample.
	rec(home, true, at(0), n("n1", 1000), n("n2", 50))
	rec(home, true, at(5), n("n1", 1500))
	rec(home, true, at(10), n("n1", 1800))
	rec(home, true, at(15), n("n1", 200)) // the panel reset the counter
	rec(home, true, at(20), n("n1", 500))
	rec(home, true, at(20), n("n1", 500)) // a repeated snapshot is harmless
	rec(work, true, at(5), store.Counter{RemoteUUID: "w1", Bytes: 7777, Source: store.SrcNodeUsed})
	// users: alice has a lifetime counter and a period counter (the lifetime one wins); router only a period counter.
	u := func(id string, b int64, src string) store.Counter {
		return store.Counter{RemoteUUID: id, Bytes: b, Source: src}
	}
	rec(home, false, at(0), u("2", 100, store.SrcUserLifetime), u("2", 40, store.SrcUserUsed), u("4", 10, store.SrcUserUsed))
	rec(home, false, at(10), u("2", 160, store.SrcUserLifetime), u("2", 5, store.SrcUserUsed), u("4", 90, store.SrcUserUsed))
	// An unknown id is skipped, not invented.
	if got, _ := s.RecordUserCounters(ctx, home.ID, at(11), []store.Counter{u("999", 1, store.SrcUserUsed)}); got != 0 {
		t.Fatalf("unknown user recorded: %d", got)
	}

	q := store.AnalyticsQuery{PanelIDs: []string{home.ID}, From: at(-10), To: at(60), Granularity: 10 * time.Minute}
	nodes, err := s.TrafficByNode(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 || nodes[0].Name != "alpha" {
		t.Fatalf("nodes: %+v", nodes)
	}
	// 500 + 300 + (reset: 200) + 300 = 1300; never negative.
	if a := nodes[0]; a.Bytes != 1300 || a.Resets != 1 || a.Current != 500 || a.Samples != 5 {
		t.Fatalf("alpha: %+v", a)
	}
	if b := nodes[1]; b.Bytes != 0 || b.Samples != 1 {
		t.Fatalf("beta (single sample, nothing known before it): %+v", b)
	}

	users, err := s.TrafficByUser(ctx, q, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[0].RemoteID != "4" || users[0].Bytes != 80 || users[0].Source != store.SrcUserUsed {
		t.Fatalf("users: %+v", users)
	}
	if users[1].RemoteID != "2" || users[1].Bytes != 60 || users[1].Source != store.SrcUserLifetime {
		t.Fatalf("alice must use the lifetime counter only: %+v", users[1])
	}

	sum, err := s.TrafficSummaryFor(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if sum.NodeBytes != 1300 || sum.UserBytes != 140 || sum.Resets != 1 {
		t.Fatalf("summary: %+v", sum)
	}
	var tl int64
	for _, p := range sum.Timeline {
		tl += p.Bytes
	}
	if tl != 1300 {
		t.Fatalf("timeline must add up to the node total: %d", tl)
	}

	// A narrower range still finds the sample before it, so the delta at its start is real.
	nq := q
	nq.From = at(12)
	if rows, _ := s.TrafficByNode(ctx, nq); rows[0].Bytes != 500 { // at15: reset 200, at20: +300
		t.Fatalf("narrow range: %+v", rows[0])
	}
	// The other panel is invisible to this scope.
	for _, r := range nodes {
		if r.Name == "work-1" {
			t.Fatal("leak across panels")
		}
	}
	// A node filter limits the totals.
	fq := q
	fq.NodeIDs = []string{nodes[1].NodeID}
	if sm, _ := s.TrafficSummaryFor(ctx, fq); sm.NodeBytes != 0 {
		t.Fatalf("node filter: %+v", sm)
	}
	// Retention.
	if n, err := s.PurgeExpiredTraffic(ctx, now.AddDate(1, 0, 0)); err != nil || n == 0 {
		t.Fatalf("purge %d %v", n, err)
	}
}
