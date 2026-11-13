package store_test

import (
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

func TestSubscriptionRequestsCountDifferentAddressesPerSubscription(t *testing.T) {
	e := newAgentEnv(t)
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	at := func(h int) time.Time { return now.Add(-time.Duration(h) * time.Hour) }
	var recs []store.SubRequest
	id := int64(0)
	add := func(user, ip, ua string, h int) {
		id++
		recs = append(recs, store.SubRequest{RemoteID: id, RemoteUser: user, At: at(h), IP: ip, Agent: ua})
	}
	// alice: five addresses, one of them first seen within the last day
	for i, ip := range []string{"46.0.0.1", "46.0.0.2", "46.0.0.3", "46.0.0.4"} {
		add("2", ip, "Hiddify/2.0", 30+i)
	}
	add("2", "46.0.0.1", "Hiddify/2.0", 5)
	add("2", "91.0.0.9", "v2rayN/6", 2)
	add("2", "", "v2rayN/6", 1) // no address: counts as a request, not as an address
	// bob: one address many times
	for i := 0; i < 6; i++ {
		add("3", "198.51.100.1", "Streisand", 10+i)
	}
	// too old to count
	add("3", "203.0.113.5", "x", 24*20)
	n, err := e.s.AddSubscriptionRequests(ctx, e.panel.ID, recs)
	if err != nil || n != int64(len(recs)) {
		t.Fatalf("added %d, %v", n, err)
	}
	if n, err = e.s.AddSubscriptionRequests(ctx, e.panel.ID, recs); err != nil || n != 0 {
		t.Fatalf("asking again must add nothing, got %d, %v", n, err)
	}

	from, to := now.Add(-7*24*time.Hour), now
	got, err := e.s.SubLeaks(ctx, store.Scope{All: true}, from, to, 2, 50)
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v, %v", got, err)
	}
	a := got[0]
	if a.RemoteUser != "2" || a.Name != "alice" || a.IPs != 5 || a.IPsBefore != 4 || a.Requests != 7 || len(a.Agents) != 2 {
		t.Fatalf("alice: %+v", a)
	}
	if !a.Last.Equal(at(1)) {
		t.Fatalf("last %v", a.Last)
	}
	if all, _ := e.s.SubLeaks(ctx, store.Scope{All: true}, from, to, 1, 50); len(all) != 2 || all[0].RemoteUser != "2" {
		t.Fatalf("with a threshold of one both show, the one with more addresses first: %+v", all)
	}
	if c, err := e.s.SubscriptionsAsked(ctx, store.Scope{All: true}, from, to); err != nil || c != 2 {
		t.Fatalf("asked %d, %v", c, err)
	}
	if got, _ := e.s.SubLeaks(ctx, store.Scope{IDs: []string{"00000000-0000-0000-0000-000000000000"}}, from, to, 1, 50); len(got) != 0 {
		t.Fatalf("another panel's subscriptions leaked into this scope: %+v", got)
	}

	ips, err := e.s.SubLeakIPs(ctx, e.panel.ID, "2", from, to)
	if err != nil || len(ips) != 5 || ips[0].IP != "46.0.0.1" || ips[0].Requests != 2 || ips[0].Agent != "Hiddify/2.0" {
		t.Fatalf("ips %+v, %v", ips, err)
	}

	if err := e.s.PruneSubscriptionRequests(ctx, now.Add(40*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if c, _ := e.s.SubscriptionsAsked(ctx, store.Scope{All: true}, from, to); c != 0 {
		t.Fatalf("pruned data still there: %d", c)
	}
}
