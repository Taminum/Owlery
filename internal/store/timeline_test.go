package store_test

import (
	"testing"
	"time"
)

func TestTimelineGroupsVisitsAndFindsByPartOfDomainOrService(t *testing.T) {
	e := newAnalyticsEnv(t)
	first := evt("www.example.org", "", 443, "tcp", "2", false, 30)
	second := evt("cdn.example.org", "", 443, "tcp", "2", false, 31)
	late := evt("www.example.org", "", 443, "tcp", "2", false, 32)
	late.Time = late.Time.Add(40 * time.Minute)
	e.push(t, e.homeAgent, first, second, late)

	rows, more, tot, err := e.s.Timeline(ctx, e.q, "EXAMPLE.ORG", false, "", time.Time{}, 50)
	if err != nil {
		t.Fatal(err)
	}
	if more || len(rows) != 2 || tot.Visits != 2 || tot.Connections != 3 || tot.Sites != 1 || tot.Last == nil {
		t.Fatalf("a quiet gap splits the visit: %+v %+v", rows, tot)
	}
	if !rows[0].Start.After(rows[1].Start) || rows[0].Connections != 1 || rows[1].Connections != 2 || rows[1].Hosts != 2 || rows[1].Site != "example.org" || rows[1].Src != "node" {
		t.Fatalf("newest first, the older visit has both hosts: %+v", rows)
	}
	if rows[1].NodeName == "" {
		t.Fatalf("the node is named: %+v", rows[1])
	}

	raw, _, _, err := e.s.Timeline(ctx, e.q, "example.org", true, "", time.Time{}, 50)
	if err != nil || len(raw) != 3 {
		t.Fatalf("raw view lists every connection: %+v %v", raw, err)
	}

	// Paging back: only what began before the last entry shown.
	older, _, _, err := e.s.Timeline(ctx, e.q, "example.org", false, "", rows[0].Start, 50)
	if err != nil || len(older) != 1 || !older[0].Start.Before(rows[0].Start) {
		t.Fatalf("before: %+v %v", older, err)
	}
	pg, more, _, err := e.s.Timeline(ctx, e.q, "example.org", true, "", time.Time{}, 2)
	if err != nil || len(pg) != 2 || !more {
		t.Fatalf("limit reports that there is more: %+v %v %v", pg, more, err)
	}

	// The service name finds its domains.
	e.push(t, e.homeAgent, evt("www.google.com", "", 443, "tcp", "2", false, 40))
	svc, _, _, err := e.s.Timeline(ctx, e.q, "google", false, "", time.Time{}, 50)
	byService := false
	for _, r := range svc {
		byService = byService || (r.Site == "gstatic.com" && r.Service == "Google") // found by the service name, not by the domain
	}
	if err != nil || !byService {
		t.Fatalf("service: %+v %v", svc, err)
	}
	if r, _, _, err := e.s.Timeline(ctx, e.q, "example.org", false, "router", time.Time{}, 50); err != nil || len(r) != 0 {
		t.Fatalf("a source filter: %+v %v", r, err)
	}
	none, _, tot, err := e.s.Timeline(ctx, e.q, "no-such-thing", false, "", time.Time{}, 50)
	if err != nil || len(none) != 0 || tot.Connections != 0 {
		t.Fatalf("nothing found: %+v %+v %v", none, tot, err)
	}
}
