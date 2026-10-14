package demo

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 10, 9, 12, 7, 31, 0, time.UTC)

func query(panels, nodes []string, d time.Duration) Query {
	return Query{PanelIDs: panels, NodeIDs: nodes, From: fixedNow.Add(-d), To: fixedNow, Now: fixedNow}
}

func mustOverview(t *testing.T, q Query) Overview {
	t.Helper()
	ov, err := BuildOverview(q)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	return ov
}

func sumRows(rows []Row) int {
	s := 0
	for _, r := range rows {
		s += r.Count
	}
	return s
}

func TestDeterministic(t *testing.T) {
	a := mustOverview(t, query(nil, nil, 24*time.Hour))
	b := mustOverview(t, query(nil, nil, 24*time.Hour))
	if !reflect.DeepEqual(a, b) {
		t.Fatal("same query must give identical payload")
	}
}

func TestEverythingMarkedDemo(t *testing.T) {
	ov := mustOverview(t, query(nil, nil, time.Hour))
	if !ov.Meta.Demo {
		t.Fatal("meta.demo must be true")
	}
	if ov.Connections.MetricKind != KindConnections || ov.Traffic.MetricKind != KindBytes {
		t.Fatal("metric kinds must stay separate")
	}
	if ov.Connections.Source != Source || ov.Traffic.Source != Source {
		t.Fatal("source must be labelled")
	}
}

func TestListsAddUpToTotal(t *testing.T) {
	ov := mustOverview(t, query(nil, nil, 24*time.Hour))
	total := ov.Connections.Total
	if total == 0 || ov.Connections.TCP+ov.Connections.UDP != total {
		t.Fatalf("tcp+udp must equal total: %+v", ov.Connections)
	}
	tl := 0
	for _, p := range ov.Timeline {
		tl += p.TCP + p.UDP
	}
	if tl != total {
		t.Fatalf("timeline %d != total %d", tl, total)
	}
	for name, rows := range map[string][]Row{"hosts": ov.TopHosts, "ips": ov.TopIPs, "ports": ov.TopPorts, "services": ov.Services} {
		if got := sumRows(rows); got != total {
			t.Errorf("%s sum %d != total %d", name, got, total)
		}
	}
	if got := sumRows(ov.Users); got != total {
		t.Errorf("users sum %d != total %d", got, total)
	}
}

func TestPanelIsolation(t *testing.T) {
	home := mustOverview(t, query([]string{HomePanelID}, nil, 24*time.Hour))
	work := mustOverview(t, query([]string{WorkPanelID}, nil, 24*time.Hour))
	all := mustOverview(t, query(nil, nil, 24*time.Hour))

	if home.Connections.Total+work.Connections.Total != all.Connections.Total {
		t.Fatal("per-panel totals must add up to the all-panel total")
	}
	for _, u := range home.Users {
		if u.PanelID != HomePanelID {
			t.Fatalf("home view leaked user from %s", u.PanelID)
		}
	}
	for _, r := range home.Recent {
		if r.PanelID != HomePanelID {
			t.Fatal("home view leaked a work event")
		}
	}
	for _, n := range home.Meta.NodeIDs {
		if nodePanel(n).ID != HomePanelID {
			t.Fatal("home view leaked a work node")
		}
	}
}

func TestSameEmailInTwoPanelsStaysSeparate(t *testing.T) {
	all := mustOverview(t, query(nil, nil, 24*time.Hour))
	byLabel := map[string]map[string]bool{}
	for _, u := range all.Users {
		if byLabel[u.Label] == nil {
			byLabel[u.Label] = map[string]bool{}
		}
		byLabel[u.Label][u.PanelID] = true
	}
	if len(byLabel["2"]) != 2 || len(byLabel["3"]) != 2 {
		t.Fatalf("raw ids 2 and 3 exist in both panels and must be separate rows: %v", byLabel)
	}
}

func TestNodeFilter(t *testing.T) {
	one := Panels[0].Nodes[0].ID
	ov := mustOverview(t, query([]string{HomePanelID}, []string{one}, 24*time.Hour))
	all := mustOverview(t, query([]string{HomePanelID}, nil, 24*time.Hour))
	if ov.Connections.Total >= all.Connections.Total || ov.Nodes.Total != 1 {
		t.Fatalf("node filter had no effect: %d vs %d", ov.Connections.Total, all.Connections.Total)
	}
}

func TestScopeErrors(t *testing.T) {
	if _, err := BuildOverview(query([]string{"00000000-0000-4000-8000-000000000000"}, nil, time.Hour)); !errors.Is(err, ErrUnknownPanel) {
		t.Fatalf("unknown panel: %v", err)
	}
	workNode := Panels[1].Nodes[0].ID
	if _, err := BuildOverview(query([]string{HomePanelID}, []string{workNode}, time.Hour)); !errors.Is(err, ErrNodeOutOfScope) {
		t.Fatalf("node from another panel must be rejected: %v", err)
	}
	q := query(nil, nil, time.Hour)
	q.From = q.To
	if _, err := BuildOverview(q); !errors.Is(err, ErrBadRange) {
		t.Fatalf("empty range: %v", err)
	}
	if _, err := BuildOverview(query(nil, nil, 400*24*time.Hour)); !errors.Is(err, ErrBadRange) {
		t.Fatalf("huge range: %v", err)
	}
}

func TestGapIsReportedAndLowersCoverage(t *testing.T) {
	ov := mustOverview(t, query([]string{WorkPanelID}, nil, 24*time.Hour))
	if len(ov.Meta.Coverage.Gaps) != 1 || ov.Meta.Coverage.Pct >= 100 {
		t.Fatalf("expected one gap and coverage < 100: %+v", ov.Meta.Coverage)
	}
	marked := 0
	for _, p := range ov.Timeline {
		if p.Gap {
			marked++
		}
	}
	if marked == 0 {
		t.Fatal("timeline must mark gap buckets")
	}
	home := mustOverview(t, query([]string{HomePanelID}, nil, 24*time.Hour))
	if home.Meta.Coverage.Pct != 100 || len(home.Meta.Coverage.Gaps) != 0 {
		t.Fatal("home panel has no gap")
	}
}

func TestPreviewStatesCarryNoNumbers(t *testing.T) {
	for state, want := range map[string]string{"empty": "no_data", "pending": "sync_pending"} {
		q := query(nil, nil, time.Hour)
		q.State = state
		ov := mustOverview(t, q)
		if ov.Meta.State != want || ov.Connections.Total != 0 || len(ov.Timeline) != 0 || len(ov.TopHosts) != 0 {
			t.Fatalf("%s must be empty, got %+v", state, ov.Meta)
		}
	}
}

func TestTrafficSeriesMatchesTotals(t *testing.T) {
	ov := mustOverview(t, query(nil, nil, 24*time.Hour))
	var up, down int64
	for _, p := range ov.Traffic.Series {
		up += p.Up
		down += p.Down
	}
	if up != ov.Traffic.UpBytes || down != ov.Traffic.DownBytes || down <= up {
		t.Fatalf("traffic totals inconsistent: %d/%d vs %d/%d", up, down, ov.Traffic.UpBytes, ov.Traffic.DownBytes)
	}
}
