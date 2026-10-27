package httpapi

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

type destResp struct {
	Meta    aMeta     `json:"meta"`
	GroupBy string    `json:"group_by"`
	Rows    []destOut `json:"rows"`
	Groups  int       `json:"groups"`
	Total   int       `json:"total_connections"`
}

type usersResp struct {
	Meta  aMeta     `json:"meta"`
	Rows  []userOut `json:"rows"`
	Total int       `json:"total_connections"`
}

const window = "from=2026-10-09T00:00:00Z&to=2026-10-10T00:00:00Z"

func analyzerWorld(t *testing.T) *world {
	t.Helper()
	w := newAgentWorld(t)
	homeAgent := enroll(t, w.owner, w.home.ID, nodeID(t, w.owner, w.home.ID, "home-a"))
	workAgent := enroll(t, w.owner, w.work.ID, nodeID(t, w.owner, w.work.ID, "work-1"))
	lines := sampleLines(t)
	if ack := push(t, w.h, homeAgent.Token, 1, lines); ack.Accepted != 120 {
		t.Fatalf("%+v", ack)
	}
	if ack := push(t, w.h, workAgent.Token, 1, lines[:30]); ack.Accepted != 30 {
		t.Fatalf("%+v", ack)
	}
	return w
}

func TestDestinationsAnalyzerEndToEnd(t *testing.T) {
	w := analyzerWorld(t)
	st, b := w.owner.get("/api/v1/analytics/destinations?" + window + "&panel_ids=" + w.home.ID)
	r := parse[destResp](t, b)
	if st != 200 || r.Meta.State != "ok" || r.Meta.Demo || r.Meta.MetricKind != "connection_count" || r.Meta.Source != "agent_access_log" || r.GroupBy != "host" {
		t.Fatalf("%d %+v", st, r.Meta)
	}
	if r.Total != 120 || len(r.Rows) == 0 || r.Groups < len(r.Rows) {
		t.Fatalf("total %d rows %d groups %d", r.Total, len(r.Rows), r.Groups)
	}
	sum := 0.0
	for _, d := range r.Rows {
		if d.Connections == 0 || d.Kind == "" || d.Key == "" || d.Ports == nil {
			t.Fatalf("%+v", d)
		}
		sum += d.Share
	}
	if sum > 100.5 {
		t.Fatalf("shares exceed 100%%: %f", sum)
	}
	// Other panels' destinations never appear in Home's view.
	_, wb := w.owner.get("/api/v1/analytics/destinations?" + window + "&panel_ids=" + w.work.ID)
	if wr := parse[destResp](t, wb); wr.Total != 30 {
		t.Fatalf("work total %d", wr.Total)
	}
	// Group by service and by ip, plus paging.
	_, sb := w.owner.get("/api/v1/analytics/destinations?" + window + "&panel_ids=" + w.home.ID + "&group_by=service")
	if sr := parse[destResp](t, sb); sr.GroupBy != "service" || sr.Total != 120 || len(sr.Rows) == 0 {
		t.Fatalf("%+v", sr.GroupBy)
	}
	_, pb := w.owner.get("/api/v1/analytics/destinations?" + window + "&panel_ids=" + w.home.ID + "&limit=2&offset=1")
	if pr := parse[destResp](t, pb); len(pr.Rows) != 2 {
		t.Fatalf("%d", len(pr.Rows))
	}
}

func TestAnalyzerInputIsValidatedAndSearchIsSafe(t *testing.T) {
	w := analyzerWorld(t)
	base := "/api/v1/analytics/destinations?" + window + "&panel_ids=" + w.home.ID
	for name, q := range map[string]string{
		"bad group": "&group_by=drop", "bad limit": "&limit=0", "huge limit": "&limit=101", "negative offset": "&offset=-1",
		"non-numeric": "&limit=abc", "long search": "&q=" + strings.Repeat("a", 101),
	} {
		if st, b := w.owner.get(base + q); st != 400 {
			t.Errorf("%s: %d %s", name, st, b)
		}
	}
	for _, evil := range []string{"%", "_", "'; drop table connection_events; --", "%25", "\\"} {
		st, b := w.owner.get(base + "&q=" + url.QueryEscape(evil))
		if st != 200 {
			t.Errorf("%q: %d %s", evil, st, b)
		}
	}
	for url, want := range map[string]int{
		"/api/v1/analytics/destinations":                                                                                           400,
		"/api/v1/analytics/destinations?range=2y":                                                                                  400,
		"/api/v1/analytics/destinations?from=2026-10-09T00:00:00Z&to=2026-01-01T00:00:00Z":                                         400,
		"/api/v1/analytics/destinations?from=2020-01-01T00:00:00Z&to=2026-10-10T00:00:00Z":                                         400,
		"/api/v1/analytics/destinations?range=24h&panel_ids=ffffffff-ffff-4fff-8fff-ffffffffffff":                                  200, // an owner sees every panel; one that does not exist is simply empty
		"/api/v1/analytics/destinations?range=24h&panel_ids=" + w.home.ID + "&node_ids=not-a-node":                                 400,
		"/api/v1/analytics/destinations?range=24h&panel_ids=" + w.home.ID + "&node_ids=" + nodeID(t, w.owner, w.work.ID, "work-1"): 400,
	} {
		if st, _ := w.owner.get(url); st != want {
			t.Errorf("%s: %d, want %d", url, st, want)
		}
	}
}

func TestAnalyzerScopeFollowsTheRoleExactlyLikeEverythingElse(t *testing.T) {
	w := analyzerWorld(t)
	for _, path := range []string{"destinations", "users", "nodes", "traffic", "devices"} {
		// The Work viewer cannot ask for Home, by id or by guessing.
		for _, panel := range []string{w.home.ID, "ffffffff-ffff-4fff-8fff-ffffffffffff"} {
			if st, b := w.viewer.get("/api/v1/analytics/" + path + "?" + window + "&panel_ids=" + panel); st != 403 || errCode(b) != "panel_forbidden" {
				t.Errorf("%s %s: %d %s", path, panel, st, b)
			}
		}
		// The default scope is only what they may see.
		st, b := w.viewer.get("/api/v1/analytics/" + path + "?" + window)
		if st != 200 || strings.Contains(string(b), w.home.ID) || strings.Contains(string(b), "home-a") {
			t.Errorf("%s default scope leaks Home: %d", path, st)
		}
	}
	_, b := w.viewer.get("/api/v1/analytics/destinations?" + window)
	if r := parse[destResp](t, b); r.Total != 30 {
		t.Fatalf("the viewer sees Work only: %d", r.Total)
	}
	// Account names are masked for viewers, plain for operators.
	_, vb := w.viewer.get("/api/v1/analytics/users?" + window)
	_, ob := w.op.get("/api/v1/analytics/users?" + window)
	vr, or := parse[usersResp](t, vb), parse[usersResp](t, ob)
	has := func(r usersResp, name string) bool {
		for _, u := range r.Rows {
			if u.Label == name {
				return true
			}
		}
		return false
	}
	if has(vr, "someone-else") || !has(or, "someone-else") {
		t.Fatalf("viewer %+v operator %+v", vr.Rows, or.Rows)
	}
}

func TestUsersAnalyzerNamesWithoutGuessing(t *testing.T) {
	w := analyzerWorld(t)
	_, b := w.owner.get("/api/v1/analytics/users?" + window + "&panel_ids=" + w.home.ID)
	r := parse[usersResp](t, b)
	by := map[string]userOut{}
	for _, u := range r.Rows {
		by[u.Label] = u
	}
	if by["alexandra"].Connections == 0 || by["система"].Connections == 0 {
		t.Fatalf("%+v", r.Rows)
	}
	if u := by["id 3"]; u.Note != "не сопоставлен" || !strings.Contains(u.Key, "|raw|3") {
		t.Fatalf("an id that is not a user of this panel stays an unresolved id: %+v", u)
	}
	if r.Rows[0].Connections < r.Rows[len(r.Rows)-1].Connections {
		t.Fatal("busiest first")
	}
	total := 0
	for _, u := range r.Rows {
		total += u.Connections
	}
	if total != r.Total {
		t.Fatalf("%d vs %d", total, r.Total)
	}
}

func TestUserDetailRoundTripAndKeyHardening(t *testing.T) {
	w := analyzerWorld(t)
	_, b := w.owner.get("/api/v1/analytics/users?" + window + "&panel_ids=" + w.home.ID)
	var key string
	for _, u := range parse[usersResp](t, b).Rows {
		if u.Label == "alexandra" {
			key = u.Key
		}
	}
	if key == "" {
		t.Fatal("alexandra missing")
	}
	st, db := w.owner.get("/api/v1/analytics/users/detail?" + window + "&key=" + url.QueryEscape(key))
	if st != 200 {
		t.Fatalf("%d %s", st, db)
	}
	if m := nullList.Find(db); m != nil {
		t.Fatalf("null list in the JSON: %s", m)
	}
	var d struct {
		Label    string     `json:"label"`
		Total    int        `json:"total"`
		Hosts    []namedOut `json:"hosts"`
		Ports    []namedOut `json:"ports"`
		Nodes    []namedOut `json:"nodes"`
		Timeline []struct{} `json:"timeline"`
	}
	d = parse[struct {
		Label    string     `json:"label"`
		Total    int        `json:"total"`
		Hosts    []namedOut `json:"hosts"`
		Ports    []namedOut `json:"ports"`
		Nodes    []namedOut `json:"nodes"`
		Timeline []struct{} `json:"timeline"`
	}](t, db)
	if d.Label != "alexandra" || d.Total == 0 || len(d.Hosts) == 0 || len(d.Nodes) != 1 || d.Nodes[0].Key != "home-a" || len(d.Timeline) == 0 {
		t.Fatalf("%+v", d)
	}
	// A viewer of another panel cannot read this user, by key or by guessing.
	if st, _ := w.viewer.get("/api/v1/analytics/users/detail?" + window + "&key=" + url.QueryEscape(key)); st != 403 {
		t.Fatalf("a Work viewer reading a Home user: %d", st)
	}
	for _, bad := range []string{"", "nonsense", w.home.ID, w.home.ID + "|", w.home.ID + "|not-a-uuid", w.home.ID + "|raw|", w.home.ID + "|raw|" + strings.Repeat("x", 200),
		"not-a-uuid|system", w.home.ID + "|system|extra", "'; drop table users; --|system"} {
		if st, _ := w.owner.get("/api/v1/analytics/users/detail?" + window + "&key=" + url.QueryEscape(bad)); st != 400 {
			t.Errorf("key %q: %d", bad, st)
		}
	}
	// The same raw id in two panels is two different keys with different content.
	if st, rb := w.owner.get("/api/v1/analytics/users/detail?" + window + "&key=" + url.QueryEscape(w.work.ID+"|raw|zzz")); st != 200 || !strings.Contains(string(rb), `"total":0`) {
		t.Fatalf("an unknown raw id has no events: %d %s", st, rb)
	}
	// System traffic has its own key.
	if st, sb := w.owner.get("/api/v1/analytics/users/detail?" + window + "&key=" + url.QueryEscape(w.home.ID+"|system")); st != 200 || !strings.Contains(string(sb), `"label":"система"`) {
		t.Fatalf("%d %s", st, sb)
	}
}

func TestNodesAnalyzerShowsAgentStateAndQuietNodes(t *testing.T) {
	w := analyzerWorld(t)
	_, b := w.owner.get("/api/v1/analytics/nodes?" + window + "&panel_ids=" + w.home.ID)
	var r struct {
		Meta aMeta     `json:"meta"`
		Rows []nodeOut `json:"rows"`
	}
	r = parse[struct {
		Meta aMeta     `json:"meta"`
		Rows []nodeOut `json:"rows"`
	}](t, b)
	if len(r.Rows) != 2 || r.Meta.Coverage.NodesTotal != 2 || r.Meta.Coverage.NodesWithAgent != 1 {
		t.Fatalf("%+v", r)
	}
	by := map[string]nodeOut{}
	for _, n := range r.Rows {
		by[n.Name] = n
	}
	if a := by["home-a"]; a.Agent != "live" || a.Connections != 120 || a.Users == 0 {
		t.Fatalf("%+v", a)
	}
	if bq := by["home-b"]; bq.Agent != "none" || bq.Connections != 0 {
		t.Fatalf("a node without an agent must be listed, not hidden: %+v", bq)
	}
}

func TestAnalyzerSaysSoWhenThereIsNothingToAnalyse(t *testing.T) {
	w := newAgentWorld(t) // agents exist for nobody
	st, b := w.owner.get("/api/v1/analytics/destinations?range=24h&panel_ids=" + w.home.ID)
	r := parse[destResp](t, b)
	if st != 200 || r.Meta.State != "no_data" || r.Meta.Reason != "agents_not_connected" || len(r.Rows) != 0 {
		t.Fatalf("%d %+v", st, r.Meta)
	}
	homeAgent := enroll(t, w.owner, w.home.ID, nodeID(t, w.owner, w.home.ID, "home-a"))
	_ = homeAgent
	_, b = w.owner.get("/api/v1/analytics/destinations?range=24h&panel_ids=" + w.home.ID)
	if r = parse[destResp](t, b); r.Meta.Reason != "no_events" {
		t.Fatalf("an agent without events: %+v", r.Meta)
	}
	// Demo panels have nothing collected and are left out of the analyzer.
	_, b = w.owner.get("/api/v1/analytics/destinations?range=24h&panel_ids=11111111-1111-4111-8111-111111111111")
	if r = parse[destResp](t, b); r.Meta.Reason != "no_real_panels" {
		t.Fatalf("%+v", r.Meta)
	}
	for _, p := range []string{"destinations", "users", "nodes"} {
		_, jb := w.owner.get("/api/v1/analytics/" + p + "?range=24h&panel_ids=" + w.home.ID)
		if m := nullList.Find(jb); m != nil || strings.Contains(string(jb), `"rows":null`) {
			t.Errorf("%s: null where a list belongs: %s", p, jb)
		}
	}
}

type trafficResp struct {
	Meta       aMeta             `json:"meta"`
	Direction  string            `json:"direction"`
	TotalBytes int64             `json:"total_bytes"`
	UsersBytes int64             `json:"users_total_bytes"`
	Resets     int               `json:"counter_resets"`
	Samples    int               `json:"samples"`
	Timeline   []trafficPointOut `json:"timeline"`
	Nodes      []trafficNodeOut  `json:"nodes"`
	Users      []trafficUserOut  `json:"users"`
}

func TestTrafficAnalyzerUsesPanelCountersAndScope(t *testing.T) {
	w := analyzerWorld(t)
	q := "/api/v1/analytics/traffic?" + window + "&panel_ids=" + w.home.ID
	// No counters recorded yet: an explicit reason, not zeros.
	st, b := w.owner.get(q)
	if r := parse[trafficResp](t, b); st != 200 || r.Meta.State != "no_data" || r.Meta.Reason != "no_counters" || r.Nodes == nil || r.Users == nil || r.Timeline == nil {
		t.Fatalf("%d %+v", st, r.Meta)
	}

	at := func(h int) time.Time { return time.Date(2026, 10, 9, h, 0, 0, 0, time.UTC) }
	ctx := context.Background()
	rec := func(p panelDTO, h int, node string, nb int64, user string, ub int64) {
		t.Helper()
		if _, err := w.h.st.RecordNodeCounters(ctx, p.ID, at(h), []store.Counter{{RemoteUUID: node, Bytes: nb, Source: store.SrcNodeUsed}}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.h.st.RecordUserCounters(ctx, p.ID, at(h), []store.Counter{{RemoteUUID: user, Bytes: ub, Source: store.SrcUserLifetime}}); err != nil {
			t.Fatal(err)
		}
	}
	rec(w.home, 10, "h1", 1000, "2", 100)
	rec(w.home, 11, "h1", 4000, "2", 700)
	rec(w.home, 12, "h1", 100, "2", 900) // node counter reset by the panel
	rec(w.work, 10, "w1", 10, "2", 1)
	rec(w.work, 11, "w1", 99999, "2", 99999)

	st, b = w.owner.get(q)
	r := parse[trafficResp](t, b)
	if st != 200 || r.Meta.State != "ok" || r.Meta.MetricKind != "bytes" || r.Meta.Source != "panel_api_counters" || r.Direction != "total" {
		t.Fatalf("%d %+v", st, r.Meta)
	}
	if r.TotalBytes != 3100 || r.Resets != 1 || r.UsersBytes != 800 { // 3000 + reset 100; user 600 + 200
		t.Fatalf("%+v", r)
	}
	var tl int64
	for _, p := range r.Timeline {
		tl += p.Bytes
	}
	if tl != r.TotalBytes {
		t.Fatalf("timeline %d vs total %d", tl, r.TotalBytes)
	}
	if len(r.Nodes) != 2 || r.Nodes[0].Name != "home-a" || r.Nodes[0].Share != 100 || r.Nodes[1].Samples != 0 || r.Nodes[1].LastSample != nil {
		t.Fatalf("nodes: %+v", r.Nodes)
	}
	if len(r.Users) != 1 || r.Users[0].Label != "alexandra" || r.Users[0].Counter != "lifetime" || r.Users[0].Bytes != 800 {
		t.Fatalf("users: %+v", r.Users)
	}
	if strings.Contains(string(b), "99999") || strings.Contains(string(b), "work-1") {
		t.Fatal("Work's numbers leaked into Home's view")
	}

	// Roles: the Work viewer cannot ask for Home and sees Work only; its names are masked for viewers.
	if st, b := w.viewer.get(q); st != 403 || errCode(b) != "panel_forbidden" {
		t.Fatalf("%d %s", st, b)
	}
	_, vb := w.viewer.get("/api/v1/analytics/traffic?" + window)
	vr := parse[trafficResp](t, vb)
	if vr.TotalBytes != 99989 {
		t.Fatalf("viewer total %d", vr.TotalBytes)
	}
	for _, u := range vr.Users {
		if u.Label == "someone-else" {
			t.Fatalf("name not masked for a viewer: %+v", u)
		}
	}
}

// The overview reports panel counters as a total, with no up/down split, and null (not zero)
// when no counter has been recorded.
func TestOverviewTrafficIsATotalFromPanelCounters(t *testing.T) {
	w := analyzerWorld(t)
	path := "/api/v1/overview?" + window + "&panel_ids=" + w.home.ID
	_, b := w.owner.get(path)
	type ovTraffic struct {
		Traffic struct {
			Up     int64  `json:"up_bytes"`
			Down   int64  `json:"down_bytes"`
			Total  *int64 `json:"total_bytes"`
			Series []struct {
				Bytes int64 `json:"bytes"`
			} `json:"total_series"`
			Resets int `json:"counter_resets"`
		} `json:"traffic"`
	}
	if o := parse[ovTraffic](t, b); o.Traffic.Total != nil || o.Traffic.Series == nil {
		t.Fatalf("no counters yet must be null and an empty list: %+v", o.Traffic)
	}
	at := func(h int) time.Time { return time.Date(2026, 10, 9, h, 0, 0, 0, time.UTC) }
	for h, v := range map[int]int64{10: 1000, 11: 4000, 12: 100} { // the last one is a reset
		if _, err := w.h.st.RecordNodeCounters(context.Background(), w.home.ID, at(h), []store.Counter{{RemoteUUID: "h1", Bytes: v, Source: store.SrcNodeUsed}}); err != nil {
			t.Fatal(err)
		}
	}
	_, b = w.owner.get(path)
	o := parse[ovTraffic](t, b)
	if o.Traffic.Total == nil || *o.Traffic.Total != 3100 || o.Traffic.Resets != 1 || o.Traffic.Up != 0 || o.Traffic.Down != 0 {
		t.Fatalf("%+v", o.Traffic)
	}
	var sum int64
	for _, p := range o.Traffic.Series {
		sum += p.Bytes
	}
	if sum != 3100 {
		t.Fatalf("series %d", sum)
	}
}
