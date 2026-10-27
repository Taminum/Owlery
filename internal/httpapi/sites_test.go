package httpapi

import (
	"context"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/store"
	"github.com/Taminum/Owlery/internal/xraylog"
)

type sitesResp struct {
	Meta       aMeta         `json:"meta"`
	Rows       []siteOut     `json:"rows"`
	Categories []categoryOut `json:"categories"`
	Groups     int           `json:"groups"`
	Total      int           `json:"total_connections"`
}

type siteDetailResp struct {
	Meta        aMeta            `json:"meta"`
	Site        string           `json:"site"`
	Category    string           `json:"category"`
	Connections int              `json:"connections"`
	Visits      int              `json:"visits"`
	Users       int              `json:"users"`
	Who         []siteWhoOut     `json:"who"`
	Hosts       []siteHostOut    `json:"hosts"`
	Timeline    []map[string]any `json:"timeline"`
}

type subjectsResp struct {
	Subjects []subjectOut `json:"subjects"`
}

func TestSitesCategoriesAndDetailEndToEnd(t *testing.T) {
	w := analyzerWorld(t)
	base := "?" + window + "&panel_ids=" + w.home.ID
	st, b := w.owner.get("/api/v1/analytics/sites" + base)
	r := parse[sitesResp](t, b)
	if st != 200 || r.Meta.State != "ok" || len(r.Rows) == 0 || r.Categories == nil || r.Total == 0 {
		t.Fatalf("%d %+v", st, r.Meta)
	}
	conns, visits := 0, 0
	for _, x := range r.Rows {
		if x.Site == "" || x.Connections == 0 || x.Visits == 0 || x.Visits > x.Connections || x.Category == "" || x.Hosts == 0 {
			t.Fatalf("%+v", x)
		}
		if !x.Classified && x.Category != "Не определена" {
			t.Fatalf("an unclassified site must say so: %+v", x)
		}
		conns += x.Connections
		visits += x.Visits
	}
	if conns > r.Total || visits > conns {
		t.Fatalf("conns %d visits %d total %d", conns, visits, r.Total)
	}
	catConns := 0
	for _, c := range r.Categories {
		catConns += c.Connections
	}
	if catConns != r.Total {
		t.Fatalf("the categories must add up to the sites' total: %d vs %d", catConns, r.Total)
	}

	// The detail of the busiest site: its hosts add up to it, and who visited is listed.
	top := r.Rows[0]
	_, db := w.owner.get("/api/v1/analytics/sites/detail" + base + "&site=" + url.QueryEscape(top.Site))
	d := parse[siteDetailResp](t, db)
	if d.Connections != top.Connections || len(d.Hosts) == 0 || len(d.Who) == 0 || d.Timeline == nil {
		t.Fatalf("detail %+v vs %+v", d, top)
	}
	hostConns := 0
	for _, h := range d.Hosts {
		hostConns += h.Connections
	}
	if hostConns != d.Connections {
		t.Fatalf("subdomains must add up to their site: %d vs %d", hostConns, d.Connections)
	}

	// Subjects: picking one narrows every view and never widens it.
	_, sb := w.owner.get("/api/v1/analytics/subjects" + base)
	subs := parse[subjectsResp](t, sb).Subjects
	if len(subs) == 0 {
		t.Fatal("no subjects")
	}
	sub := subs[0]
	_, fb := w.owner.get("/api/v1/analytics/sites" + base + "&subject=" + url.QueryEscape(sub.Subject))
	fr := parse[sitesResp](t, fb)
	if fr.Total == 0 || fr.Total > r.Total {
		t.Fatalf("subject %q: %d of %d", sub.Subject, fr.Total, r.Total)
	}
	_, ddb := w.owner.get("/api/v1/analytics/destinations" + base + "&group_by=site&subject=" + url.QueryEscape(sub.Subject))
	if dr := parse[destResp](t, ddb); dr.Total != fr.Total {
		t.Fatalf("destinations and sites must agree for the same subject: %d vs %d", dr.Total, fr.Total)
	}
	// Hosts below a site (the hierarchy) via destinations.
	_, hb := w.owner.get("/api/v1/analytics/destinations" + base + "&group_by=host&site=" + url.QueryEscape(top.Site))
	if hr := parse[destResp](t, hb); hr.Total != top.Connections {
		t.Fatalf("hosts of %s: %d vs %d", top.Site, hr.Total, top.Connections)
	}
}

func TestSitesInputIsValidatedAndScoped(t *testing.T) {
	w := analyzerWorld(t)
	base := "?" + window + "&panel_ids=" + w.home.ID
	for name, q := range map[string]string{
		"bad subject kind":   "&subject=group:" + w.home.ID + "|x",
		"no panel":           "&subject=user:nope",
		"bad uuid":           "&subject=user:" + w.home.ID + "|not-a-uuid",
		"bad device":         "&subject=device:" + w.home.ID + "|999.1.1.1",
		"huge limit":         "&limit=101",
		"long search":        "&q=" + strings.Repeat("a", 101),
		"control in raw id":  "&subject=raw:" + w.home.ID + "|a%00b",
		"empty subject body": "&subject=user:" + w.home.ID + "|",
	} {
		if st, bd := w.owner.get("/api/v1/analytics/sites" + base + q); st != 400 {
			t.Errorf("%s: %d %s", name, st, bd)
		}
	}
	if st, _ := w.owner.get("/api/v1/analytics/sites/detail" + base); st != 400 {
		t.Errorf("detail without a site: %d", st)
	}
	for _, evil := range []string{"%", "_", "'; drop table connection_events; --", "\\"} {
		if st, bd := w.owner.get("/api/v1/analytics/sites" + base + "&q=" + url.QueryEscape(evil) + "&category=" + url.QueryEscape(evil)); st != 200 {
			t.Errorf("%q: %d %s", evil, st, bd)
		}
	}

	// A subject that belongs to a panel outside the selection is not found, and the Work viewer
	// can neither ask for Home nor see Home's names through subjects.
	other := "subject=user:" + w.work.ID + "|" + "00000000-0000-4000-8000-000000000001"
	if st, _ := w.owner.get("/api/v1/analytics/sites" + base + "&" + other); st != 404 {
		t.Errorf("subject of a panel outside the selection: %d", st)
	}
	for _, path := range []string{"sites", "sites/detail?site=example.com&x=1", "subjects"} {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		if st, bd := w.viewer.get("/api/v1/analytics/" + path + sep + strings.TrimPrefix(window, "") + "&panel_ids=" + w.home.ID); st != 403 || errCode(bd) != "panel_forbidden" {
			t.Errorf("%s: %d %s", path, st, bd)
		}
	}
	_, vb := w.viewer.get("/api/v1/analytics/subjects?" + window)
	for _, s := range parse[subjectsResp](t, vb).Subjects {
		if strings.Contains(s.Subject, w.home.ID) || s.Label == "someone-else" || strings.Contains(s.Label, "alexandra") {
			t.Fatalf("viewer sees %+v", s)
		}
	}
}

func TestActivityEndpointIsValidatedAndShaped(t *testing.T) {
	w := analyzerWorld(t)
	base := "/api/v1/analytics/activity?" + window + "&panel_ids=" + w.home.ID
	st, b := w.owner.get(base + "&tz_offset=300")
	var r struct {
		Meta  aMeta   `json:"meta"`
		Grid  [][]int `json:"grid"`
		Max   int     `json:"max"`
		Total int     `json:"total"`
	}
	r = parse[struct {
		Meta  aMeta   `json:"meta"`
		Grid  [][]int `json:"grid"`
		Max   int     `json:"max"`
		Total int     `json:"total"`
	}](t, b)
	if st != 200 || len(r.Grid) != 7 || len(r.Grid[0]) != 24 || r.Total != 120 || r.Max == 0 {
		t.Fatalf("%d %+v", st, r)
	}
	sum := 0
	for _, row := range r.Grid {
		for _, v := range row {
			sum += v
		}
	}
	if sum != r.Total {
		t.Fatalf("grid %d vs total %d", sum, r.Total)
	}
	for _, bad := range []string{"&tz_offset=abc", "&tz_offset=900", "&tz_offset=-900"} {
		if st, _ := w.owner.get(base + bad); st != 400 {
			t.Errorf("%s: %d", bad, st)
		}
	}
	if st, bd := w.viewer.get(base); st != 403 || errCode(bd) != "panel_forbidden" {
		t.Errorf("scope: %d %s", st, bd)
	}
}

func TestCountriesEndpoint(t *testing.T) {
	w := analyzerWorld(t)
	base := "/api/v1/analytics/countries?" + window + "&panel_ids=" + w.home.ID
	st, b := w.owner.get(base)
	r := parse[struct {
		Meta    aMeta        `json:"meta"`
		Rows    []countryOut `json:"rows"`
		Located int          `json:"located"`
		NoIP    int          `json:"no_ip"`
		Unknown int          `json:"unknown"`
		Total   int          `json:"total_connections"`
	}](t, b)
	if st != 200 || r.Meta.State != "ok" || r.Total != 120 || r.Located+r.NoIP+r.Unknown != r.Total || r.Rows == nil {
		t.Fatalf("%d %+v", st, r)
	}
	sum := 0.0
	for _, c := range r.Rows {
		if len(c.Code) != 2 || c.Name == "" || c.Connections == 0 {
			t.Fatalf("%+v", c)
		}
		sum += c.Share
	}
	if r.Located > 0 && (sum < 99 || sum > 100.5) {
		t.Fatalf("shares of the placed connections must add up to ~100: %f", sum)
	}
	if st, bd := w.viewer.get(base); st != 403 || errCode(bd) != "panel_forbidden" {
		t.Errorf("scope: %d %s", st, bd)
	}
	if st, _ := w.owner.get(base + "&limit=0"); st != 400 {
		t.Errorf("limit: %d", st)
	}
}

func TestNetworksGroupBareIPsByOwnerAndDestinationsNameThem(t *testing.T) {
	w := analyzerWorld(t)
	agents, err := w.h.st.ListAgents(context.Background(), store.Scope{All: true}, w.home.ID)
	if err != nil || len(agents) == 0 {
		t.Fatal(err)
	}
	mk := func(seq int64, ip string, sec int) store.Line {
		ev := &xraylog.Event{Time: time.Date(2026, 10, 9, 12, 0, sec, 0, time.UTC), ClientIP: netip.MustParseAddr("198.51.100.7"), Protocol: "tcp",
			DestIP: netip.MustParseAddr(ip), DestPort: 443, InboundTag: "Steal", OutboundTag: "DIRECT", Arrow: ">>", Email: "2"}
		return store.Line{Seq: seq, Event: ev, FP: []byte{byte(seq)}}
	}
	lines := []store.Line{mk(121, "1.1.1.1", 1), mk(122, "1.0.0.1", 2), mk(123, "1.1.1.1", 3), mk(124, "8.8.8.8", 4), mk(125, "192.168.9.9", 5)}
	if _, err := w.h.st.CommitBatch(context.Background(), store.Commit{AgentID: agents[0].ID, Lines: lines}); err != nil {
		t.Fatal(err)
	}
	base := "?" + window + "&panel_ids=" + w.home.ID
	_, b := w.owner.get("/api/v1/analytics/networks" + base)
	r := parse[struct {
		Meta    aMeta        `json:"meta"`
		Rows    []networkOut `json:"rows"`
		IPOnly  int          `json:"ip_only"`
		Matched int          `json:"matched"`
		Unknown int          `json:"unknown"`
	}](t, b)
	by := map[uint32]networkOut{}
	for _, n := range r.Rows {
		by[n.ASN] = n
	}
	if cf := by[13335]; cf.Connections != 3 || cf.IPs != 2 || cf.Org == "" || len(cf.Examples) == 0 {
		t.Fatalf("Cloudflare: %+v (%+v)", cf, r)
	}
	if by[15169].Connections != 1 {
		t.Fatalf("Google: %+v", r.Rows)
	}
	if r.Matched+r.Unknown != r.IPOnly || r.Unknown == 0 || r.Matched < 4 {
		t.Fatalf("the buckets must add up and the private address stays unknown: %+v", r)
	}
	sum := 0.0
	for _, n := range r.Rows {
		sum += n.Share
	}
	if sum > 100.5 {
		t.Fatalf("shares %f", sum)
	}

	// An address row in "destinations" names its owner; a domain row does not.
	_, db := w.owner.get("/api/v1/analytics/destinations" + base + "&group_by=ip&limit=100")
	var named, unnamed int
	for _, d := range parse[destResp](t, db).Rows {
		if d.Key == "1.1.1.1" && (d.ASN != 13335 || d.Owner == "") {
			t.Fatalf("%+v", d)
		}
		if d.Key == "192.168.9.9" && d.Owner != "" {
			t.Fatalf("a private address has no owner: %+v", d)
		}
		if d.Owner != "" {
			named++
		} else {
			unnamed++
		}
	}
	if named == 0 {
		t.Fatal("no row got an owner")
	}
	if st, bd := w.viewer.get("/api/v1/analytics/networks" + base); st != 403 || errCode(bd) != "panel_forbidden" {
		t.Fatalf("scope: %d %s", st, bd)
	}
	if st, _ := w.owner.get("/api/v1/analytics/networks" + base + "&limit=0"); st != 400 {
		t.Fatalf("limit: %d", st)
	}
}
