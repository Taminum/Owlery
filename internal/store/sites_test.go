package store_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/routerlog"
	"github.com/Taminum/RemnaScope/internal/store"
	"github.com/Taminum/RemnaScope/internal/xraylog"
)

func siteBy(rows []store.SiteRow) map[string]store.SiteRow {
	m := map[string]store.SiteRow{}
	for _, r := range rows {
		m[r.Site] = r
	}
	return m
}

func userUUID(t *testing.T, e *aEnv, remote string) string {
	t.Helper()
	var id string
	if err := e.s.Pool().QueryRow(ctx, `SELECT id::text FROM users WHERE panel_id=$1 AND remote_uuid=$2`, e.home.ID, remote).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSitesFoldSubdomainsAndKeepHostsUnderThem(t *testing.T) {
	e := newAnalyticsEnv(t)
	// Three more hosts of two sites, from two people.
	e.push(t, e.homeAgent,
		evt("www.pixiv.net", "", 443, "tcp", "2", false, 20),
		evt("i.pximg.net", "", 443, "tcp", "2", false, 21),
		evt("app-api.pixiv.net", "", 443, "tcp", "4", false, 22),
	)
	rows, groups, total, err := e.s.Sites(ctx, e.q)
	if err != nil {
		t.Fatal(err)
	}
	m := siteBy(rows)
	if g := m["google.com"]; g.Connections != 2 || g.Hosts != 1 || g.Service != "Google" || g.Category != "Поиск и сервисы" || g.Users != 1 {
		t.Fatalf("google.com: %+v", g)
	}
	if p := m["pixiv.net"]; p.Connections != 2 || p.Hosts != 2 || p.Users != 2 || p.Category != "Аниме и арт" {
		t.Fatalf("pixiv.net: %+v", p)
	}
	if m["pximg.net"].Category != "Аниме и арт" || m["ytimg.com"].Category != "Видео и стриминг" {
		t.Fatalf("categories: %+v", m)
	}
	if m["notgoogle.com"].Category != "" || m["notgoogle.com"].Service != "" {
		t.Fatalf("an unknown site must stay unclassified: %+v", m["notgoogle.com"])
	}
	if _, ok := m["9.9.9.9"]; ok {
		t.Fatal("an IP is not a site")
	}
	// Rows stored while an IP could still be a site must stay out of the site views.
	if _, err := e.s.Pool().Exec(ctx, `UPDATE connection_events SET site = '150.241.88.30' WHERE destination_host = 'www.pixiv.net'`); err != nil {
		t.Fatal(err)
	}
	if again, _, _, _ := e.s.Sites(ctx, e.q); siteBy(again)["150.241.88.30"].Site != "" {
		t.Fatal("an old IP-shaped site leaked into the sites view")
	}
	if _, err := e.s.Pool().Exec(ctx, `UPDATE connection_events SET site = 'pixiv.net' WHERE destination_host = 'www.pixiv.net'`); err != nil {
		t.Fatal(err)
	}
	if groups != len(rows) || total == 0 {
		t.Fatalf("groups %d rows %d total %d", groups, len(rows), total)
	}
	// google.com was hit twice within a second by one person: one visit, two connections.
	if g := m["google.com"]; g.Visits != 1 {
		t.Fatalf("visits: %+v", g)
	}

	// The hierarchy: the site's hosts stay visible below it.
	d, err := e.s.SiteDetailFor(ctx, e.q, "pixiv.net")
	if err != nil {
		t.Fatal(err)
	}
	if d.Connections != 2 || len(d.Hosts) != 2 || len(d.Who) != 2 || d.Category != "Аниме и арт" || len(d.Timeline) == 0 {
		t.Fatalf("detail: %+v", d)
	}
	names := map[string]bool{}
	for _, h := range d.Hosts {
		names[h.Host] = true
	}
	if !names["www.pixiv.net"] || !names["app-api.pixiv.net"] {
		t.Fatalf("subdomains missing: %+v", d.Hosts)
	}
	hq := e.q
	hq.GroupBy, hq.Site = "host", "pixiv.net"
	hrows, _, _, err := e.s.Destinations(ctx, hq)
	if err != nil || len(hrows) != 2 {
		t.Fatalf("hosts of the site: %+v %v", hrows, err)
	}
	sq := e.q
	sq.GroupBy = "site"
	srows, _, _, _ := e.s.Destinations(ctx, sq)
	if p := byKey(srows)["pixiv.net"]; p.Kind != "site" || p.Category != "Аниме и арт" {
		t.Fatalf("destinations by site: %+v", p)
	}

	cats, err := e.s.Categories(ctx, e.q)
	if err != nil {
		t.Fatal(err)
	}
	cm := map[string]store.CategoryRow{}
	for _, c := range cats {
		cm[c.Category] = c
	}
	if cm["Аниме и арт"].Sites != 2 || cm["Аниме и арт"].Connections != 3 {
		t.Fatalf("categories: %+v", cats) // pixiv.net (2) + pximg.net (1)
	}
	if cm[store.UncategorisedLabel].Connections == 0 {
		t.Fatalf("unclassified sites must be grouped honestly: %+v", cats)
	}
	cq := e.q
	cq.Category = "Аниме и арт"
	if rows, _, _, _ := e.s.Sites(ctx, cq); len(rows) != 2 {
		t.Fatalf("category filter: %+v", rows)
	}
	cq.Category = store.UncategorisedLabel
	if rows, _, _, _ := e.s.Sites(ctx, cq); siteBy(rows)["google.com"].Site != "" {
		t.Fatal("the uncategorised filter included a categorised site")
	}
}

func TestVisitsSplitAfterAQuietPeriod(t *testing.T) {
	e := newAnalyticsEnv(t)
	first := evt("www.example.org", "", 443, "tcp", "2", false, 30)
	late := evt("www.example.org", "", 443, "tcp", "2", false, 31)
	late.Time = late.Time.Add(40 * time.Minute)
	other := evt("cdn.example.org", "", 443, "tcp", "4", false, 32)
	e.push(t, e.homeAgent, first, late, other)
	rows, _, _, _ := e.s.Sites(ctx, e.q)
	g := siteBy(rows)["example.org"]
	if g.Connections != 3 || g.Visits != 3 || g.Users != 2 {
		t.Fatalf("two visits by one person (40 minutes apart) and one by another: %+v", g)
	}
}

func TestSubjectFilterUsersDevicesAndTheRouterUser(t *testing.T) {
	e := newAnalyticsEnv(t)
	router, err := e.s.CreateAgent(ctx, store.Scope{All: true}, e.home.ID, e.homeNodes[0].ID, "OpenWrt", "router", "4", store.HashAgentSecret("rt"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = e.s.AgentHello(ctx, router.ID, "e", "v", "s")
	ev := func(id, dev, host string, min int) *routerlog.Event {
		start := time.Date(2026, 10, 9, 13, min, 0, 0, time.UTC)
		return &routerlog.Event{ID: id, Start: start, Seen: start, Device: netip.MustParseAddr(dev), Host: host, Port: 443, Protocol: "tcp", Up: 1, Down: 9}
	}
	if _, err := e.s.CommitBatch(ctx, store.Commit{AgentID: router.ID, Lines: []store.Line{
		{Seq: 1, Device: ev("a", "192.168.1.5", "www.pixiv.net", 1), FP: []byte{1}},
		{Seq: 2, Device: ev("b", "192.168.1.6", "www.pixiv.net", 2), FP: []byte{2}},
		{Seq: 3, Device: ev("c", "192.168.1.6", "v.sankakucomplex.com", 3), FP: []byte{3}},
	}}); err != nil {
		t.Fatal(err)
	}
	e.q.GroupBy = "site"
	count := func(sub store.Subject) map[string]store.DestRow {
		q := e.q
		q.Subject = sub
		rows, _, _, err := e.s.Destinations(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		return byKey(rows)
	}
	// A device: only its own router records.
	d6 := count(store.Subject{Kind: "device", PanelID: e.home.ID, ID: "192.168.1.6"})
	if len(d6) != 2 || d6["pixiv.net"].Connections != 1 || d6["sankakucomplex.com"].Connections != 1 || d6["google.com"].Connections != 0 {
		t.Fatalf("device 192.168.1.6: %+v", d6)
	}
	// The nodes saw the router's user again after the router agent started reporting: that copy
	// must not be counted next to the router's own records.
	dup := evt("dup.example.test", "", 443, "tcp", "4", false, 0)
	dup.Time = time.Date(2026, 10, 9, 13, 30, 0, 0, time.UTC)
	e.push(t, e.homeAgent, dup)
	// The user the router stands for: every device's router records, and the nodes' events from
	// before the router existed (nothing else saw that traffic then).
	u4 := count(store.Subject{Kind: "user", PanelID: e.home.ID, ID: userUUID(t, e, "4")})
	if u4["pixiv.net"].Connections != 2 || u4["sankakucomplex.com"].Connections != 1 || u4["ytimg.com"].Connections != 1 {
		t.Fatalf("router user: %+v", u4)
	}
	if _, ok := u4["example.test"]; ok {
		t.Fatalf("the nodes' copy after the router's first record was counted twice: %+v", u4)
	}
	if all := count(store.Subject{}); all["example.test"].Connections != 1 { // only user 99's own line, not the duplicate
		t.Fatalf("double counting in the unfiltered view: %+v", all["example.test"])
	}
	// An ordinary user: node events only.
	u2 := count(store.Subject{Kind: "user", PanelID: e.home.ID, ID: userUUID(t, e, "2")})
	if u2["google.com"].Connections != 2 || u2["pixiv.net"].Connections != 0 {
		t.Fatalf("user 2: %+v", u2)
	}
	// An unresolved id.
	raw := count(store.Subject{Kind: "raw", PanelID: e.home.ID, ID: "99"})
	if len(raw) != 1 || raw["example.test"].Connections != 1 {
		t.Fatalf("raw 99: %+v", raw)
	}
	// Another panel's id never matches.
	if other := count(store.Subject{Kind: "user", PanelID: e.work.ID, ID: userUUID(t, e, "2")}); len(other) != 0 {
		t.Fatalf("a subject of another panel must match nothing: %+v", other)
	}

	subs, err := e.s.Subjects(ctx, e.q)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, s := range subs {
		kinds[s.Kind]++
	}
	if kinds["device"] != 2 || kinds["user"] < 2 || kinds["raw"] != 1 {
		t.Fatalf("subjects: %+v", subs)
	}
}

func TestBackfillFillsOnlyMissingSites(t *testing.T) {
	e := newAnalyticsEnv(t)
	if _, err := e.s.Pool().Exec(ctx, `UPDATE connection_events SET site = NULL`); err != nil {
		t.Fatal(err)
	}
	n, err := e.s.BackfillSites(ctx)
	if err != nil || n == 0 {
		t.Fatalf("backfill: %d %v", n, err)
	}
	var missing int
	_ = e.s.Pool().QueryRow(ctx, `SELECT count(*) FROM connection_events WHERE site IS NULL AND destination_host IS NOT NULL`).Scan(&missing)
	if missing != 0 {
		t.Fatalf("%d rows still without a site", missing)
	}
	if again, _ := e.s.BackfillSites(ctx); again != 0 {
		t.Fatalf("second run touched %d rows", again)
	}
}

// The drill-down category -> service -> site -> host must add up at every level, and every level
// must use the same (host-level) classification.
func TestDrillDownAddsUpAtEveryLevel(t *testing.T) {
	e := newAnalyticsEnv(t)
	e.push(t, e.homeAgent,
		evt("music.yandex.ru", "", 443, "tcp", "2", false, 40), // service Яндекс Музыка, category Музыка
		evt("music.yandex.ru", "", 443, "tcp", "2", false, 41),
		evt("mail.yandex.ru", "", 443, "tcp", "2", false, 42), // same site, service Yandex
	)
	level := func(group string, mod func(*store.AnalyticsQuery)) (map[string]store.DestRow, int) {
		q := e.q
		q.GroupBy = group
		mod(&q)
		rows, _, total, err := e.s.Destinations(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		return byKey(rows), total
	}
	cats, all := level("category", func(*store.AnalyticsQuery) {})
	sum := 0
	for _, c := range cats {
		sum += c.Connections
	}
	if sum != all || cats["Музыка"].Connections == 0 || cats["Музыка"].Kind != "category" {
		t.Fatalf("categories: %+v", cats)
	}
	if cats["IP без домена"].Connections == 0 {
		t.Fatalf("IP-only traffic must be its own group, not hidden: %+v", cats)
	}
	// category -> services
	svcs, tot := level("service", func(q *store.AnalyticsQuery) { q.Category = "Музыка" })
	if tot != cats["Музыка"].Connections || svcs["Яндекс Музыка"].Connections != 2 || svcs["Spotify"].Kind != "" && svcs["Spotify"].Connections > tot {
		t.Fatalf("services of Музыка: %+v (total %d vs %d)", svcs, tot, cats["Музыка"].Connections)
	}
	// service -> sites: only the hosts that rule matches, so yandex.ru counts the music host alone
	sites, tot := level("site", func(q *store.AnalyticsQuery) { q.Service = "Яндекс Музыка" })
	if tot != 2 || sites["yandex.ru"].Connections != 2 {
		t.Fatalf("sites of the service: %+v", sites)
	}
	// site -> hosts, inheriting the service filter: music.yandex.ru only
	hosts, tot := level("host", func(q *store.AnalyticsQuery) { q.Site, q.Service = "yandex.ru", "Яндекс Музыка" })
	if tot != 2 || len(hosts) != 1 || hosts["music.yandex.ru"].Connections != 2 {
		t.Fatalf("hosts: %+v", hosts)
	}
	// without the service filter the site shows both of its services' hosts
	hosts, tot = level("host", func(q *store.AnalyticsQuery) { q.Site = "yandex.ru" })
	if tot != 3 || len(hosts) != 2 {
		t.Fatalf("all hosts of yandex.ru: %+v", hosts)
	}
	// unknown service/category filters match nothing and never everything
	if none, tot := level("site", func(q *store.AnalyticsQuery) { q.Service = "нет такого" }); len(none) != 0 || tot != 0 {
		t.Fatalf("%+v", none)
	}
}

// What the nodes did with a site (blocked, sent through WARP) is read from the node log, and the
// .ru/.su/.рф filter looks at the domain name only.
func TestSitesShowNodeOutcomeAndRuZone(t *testing.T) {
	e := newAnalyticsEnv(t)
	blocked := evt("app-measurement.com", "", 443, "tcp", "2", false, 50)
	blocked.OutboundTag = "BLOCK"
	warp := evt("www.openai.com", "", 443, "tcp", "2", false, 51)
	warp.OutboundTag = "warp-out"
	ru := evt("www.yandex.ru", "", 443, "tcp", "2", false, 52)
	su := evt("old.example.su", "", 443, "tcp", "4", false, 53)
	e.push(t, e.homeAgent, blocked, blocked, warp, ru, su)

	rows, _, _, err := e.s.Sites(ctx, e.q)
	if err != nil {
		t.Fatal(err)
	}
	m := siteBy(rows)
	if m["app-measurement.com"].Blocked != 2 || m["openai.com"].Warp != 1 || m["openai.com"].Blocked != 0 {
		t.Fatalf("outcomes: %+v %+v", m["app-measurement.com"], m["openai.com"])
	}
	if !m["yandex.ru"].RU || !m["example.su"].RU || m["openai.com"].RU || m["google.com"].RU {
		t.Fatalf("ru zone flags: %+v", m)
	}
	q := e.q
	q.Zone = "ru"
	rr, _, _, _ := e.s.Sites(ctx, q)
	if len(rr) != 2 {
		t.Fatalf("ru zone: %+v", rr)
	}
	q.Zone = "other"
	oo, _, _, _ := e.s.Sites(ctx, q)
	if siteBy(oo)["yandex.ru"].Site != "" || siteBy(oo)["google.com"].Site == "" {
		t.Fatalf("other zone: %+v", oo)
	}
	// A subject narrows the outcome counts too: user 4 never had the blocked/warp lines.
	u4 := e.q
	u4.Subject = store.Subject{Kind: "user", PanelID: e.home.ID, ID: userUUID(t, e, "4")}
	r4, _, _, _ := e.s.Sites(ctx, u4)
	if siteBy(r4)["app-measurement.com"].Site != "" {
		t.Fatalf("user 4 does not use that site: %+v", r4)
	}
}

// The CDN entrance (an inbound) can be picked like a person. It reads node log lines only, and
// shows what came in through that inbound even for the user a router stands for.
func TestPathSubjectSelectsAnInbound(t *testing.T) {
	e := newAnalyticsEnv(t)
	cdn := evt("m.example.org", "", 443, "tcp", "2", false, 60)
	cdn.InboundTag = "XHTTP-TW"
	e.push(t, e.homeAgent, cdn, cdn)
	q := e.q
	q.GroupBy = "site"
	q.Subject = store.Subject{Kind: "path", PanelID: e.home.ID, ID: "XHTTP-TW"}
	rows, _, total, err := e.s.Destinations(ctx, q)
	if err != nil || total != 2 || byKey(rows)["example.org"].Connections != 2 {
		t.Fatalf("path XHTTP-TW: %+v total %d %v", rows, total, err)
	}
	q.Subject.ID = "Steal"
	rows, _, total, _ = e.s.Destinations(ctx, q)
	if total == 0 || byKey(rows)["example.org"].Connections != 0 {
		t.Fatalf("path Steal: %+v", rows)
	}
	subs, err := e.s.Subjects(ctx, e.q)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]int{}
	for _, s := range subs {
		if s.Kind == "path" {
			paths[s.ID] = s.Connections
		}
	}
	if paths["XHTTP-TW"] != 2 || paths["Steal"] == 0 {
		t.Fatalf("path subjects: %+v", paths)
	}
}

// "New" means a site nobody in scope had visited before the range began, whatever else it does.
func TestNewSitesAreThoseNeverSeenBeforeTheRange(t *testing.T) {
	e := newAnalyticsEnv(t)
	late := func(host string, hour int) *xraylog.Event {
		ev := evt(host, "", 443, "tcp", "2", false, 0)
		ev.Time = time.Date(2026, 10, 9, hour, 0, 0, 0, time.UTC)
		return ev
	}
	// google.com was seen at 12:00 (earlier, in the env). It is seen again at 13:00 together with a brand-new site.
	e.push(t, e.homeAgent, late("www.google.com", 13), late("fresh.example.org", 13), late("fresh.example.org", 14))
	q := e.q
	q.From = time.Date(2026, 10, 9, 12, 30, 0, 0, time.UTC)
	all, _, _, _ := e.s.Sites(ctx, q)
	if siteBy(all)["google.com"].Site == "" || siteBy(all)["example.org"].Site == "" {
		t.Fatalf("both are active in the range: %+v", all)
	}
	q.NewOnly = true
	fresh, _, _, err := e.s.Sites(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	m := siteBy(fresh)
	if len(m) != 1 || m["example.org"].Connections != 2 {
		t.Fatalf("only the site first seen inside the range: %+v", fresh)
	}
	// For a range that starts before everything, everything is new.
	q.From = time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	if rows, _, _, _ := e.s.Sites(ctx, q); len(rows) < 5 {
		t.Fatalf("with no history before the range every site is new: %d", len(rows))
	}
}

func TestActivityGridUsesTheViewersClock(t *testing.T) {
	e := newAnalyticsEnv(t)
	// Oct 9 2026 is a Friday. The env's events are at 12:00 UTC.
	utc, err := e.s.ActivityGrid(ctx, e.q, 0)
	if err != nil {
		t.Fatal(err)
	}
	if utc.Grid[4][12] == 0 || utc.Sum != utc.Grid[4][12] || utc.Max != utc.Grid[4][12] {
		t.Fatalf("friday 12:00 UTC: %+v", utc.Grid[4])
	}
	// Five hours east of UTC (the viewer's local time) the same events fall at 17:00.
	east, _ := e.s.ActivityGrid(ctx, e.q, 300)
	if east.Grid[4][17] != utc.Grid[4][12] || east.Grid[4][12] != 0 || east.Sum != utc.Sum {
		t.Fatalf("shifted: %+v", east.Grid[4])
	}
	// Past midnight the weekday moves too: 12:00 UTC + 13 h = Saturday 01:00.
	far, _ := e.s.ActivityGrid(ctx, e.q, 13*60)
	if far.Grid[5][1] != utc.Grid[4][12] {
		t.Fatalf("saturday: %+v", far.Grid[5])
	}
}

func TestCountriesPlaceOnlyLinesWithAnIPAndBackfillMatches(t *testing.T) {
	e := newAnalyticsEnv(t)
	e.push(t, e.homeAgent,
		evt("", "8.8.8.8", 443, "tcp", "2", false, 40), evt("", "8.8.8.8", 443, "tcp", "2", false, 41), evt("", "8.8.4.4", 443, "tcp", "4", false, 42),
		evt("", "77.88.8.8", 443, "tcp", "4", false, 43), evt("", "77.88.8.1", 443, "tcp", "2", false, 44),
		evt("", "192.168.5.5", 443, "tcp", "2", false, 45), // private: counted, never placed (the env already has 9.9.9.9, also US: 4 in all)
	)
	byCode := func() map[string]store.CountryRow {
		rows, err := e.s.Countries(ctx, e.q)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]store.CountryRow{}
		for _, r := range rows {
			m[r.Code] = r
		}
		return m
	}
	m := byCode()
	if m["US"].Connections != 4 || m["US"].Users != 2 || m["RU"].Connections != 2 {
		t.Fatalf("placed: %+v", m)
	}
	if m[store.UnknownCountry].Connections == 0 {
		t.Fatalf("a private address is its own bucket, not hidden: %+v", m)
	}
	if m[""].Connections == 0 {
		t.Fatalf("domain-only lines are counted apart: %+v", m)
	}
	// Total of all buckets equals every connection.
	sum := 0
	for _, r := range m {
		sum += r.Connections
	}
	if _, _, total, _ := e.s.Destinations(ctx, func() store.AnalyticsQuery { q := e.q; q.GroupBy = "host"; return q }()); sum != total {
		t.Fatalf("buckets %d vs connections %d", sum, total)
	}

	// Rows stored before the column existed get the same answer from the backfill.
	if _, err := e.s.Pool().Exec(ctx, `UPDATE connection_events SET country = NULL`); err != nil {
		t.Fatal(err)
	}
	if n, err := e.s.BackfillCountries(ctx); err != nil || n == 0 {
		t.Fatalf("backfill %d %v", n, err)
	}
	if after := byCode(); after["US"].Connections != 4 || after["RU"].Connections != 2 || after[store.UnknownCountry].Connections != m[store.UnknownCountry].Connections {
		t.Fatalf("after backfill: %+v", after)
	}
	if again, _ := e.s.BackfillCountries(ctx); again != 0 {
		t.Fatalf("second backfill touched %d rows", again)
	}
}

// Regression: the shared events query once re-ran its "router coverage" aggregate for every node
// event and took minutes on real data. With a router agent in place and enough rows it must stay quick.
func TestEventsQueriesStayFastWithManyRowsAndARouterAgent(t *testing.T) {
	e := newAnalyticsEnv(t)
	router, err := e.s.CreateAgent(ctx, store.Scope{All: true}, e.home.ID, e.homeNodes[0].ID, "OpenWrt", "router", "4", store.HashAgentSecret("rt"))
	if err != nil {
		t.Fatal(err)
	}
	pool := e.s.Pool()
	if _, err := pool.Exec(ctx, `INSERT INTO connection_events (event_id, panel_id, node_id, agent_id, ts, destination_host, destination_port, protocol, xray_email, raw_fingerprint, site)
		SELECT gen_random_uuid(), $1, $2, $3, '2026-10-09T00:00:00Z'::timestamptz + (g % 80000) * interval '1 second', 'h' || (g % 500) || '.example.org', 443, 'tcp', '4', '\x01', 'example.org'
		FROM generate_series(1, 60000) g`, e.home.ID, e.homeNodes[0].ID, e.homeAgent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO device_connections (panel_id, agent_id, conn_key, started_at, updated_at, device_ip, destination_host, destination_port, protocol, up_bytes, down_bytes, site)
		SELECT $1, $2, 'c' || g, '2026-10-09T00:00:00Z'::timestamptz + (g % 80000) * interval '1 second', '2026-10-09T00:00:00Z'::timestamptz + (g % 80000) * interval '1 second',
		       ('192.168.1.' || (1 + g % 200))::inet, 'h' || (g % 500) || '.example.org', 443, 'tcp', 10, 20, 'example.org'
		FROM generate_series(1, 20000) g`, e.home.ID, router.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `ANALYZE connection_events; ANALYZE device_connections`); err != nil {
		t.Fatal(err)
	}
	q := e.q
	q.To = time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	for name, run := range map[string]func(context.Context) error{
		"sites": func(c context.Context) error { _, _, _, err := e.s.Sites(c, q); return err },
		"destinations": func(c context.Context) error {
			qq := q
			qq.GroupBy = "site"
			_, _, _, err := e.s.Destinations(c, qq)
			return err
		},
		"subjects":  func(c context.Context) error { _, err := e.s.Subjects(c, q); return err },
		"countries": func(c context.Context) error { _, err := e.s.Countries(c, q); return err },
		"activity":  func(c context.Context) error { _, err := e.s.ActivityGrid(c, q, 300); return err },
	} {
		start := time.Now()
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := run(cctx)
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s took %s", name, d)
		}
	}
}

// Resolvers and VPN providers have their own categories, so they are not dumped into a catch-all, and
// a rule moved to a new category keeps the service it already had.
func TestVPNAndDNSCategoriesExistAndApply(t *testing.T) {
	e := newAnalyticsEnv(t)
	e.push(t, e.homeAgent,
		evt("dns.google", "", 443, "tcp", "2", false, 50), evt("dns.quad9.net", "", 443, "tcp", "2", false, 51),
		evt("mullvad.net", "", 443, "tcp", "4", false, 52), evt("cloudflare-dns.com", "", 443, "tcp", "4", false, 53))
	rows, _, _, err := e.s.Sites(ctx, e.q)
	if err != nil {
		t.Fatal(err)
	}
	m := siteBy(rows)
	want := map[string][2]string{"dns.google": {"DNS и сеть", "Google Public DNS"}, "quad9.net": {"DNS и сеть", "Quad9"},
		"mullvad.net": {"VPN и приватность", "Mullvad"}, "cloudflare-dns.com": {"DNS и сеть", "Cloudflare"}}
	for site, w := range want {
		if r := m[site]; r.Category != w[0] || r.Service != w[1] {
			t.Errorf("%s: %q / %q, want %q / %q", site, r.Category, r.Service, w[0], w[1])
		}
	}
	cats, err := e.s.RuleCategories(ctx)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, c := range cats {
		have[c] = true
	}
	if !have["VPN и приватность"] || !have["DNS и сеть"] {
		t.Fatalf("the new categories are missing: %v", cats)
	}
}
