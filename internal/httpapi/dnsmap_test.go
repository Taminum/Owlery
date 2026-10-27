package httpapi

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/alerts"
	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/dnsmap"
	"github.com/Taminum/Owlery/internal/store"
)

type dnsMapResp struct {
	ID           string  `json:"id"`
	Domain       string  `json:"domain"`
	Display      string  `json:"display"`
	IntervalH    int     `json:"interval_hours"`
	Enabled      bool    `json:"enabled"`
	LastStatus   *string `json:"last_status"`
	BaselineDone bool    `json:"baseline_done"`
}

func mkMap(t *testing.T, w *world, domain string) dnsMapResp {
	t.Helper()
	st, b := w.owner.do("POST", "/api/v1/intel/dns/maps", map[string]any{"domain": domain, "confirm_scope": true})
	if st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	return parse[dnsMapResp](t, b)
}

func TestDNSMapCreationIsValidatedAndOwnerOnly(t *testing.T) {
	w := newAgentWorld(t)
	post := func(c *client, body map[string]any) (int, []byte) {
		return c.do("POST", "/api/v1/intel/dns/maps", body)
	}

	if st, _ := post(w.owner, map[string]any{"domain": "example.com"}); st != 422 {
		t.Errorf("without confirming the scope: %d", st)
	}
	for name, d := range map[string]string{"ip": "203.0.113.7", "cidr": "10.0.0.0/8", "asn": "AS15169", "localhost": "localhost", "internal": "printer.lan", "junk": "not a domain!", "single label": "com"} {
		if st, _ := post(w.owner, map[string]any{"domain": d, "confirm_scope": true}); st != 422 {
			t.Errorf("%s: %d", name, st)
		}
	}
	for name, body := range map[string]map[string]any{
		"outside name":  {"domain": "example.com", "confirm_scope": true, "extra_names": []string{"evil.org"}},
		"look-alike":    {"domain": "example.com", "confirm_scope": true, "extra_names": []string{"example.com.evil.org"}},
		"an ip":         {"domain": "example.com", "confirm_scope": true, "extra_names": []string{"203.0.113.7"}},
		"interval 0.5":  {"domain": "example.com", "confirm_scope": true, "interval_hours": 500},
		"unknown field": {"domain": "example.com", "confirm_scope": true, "axfr": true},
	} {
		if st, _ := post(w.owner, body); st != 422 && st != 400 {
			t.Errorf("%s: %d", name, st)
		}
	}
	// A URL is reduced to its host; an IDN is stored in ASCII and shown in Unicode; case does not matter.
	st, b := post(w.owner, map[string]any{"domain": "https://Пример.рф/path?x=1", "confirm_scope": true, "extra_names": []string{"API.пример.рф"}, "use_ct": true})
	if st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	m := parse[dnsMapResp](t, b)
	if m.Domain != "xn--e1afmkfd.xn--p1ai" || m.Display != "пример.рф" || m.IntervalH != 24 || !m.Enabled {
		t.Fatalf("%+v", m)
	}
	if st, _ := post(w.owner, map[string]any{"domain": "xn--e1afmkfd.xn--p1ai", "confirm_scope": true}); st != 409 {
		t.Errorf("the same domain twice: %d", st)
	}

	// Only the owner, on every route.
	base := "/api/v1/intel/dns/maps"
	for who, c := range map[string]*client{"admin": w.adm, "operator": w.op, "viewer": w.viewer} {
		for _, p := range []string{"", "/" + m.ID, "/" + m.ID + "/records", "/" + m.ID + "/graph", "/" + m.ID + "/changes", "/" + m.ID + "/checks"} {
			if st, _ := c.get(base + p); st != 403 {
				t.Errorf("%s GET %s: %d", who, p, st)
			}
		}
		if st, _ := c.do("POST", base+"/"+m.ID+"/refresh", nil); st != 403 {
			t.Errorf("%s refresh: %d", who, st)
		}
		if st, _ := post(c, map[string]any{"domain": "other.example.org", "confirm_scope": true}); st != 403 {
			t.Errorf("%s create: %d", who, st)
		}
	}
	if st, _ := w.h.anon().get(base); st != 401 {
		t.Errorf("anonymous: %d", st)
	}

	// Change, then archive: the map goes, a new one of the same domain may come.
	if st, b := w.owner.do("PATCH", base+"/"+m.ID, map[string]any{"interval_hours": 6, "enabled": false, "extra_names": []string{"mail.пример.рф"}}); st != 200 {
		t.Fatalf("%d %s", st, b)
	}
	if st, _ := w.owner.do("PATCH", base+"/"+m.ID, map[string]any{"extra_names": []string{"evil.org"}}); st != 422 {
		t.Errorf("%d", st)
	}
	if st, _ := w.owner.do("DELETE", base+"/"+m.ID, nil); st != 204 {
		t.Fatalf("%d", st)
	}
	if st, _ := w.owner.get(base + "/" + m.ID); st != 404 {
		t.Errorf("an archived map: %d", st)
	}
	if st, _ := post(w.owner, map[string]any{"domain": "xn--e1afmkfd.xn--p1ai", "confirm_scope": true}); st != 201 {
		t.Errorf("a domain can be mapped again after archiving: %d", st)
	}
}

func TestDNSRefreshIsLimitedAndRefusedWhileARunIsInProgress(t *testing.T) {
	w := newAgentWorld(t)
	m := mkMap(t, w, "example.com")
	path := "/api/v1/intel/dns/maps/" + m.ID + "/refresh"
	if st, b := w.owner.do("POST", path, nil); st != 202 {
		t.Fatalf("%d %s", st, b)
	}
	if st, _ := w.owner.do("POST", path, nil); st != 429 {
		t.Errorf("a second refresh at once: %d", st)
	}
	w.h.srv.dnsLimit = auth.NewLimiter(1000, 1000)
	if _, err := w.h.st.StartDNSRun(ctx, m.ID, "manual", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if st, b := w.owner.do("POST", path, nil); st != 409 || errCode(b) != "running" {
		t.Errorf("%d %s", st, b)
	}
}

// ---- runs, changes, alerts, graph ----

func rec(name, typ, result string, confirmed bool, ttl uint32, values ...string) dnsmap.Rec {
	return dnsmap.Rec{Obs: dnsmap.Obs{Name: name, Type: typ, Result: result, Values: values, TTL: ttl, Confirmed: confirmed},
		Views: []dnsmap.ResolverView{{Server: "1.1.1.1:53", Outcome: result, Values: values}, {Server: "8.8.8.8:53", Outcome: result, Values: values}}}
}

func result(status string, recs ...dnsmap.Rec) dnsmap.RunResult {
	return dnsmap.RunResult{Names: []dnsmap.NameInfo{{Name: "example.com", Provenance: dnsmap.ProvApex}, {Name: "www.example.com", Provenance: dnsmap.ProvWWW}},
		Recs: recs, Status: status, Coverage: dnsmap.Coverage{Discovery: "known_names", DNSSEC: "not_checked", NamesTotal: 2, NamesChecked: 2}}
}

type changeList struct {
	Items []struct {
		ID       string   `json:"id"`
		Name     string   `json:"name"`
		Type     string   `json:"type"`
		Kind     string   `json:"kind"`
		Before   []string `json:"before"`
		After    []string `json:"after"`
		Volatile bool     `json:"volatile"`
	} `json:"items"`
	More bool `json:"more"`
}

func TestDNSRunsBecomeRecordsChangesAndAlertsAndFailuresLoseNothing(t *testing.T) {
	w := newAgentWorld(t)
	m := mkMap(t, w, "example.com")
	base := "/api/v1/intel/dns/maps/" + m.ID
	at := time.Now().UTC().Add(-48 * time.Hour)
	run := func(res dnsmap.RunResult) {
		t.Helper()
		at = at.Add(2 * time.Hour)
		id, err := w.h.st.StartDNSRun(ctx, m.ID, "schedule", at)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.h.st.FinishDNSRun(ctx, m.ID, id, res, at, at.Add(24*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	changes := func(q string) changeList {
		st, b := w.owner.get(base + "/changes" + q)
		if st != 200 {
			t.Fatalf("%d %s", st, b)
		}
		return parse[changeList](t, b)
	}
	records := func(q string) []struct {
		Name             string   `json:"name"`
		Type             string   `json:"type"`
		Result           *string  `json:"result"`
		Values           []string `json:"values"`
		Confirmed        bool     `json:"confirmed"`
		LastResult       string   `json:"last_result"`
		NoLongerObserved bool     `json:"no_longer_observed"`
	} {
		st, b := w.owner.get(base + "/records" + q)
		if st != 200 {
			t.Fatalf("%d %s", st, b)
		}
		return parse[struct {
			Items []struct {
				Name             string   `json:"name"`
				Type             string   `json:"type"`
				Result           *string  `json:"result"`
				Values           []string `json:"values"`
				Confirmed        bool     `json:"confirmed"`
				LastResult       string   `json:"last_result"`
				NoLongerObserved bool     `json:"no_longer_observed"`
			} `json:"items"`
		}](t, b).Items
	}
	openAlerts := func() map[string]bool {
		if _, _, err := alerts.Evaluate(ctx, w.h.st, at); err != nil {
			t.Fatal(err)
		}
		_, b := w.owner.get("/api/v1/alerts")
		out := map[string]bool{}
		for _, a := range parse[alertsResp](t, b).Alerts {
			out[a.Kind] = true
		}
		return out
	}

	// 1. The first run is a baseline: every record is recorded and nothing is "added".
	run(result("ok",
		rec("example.com", "A", "answer", true, 300, "1.1.1.1"), rec("example.com", "MX", "answer", true, 300, "10 mail.example.com"),
		rec("example.com", "NS", "answer", true, 300, "ns1.example.net", "ns2.example.net"),
		rec("www.example.com", "CNAME", "answer", true, 60, "cdn.example.net"), rec("cdn.example.net", "A", "answer", true, 60, "198.51.100.7")))
	if c := changes(""); len(c.Items) != 0 {
		t.Fatalf("the baseline explained something: %+v", c.Items)
	}
	if rs := records(""); len(rs) != 5 {
		t.Fatalf("%d records", len(rs))
	}

	// 2. A confirmed change of the address, the mail server and the name servers.
	run(result("ok",
		rec("example.com", "A", "answer", true, 300, "2.2.2.2"), rec("example.com", "MX", "answer", true, 300, "20 mx.other.org"),
		rec("example.com", "NS", "answer", true, 300, "ns1.example.net", "ns3.example.net")))
	got := map[string]bool{}
	for _, c := range changes("").Items {
		got[c.Name+" "+c.Type+" "+c.Kind] = true
	}
	for _, want := range []string{"example.com A dns.record_added", "example.com A dns.record_removed", "example.com MX dns.mx_changed", "example.com NS dns.ns_changed"} {
		if !got[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	// The alert says what was seen; the unchanged records were not asked about and stay as they were.
	if a := openAlerts(); !a["dns_change"] {
		t.Fatalf("an important confirmed change must raise an alert: %v", a)
	}
	if rs := records("?name=www.example.com"); len(rs) != 1 || rs[0].Values[0] != "cdn.example.net" {
		t.Fatalf("a record that was not asked about changed: %+v", rs)
	}

	// 3. A run where nothing answers: no change, no record lost, one check_failed, one alert.
	run(result("failed",
		rec("example.com", "A", "timeout", false, 0), rec("example.com", "MX", "servfail", false, 0), rec("example.com", "NS", "timeout", false, 0)))
	for _, r := range records("?name=example.com") {
		if r.Type == "A" && (len(r.Values) != 1 || r.Values[0] != "2.2.2.2" || r.LastResult != "timeout" || r.NoLongerObserved) {
			t.Fatalf("a failure replaced what was known: %+v", r)
		}
	}
	if c := changes("?kind=dns.check_failed"); len(c.Items) != 1 {
		t.Fatalf("%+v", c.Items)
	}
	if a := openAlerts(); !a["dns_check_failed"] {
		t.Fatalf("%v", a)
	}
	// A second failed run is still one failure, not another event.
	run(result("failed", rec("example.com", "A", "timeout", false, 0)))
	if c := changes("?kind=dns.check_failed"); len(c.Items) != 1 {
		t.Fatalf("a repeated failure repeated the event: %+v", c.Items)
	}

	// 4. Recovery: same data as before the failure is no change; one check_recovered; the failure alert closes.
	run(result("ok", rec("example.com", "A", "answer", true, 300, "2.2.2.2")))
	if c := changes("?kind=dns.check_recovered"); len(c.Items) != 1 {
		t.Fatalf("%+v", c.Items)
	}
	if a := openAlerts(); a["dns_check_failed"] {
		t.Fatalf("the failure alert did not close: %v", a)
	}
	n := len(changes("").Items)

	// 5. Two resolvers that disagree: the difference is not a change, and the settled value stays.
	run(result("ok", rec("example.com", "A", "answer", false, 300, "9.9.9.9")))
	if len(changes("").Items) != n {
		t.Fatalf("an unconfirmed answer became a change")
	}
	for _, r := range records("?name=example.com&type=A") {
		if r.Values[0] != "2.2.2.2" || r.Confirmed {
			t.Fatalf("%+v", r)
		}
	}

	// 6. A confirmed, complete "no such record" is a removal, and the record is marked, not erased.
	run(result("ok", rec("www.example.com", "CNAME", "nodata", true, 0)))
	if c := changes("?name=www.example.com"); len(c.Items) != 1 || c.Items[0].Kind != "dns.record_removed" || c.Items[0].Before[0] != "cdn.example.net" {
		t.Fatalf("%+v", c.Items)
	}
	for _, r := range records("?name=www.example.com") {
		if !r.NoLongerObserved {
			t.Fatalf("%+v", r)
		}
	}

	// 7. A record set that keeps flipping is volatile: still listed, never an alert.
	for i := 0; i < 4; i++ {
		v := "5.5.5." + string(rune('1'+i%2))
		run(result("ok", rec("flip.example.com", "A", "answer", true, 30, v)))
	}
	vol := 0
	for _, c := range changes("?name=flip.example.com").Items {
		if c.Volatile {
			vol++
		}
	}
	if vol == 0 {
		t.Fatalf("a record set that changes every run must be marked volatile: %+v", changes("?name=flip.example.com").Items)
	}

	// Reads are validated and paged.
	for name, q := range map[string]string{"limit": "?limit=0", "type": "?type=AXFR", "kind": "?kind=evil", "time": "?from=yesterday"} {
		if st, _ := w.owner.get(base + "/changes" + q); st != 400 {
			t.Errorf("%s: %d", name, st)
		}
	}
	first := changes("?limit=2")
	if len(first.Items) != 2 || !first.More {
		t.Fatalf("%+v", first)
	}
	var ts time.Time
	_ = w.h.st.Pool().QueryRow(ctx, `SELECT observed_at FROM dns_changes WHERE id=$1`, first.Items[1].ID).Scan(&ts)
	next := changes("?limit=200&before_ts=" + url.QueryEscape(ts.Format(time.RFC3339Nano)) + "&before_id=" + first.Items[1].ID)
	seen := map[string]bool{}
	for _, c := range append(first.Items, next.Items...) {
		if seen[c.ID] {
			t.Fatalf("duplicate %s", c.ID)
		}
		seen[c.ID] = true
	}
	if len(seen) != len(changes("?limit=200").Items) {
		t.Fatalf("paging lost changes: %d vs %d", len(seen), len(changes("?limit=200").Items))
	}
	if rs := records("?q=" + url.QueryEscape("mx.other.org")); len(rs) != 1 || rs[0].Type != "MX" {
		t.Fatalf("search by value: %+v", rs)
	}
	if rs := records("?q=" + url.QueryEscape("%")); len(rs) != 0 {
		t.Fatalf("a percent sign must be literal: %+v", rs)
	}
	if st, b := w.owner.get(base + "/checks"); st != 200 || !strings.Contains(string(b), `"status":"failed"`) || !strings.Contains(string(b), `"discovery":"known_names"`) {
		t.Fatalf("%d %s", st, b)
	}
}

func TestDNSGraphShowsOnlyObservedRecordsAndIsBounded(t *testing.T) {
	w := newAgentWorld(t)
	m := mkMap(t, w, "example.com")
	at := time.Now().UTC()
	id, _ := w.h.st.StartDNSRun(ctx, m.ID, "manual", at)
	res := result("ok",
		rec("example.com", "A", "answer", true, 300, "93.184.216.34"), rec("example.com", "AAAA", "answer", true, 300, "2001:db8::1"),
		rec("example.com", "MX", "answer", true, 300, "10 mail.example.com", "20 mx2.example.net"), rec("example.com", "NS", "answer", true, 300, "ns1.example.net"),
		rec("example.com", "TXT", "answer", true, 300, "v=spf1 -all"), rec("example.com", "SOA", "answer", true, 300, "ns1 h 1 1 1 1 1"),
		rec("www.example.com", "CNAME", "answer", true, 60, "cdn.example.net"), rec("cdn.example.net", "A", "answer", false, 60, "198.51.100.7"),
		rec("gone.example.com", "A", "nodata", true, 0))
	if err := w.h.st.FinishDNSRun(ctx, m.ID, id, res, at, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	type graph struct {
		Nodes []struct {
			ID    string `json:"id"`
			Kind  string `json:"kind"`
			Label string `json:"label"`
		} `json:"nodes"`
		Edges []struct {
			From       string `json:"from"`
			To         string `json:"to"`
			Type       string `json:"type"`
			Label      string `json:"label"`
			Unverified bool   `json:"unverified"`
		} `json:"edges"`
		Total     int  `json:"total_nodes"`
		Truncated bool `json:"truncated"`
	}
	st, b := w.owner.get("/api/v1/intel/dns/maps/" + m.ID + "/graph")
	if st != 200 {
		t.Fatalf("%d %s", st, b)
	}
	g := parse[graph](t, b)
	kinds := map[string]int{}
	for _, n := range g.Nodes {
		kinds[n.Kind]++
	}
	if kinds["ip"] != 3 || kinds["mail"] != 2 || kinds["ns"] != 1 || kinds["name"] < 3 {
		t.Fatalf("%v", kinds)
	}
	types := map[string]int{}
	var prio, unverified bool
	for _, e := range g.Edges {
		types[e.Type]++
		prio = prio || (e.Type == "MX" && strings.HasPrefix(e.Label, "prio "))
		unverified = unverified || (e.To == "ip:198.51.100.7" && e.Unverified)
	}
	if types["A"] != 2 || types["AAAA"] != 1 || types["CNAME"] != 1 || types["MX"] != 2 || types["NS"] != 1 || types["TXT"] != 0 || types["SOA"] != 0 {
		t.Fatalf("TXT and SOA stay out of the graph, and a missing record draws nothing: %v", types)
	}
	if !prio || !unverified {
		t.Fatalf("MX shows its priority and an unconfirmed record is marked: prio %v unverified %v", prio, unverified)
	}
	if g.Truncated {
		t.Fatalf("%+v", g)
	}
	// Bounded: a small limit truncates and says so.
	st, b = w.owner.get("/api/v1/intel/dns/maps/" + m.ID + "/graph?max_nodes=5")
	if g2 := parse[graph](t, b); st != 200 || len(g2.Nodes) > 5 || !g2.Truncated || g2.Total <= 5 {
		t.Fatalf("%d %+v", st, g2)
	}
	if st, _ := w.owner.get("/api/v1/intel/dns/maps/" + m.ID + "/graph?max_nodes=2"); st != 400 {
		t.Errorf("%d", st)
	}
}

func TestDNSRetentionRemovesOnlyOldHistory(t *testing.T) {
	w := newAgentWorld(t)
	m := mkMap(t, w, "example.com")
	now := time.Now().UTC()
	id, _ := w.h.st.StartDNSRun(ctx, m.ID, "manual", now)
	if err := w.h.st.FinishDNSRun(ctx, m.ID, id, result("ok", rec("example.com", "A", "answer", true, 60, "1.1.1.1")), now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	old, fresh := now.Add(-181*24*time.Hour), now.Add(-179*24*time.Hour)
	for i, at := range []time.Time{old, fresh} {
		if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO dns_changes (map_id, name, type, kind, observed_at, dedupe_key) VALUES ($1,'example.com','A','dns.record_added',$2,$3)`, m.ID, at, "k"+string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO dns_check_runs (map_id, trigger, started_at, status) VALUES ($1,'schedule',$2,'ok')`, m.ID, old); err != nil {
		t.Fatal(err)
	}
	// Something that must survive: the audit log and a Security event of the same age.
	if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO audit_log (action, object_type, ts) VALUES ('intel.dns_map.create','dns_map',$1)`, old); err != nil {
		t.Fatal(err)
	}
	n, err := w.h.st.PurgeDNS(ctx, now)
	if err != nil || n != 2 {
		t.Fatalf("deleted %d, %v", n, err)
	}
	count := func(q string) (c int) { _ = w.h.st.Pool().QueryRow(ctx, q).Scan(&c); return }
	if count(`SELECT count(*) FROM dns_changes`) != 1 || count(`SELECT count(*) FROM dns_records`) != 1 || count(`SELECT count(*) FROM dns_maps`) != 1 ||
		count(`SELECT count(*) FROM audit_log WHERE action='intel.dns_map.create' AND ts < now() - interval '180 days'`) != 1 {
		t.Fatal("the purge took more than old DNS history")
	}
	_ = store.DNSRetention
}
