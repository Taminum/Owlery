package httpapi

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/alerts"
	"github.com/Taminum/Owlery/internal/store"
)

type journalResp struct {
	Items []struct {
		ID       string `json:"id"`
		VPSName  string `json:"vps_name"`
		Category string `json:"category"`
		Type     string `json:"type"`
		Severity string `json:"severity"`
	} `json:"items"`
	More bool `json:"more"`
}

func mkVPS(t *testing.T, w *world, name, addr string, linkTo string) string {
	t.Helper()
	_, b := w.owner.do("POST", "/api/v1/security/vps", map[string]any{"name": name, "addresses": []string{addr}})
	v := parse[vpsResp](t, b)
	if linkTo != "" {
		if st, _ := w.owner.do("POST", "/api/v1/security/vps/"+v.ID+"/links", map[string]any{"panel_id": linkTo}); st != 201 {
			t.Fatal(st)
		}
	}
	return v.ID
}

func addEvent(t *testing.T, w *world, vps, cat, typ, sev, payload string, at time.Time) {
	t.Helper()
	_, err := w.h.st.Pool().Exec(ctx, `INSERT INTO security_events (vps_id, category, type, severity, source, observed_at, received_at, dedupe_key, payload)
		VALUES ($1,$2,$3,$4,'state_diff',$5,$5,$6,$7::jsonb)`, vps, cat, typ, sev, at, fmt.Sprintf("%s|%s|%d", typ, payload, at.UnixNano()), payload)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSecurityJournalFiltersPagingAndScope(t *testing.T) {
	w := newAgentWorld(t)
	a := mkVPS(t, w, "Linked", "203.0.113.7", w.work.ID)
	b := mkVPS(t, w, "Private", "203.0.113.8", "")
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	for i := 0; i < 4; i++ {
		addEvent(t, w, a, "fail2ban", "fail2ban.ban", "info", fmt.Sprintf(`{"jail":"sshd","ip":"198.51.100.%d"}`, i), t0.Add(time.Duration(i)*time.Minute))
	}
	addEvent(t, w, a, "tls", "tls.expired", "critical", `{"host":"a.example","port":443}`, t0.Add(10*time.Minute))
	addEvent(t, w, b, "firewall", "firewall.rules_changed", "warning", `{"backend":"nft"}`, t0.Add(20*time.Minute))
	addEvent(t, w, b, "ports", "port.public_reachable", "critical", `{"host":"h","port":9000}`, t0.Add(30*time.Minute))

	get := func(c *client, q string) journalResp {
		st, b := c.get("/api/v1/security/events" + q)
		if st != 200 {
			t.Fatalf("%s: %d %s", q, st, b)
		}
		return parse[journalResp](t, b)
	}
	// The owner sees both servers, newest first.
	all := get(w.owner, "")
	if len(all.Items) != 7 || all.Items[0].VPSName != "Private" || all.Items[0].Type != "port.public_reachable" {
		t.Fatalf("%+v", all)
	}
	// A panel role sees only the server linked to its panel; the private one is invisible.
	for who, c := range map[string]*client{"viewer": w.viewer, "admin": w.adm} {
		r := get(c, "")
		if len(r.Items) != 5 {
			t.Fatalf("%s sees %d", who, len(r.Items))
		}
		for _, e := range r.Items {
			if e.VPSName != "Linked" {
				t.Fatalf("%s sees %+v", who, e)
			}
		}
	}
	if r := get(w.viewer, "?vps_id="+b); len(r.Items) != 0 {
		t.Fatalf("asking for an invisible server by id must show nothing: %+v", r)
	}

	// Filters.
	if r := get(w.owner, "?category=tls"); len(r.Items) != 1 || r.Items[0].Type != "tls.expired" {
		t.Fatalf("%+v", r)
	}
	if r := get(w.owner, "?severity=critical"); len(r.Items) != 2 {
		t.Fatalf("%+v", r)
	}
	if r := get(w.owner, "?type=fail2ban.ban&vps_id="+a); len(r.Items) != 4 {
		t.Fatalf("%+v", r)
	}
	if r := get(w.owner, "?q="+url.QueryEscape("198.51.100.2")); len(r.Items) != 1 {
		t.Fatalf("search by IP: %+v", r)
	}
	if r := get(w.owner, "?q="+url.QueryEscape("%")); len(r.Items) != 0 {
		t.Fatalf("a percent sign must be literal: %+v", r)
	}
	from, to := t0.Add(9*time.Minute).Format(time.RFC3339), t0.Add(21*time.Minute).Format(time.RFC3339)
	if r := get(w.owner, "?from="+url.QueryEscape(from)+"&to="+url.QueryEscape(to)); len(r.Items) != 2 {
		t.Fatalf("time range: %+v", r)
	}

	// Paging walks every event exactly once.
	seen := map[string]bool{}
	q := "?limit=3"
	for pages := 0; pages < 5; pages++ {
		r := get(w.owner, q)
		for _, e := range r.Items {
			if seen[e.ID] {
				t.Fatalf("duplicate %s", e.ID)
			}
			seen[e.ID] = true
		}
		if !r.More {
			break
		}
		last := r.Items[len(r.Items)-1]
		var ts time.Time
		_ = w.h.st.Pool().QueryRow(ctx, `SELECT observed_at FROM security_events WHERE id=$1`, last.ID).Scan(&ts)
		q = "?limit=3&before_ts=" + url.QueryEscape(ts.UTC().Format(time.RFC3339Nano)) + "&before_id=" + last.ID
	}
	if len(seen) != 7 {
		t.Fatalf("paging saw %d of 7", len(seen))
	}

	for name, bad := range map[string]string{"limit": "?limit=0", "big limit": "?limit=500", "category": "?category=shell", "severity": "?severity=fatal",
		"type": "?type=a%20b", "time": "?from=yesterday", "long q": "?q=" + strings.Repeat("a", 101)} {
		if st, _ := w.owner.get("/api/v1/security/events" + bad); st != 400 {
			t.Errorf("%s: %d", name, st)
		}
	}
	if st, _ := w.h.anon().get("/api/v1/security/events"); st != 401 {
		t.Errorf("anonymous: %d", st)
	}
	if st, b := w.viewer.get("/api/v1/security/settings"); st != 200 || !strings.Contains(string(b), `"retention_days":180`) || !strings.Contains(string(b), `"independent":false`) {
		t.Errorf("settings: %d %s", st, b)
	}
}

func TestSecurityAlertsOpenCloseAndAreScoped(t *testing.T) {
	w := newAgentWorld(t)
	a := mkVPS(t, w, "Linked", "203.0.113.7", w.work.ID)
	b := mkVPS(t, w, "Private", "203.0.113.8", "")
	all := store.Scope{All: true}
	epA, err := w.h.st.AddTLSEndpoint(ctx, all, a, "203.0.113.7", 443, "")
	if err != nil {
		t.Fatal(err)
	}
	epB, err := w.h.st.AddTLSEndpoint(ctx, all, b, "203.0.113.8", 443, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	setTLS := func(id, state string, notAfter time.Time) {
		if _, err := w.h.st.Pool().Exec(ctx, `UPDATE security_tls_endpoints SET last_state=$2, last_not_after=$3, last_checked_at=now() WHERE id=$1`, id, state, notAfter); err != nil {
			t.Fatal(err)
		}
	}
	eval := func() {
		if _, _, err := alerts.Evaluate(ctx, w.h.st, now); err != nil {
			t.Fatal(err)
		}
	}
	open := func(c *client) alertsResp {
		_, b := c.get("/api/v1/alerts")
		return parse[alertsResp](t, b)
	}

	setTLS(epA.ID, "expired", now.Add(-48*time.Hour))
	setTLS(epB.ID, "ok", now.Add(10*24*time.Hour))
	eval()

	// The owner sees both: Linked under its panel, Private under "Безопасность". Work's roles see only Linked.
	o := open(w.owner)
	if o.Open != 2 {
		t.Fatalf("%+v", o)
	}
	names := map[string]bool{}
	for _, x := range o.Alerts {
		names[x.PanelName] = true
		if x.Kind != "sec_tls" {
			t.Errorf("%+v", x)
		}
	}
	if !names["Work"] || !names["Безопасность"] {
		t.Fatalf("%v", names)
	}
	if v := open(w.viewer); v.Open != 1 || v.Alerts[0].PanelName != "Work" {
		t.Fatalf("a panel role must not see the private server's alert: %+v", v)
	}

	// Fixing both closes both, even though no condition of the kind is left.
	setTLS(epA.ID, "ok", now.Add(80*24*time.Hour))
	setTLS(epB.ID, "ok", now.Add(80*24*time.Hour))
	eval()
	if o := open(w.owner); o.Open != 0 {
		t.Fatalf("the alerts did not close: %+v", o)
	}
}

func TestSecurityRetentionRemovesOnlyOldSecurityHistory(t *testing.T) {
	w := newAgentWorld(t)
	v := mkVPS(t, w, "Old", "203.0.113.7", "")
	now := time.Now().UTC()
	old, fresh := now.Add(-181*24*time.Hour), now.Add(-179*24*time.Hour)
	addEvent(t, w, v, "fail2ban", "fail2ban.ban", "info", `{"ip":"1.1.1.1"}`, old)
	addEvent(t, w, v, "fail2ban", "fail2ban.ban", "info", `{"ip":"2.2.2.2"}`, fresh)
	for _, at := range []time.Time{old, fresh} {
		if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO security_snapshots (vps_id, category, status, source_hash, observed_at, received_at, data) VALUES ($1,'firewall','ok','h',$2,$2,'{}')`, v, at); err != nil {
			t.Fatal(err)
		}
	}
	// Things that must survive: the audit log and the server itself.
	if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO audit_log (action, object_type, ts) VALUES ('security.vps.create','vps',$1)`, old); err != nil {
		t.Fatal(err)
	}
	n, err := w.h.st.PurgeSecurity(ctx, now)
	if err != nil || n != 2 {
		t.Fatalf("deleted %d, %v", n, err)
	}
	count := func(q string) (c int) { _ = w.h.st.Pool().QueryRow(ctx, q).Scan(&c); return }
	if c := count(`SELECT count(*) FROM security_events`); c != 1 {
		t.Errorf("events left: %d", c)
	}
	if c := count(`SELECT count(*) FROM security_snapshots`); c != 1 {
		t.Errorf("snapshots left: %d", c)
	}
	if c := count(`SELECT count(*) FROM audit_log WHERE action='security.vps.create' AND ts < now() - interval '180 days'`); c != 1 {
		t.Errorf("the audit log must not be purged: %d", c)
	}
	if c := count(`SELECT count(*) FROM security_vps`); c != 1 {
		t.Errorf("the server must stay: %d", c)
	}
}
