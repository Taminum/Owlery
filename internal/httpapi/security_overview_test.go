package httpapi

import (
	"encoding/json"
	"testing"
	"time"
)

type ovResp struct {
	Health  string `json:"health"`
	Agent   string `json:"agent"`
	Reasons []struct {
		Code string `json:"code"`
	} `json:"reasons"`
	Events24h int `json:"events_24h"`
	LastEvent *struct {
		Type string `json:"type"`
	} `json:"last_event"`
}

func TestSecurityOverviewHealthStates(t *testing.T) {
	w := newAgentWorld(t)
	v := mkVPS(t, w, "Ov", "203.0.113.30", w.work.ID)
	path := "/api/v1/security/vps/" + v + "/overview"
	get := func() ovResp {
		st, b := w.owner.get(path)
		if st != 200 {
			t.Fatalf("%d %s", st, b)
		}
		return parse[ovResp](t, b)
	}

	// Nothing read and nothing checked: unknown, never healthy.
	if o := get(); o.Health != "unknown" || o.Agent != "none" || len(o.Reasons) != 0 {
		t.Fatalf("%+v", o)
	}

	// A public port that answers and is not expected is a reason for attention, and says why.
	if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO security_port_endpoints (vps_id, host, port, expected, source, enabled, last_checked_at, last_result, unexpected_since)
		VALUES ($1,'203.0.113.30',9000,false,'manual',true,now(),'reachable',now())`, v); err != nil {
		t.Fatal(err)
	}
	if o := get(); o.Health != "attention" || len(o.Reasons) != 1 || o.Reasons[0].Code != "port_unexpected" {
		t.Fatalf("%+v", o)
	}

	// Marking it expected clears the reason; a check has run, so it is healthy (with no agent, which the
	// screen says separately).
	if _, err := w.h.st.Pool().Exec(ctx, `UPDATE security_port_endpoints SET expected=true WHERE vps_id=$1`, v); err != nil {
		t.Fatal(err)
	}
	if o := get(); o.Health != "healthy" {
		t.Fatalf("%+v", o)
	}

	// An expired certificate needs attention.
	if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO security_tls_endpoints (vps_id, host, port, sni, enabled, last_checked_at, last_state, last_not_after)
		VALUES ($1,'203.0.113.30',443,'',true,now(),'expired',$2)`, v, time.Now().Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if o := get(); o.Health != "attention" || o.Reasons[0].Code != "tls_problem" {
		t.Fatalf("%+v", o)
	}

	// A disabled server is not judged.
	if st, _ := w.owner.do("PATCH", "/api/v1/security/vps/"+v, map[string]any{"enabled": false}); st != 200 {
		t.Fatal(st)
	}
	if o := get(); o.Health != "disabled" {
		t.Fatalf("%+v", o)
	}

	// A panel role cannot read a private server's overview.
	hidden := mkVPS(t, w, "Private", "203.0.113.31", "")
	if st, _ := w.viewer.get("/api/v1/security/vps/" + hidden + "/overview"); st != 404 {
		t.Fatalf("%d", st)
	}
}

func TestSecurityEventDetailWithNeighbours(t *testing.T) {
	w := newAgentWorld(t)
	a := mkVPS(t, w, "Linked", "203.0.113.40", w.work.ID)
	b := mkVPS(t, w, "Private", "203.0.113.41", "")
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	addEvent(t, w, a, "fail2ban", "fail2ban.ban", "info", `{"jail":"sshd","ip":"198.51.100.1"}`, t0)
	addEvent(t, w, a, "firewall", "firewall.rules_changed", "warning", `{"backend":"nft"}`, t0.Add(3*time.Minute))
	addEvent(t, w, a, "fail2ban", "fail2ban.ban", "info", `{"jail":"sshd","ip":"198.51.100.2"}`, t0.Add(2*time.Hour)) // far away
	addEvent(t, w, b, "ports", "port.public_reachable", "critical", `{"host":"h","port":9000}`, t0)

	st, jb := w.owner.get("/api/v1/security/events?vps_id=" + a + "&type=firewall.rules_changed")
	if st != 200 {
		t.Fatal(st)
	}
	ev := parse[journalResp](t, jb)
	if len(ev.Items) != 1 {
		t.Fatalf("%s", jb)
	}
	st, db := w.owner.get("/api/v1/security/events/" + ev.Items[0].ID)
	if st != 200 {
		t.Fatalf("%d %s", st, db)
	}
	var d struct {
		Event struct {
			Type    string `json:"type"`
			VPSName string `json:"vps_name"`
		} `json:"event"`
		Related []struct {
			Type string `json:"type"`
		} `json:"related"`
	}
	if err := json.Unmarshal(db, &d); err != nil || d.Event.Type != "firewall.rules_changed" || d.Event.VPSName != "Linked" {
		t.Fatalf("%s", db)
	}
	if len(d.Related) != 1 || d.Related[0].Type != "fail2ban.ban" {
		t.Fatalf("only the event within ten minutes on the same server is related: %s", db)
	}

	// A private server's event does not exist for a panel role, and a bad id is simply not found.
	_, ob := w.owner.get("/api/v1/security/events?vps_id=" + b)
	priv := parse[journalResp](t, ob)
	if st, _ := w.viewer.get("/api/v1/security/events/" + priv.Items[0].ID); st != 404 {
		t.Fatalf("%d", st)
	}
	if st, _ := w.owner.get("/api/v1/security/events/not-an-id"); st != 404 {
		t.Fatalf("%d", st)
	}
}
