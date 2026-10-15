package httpapi

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDigestCountsWhatHappenedAndRespectsScope(t *testing.T) {
	w := newAgentWorld(t)
	a := mkVPS(t, w, "Linked", "203.0.113.80", w.work.ID)
	b := mkVPS(t, w, "Private", "203.0.113.81", "")
	now := time.Now().UTC()
	addEvent(t, w, a, "fail2ban", "fail2ban.ban", "info", `{"jail":"sshd","ip":"198.51.100.1"}`, now.Add(-time.Hour))
	addEvent(t, w, a, "fail2ban", "fail2ban.ban", "info", `{"jail":"sshd","ip":"198.51.100.2"}`, now.Add(-2*time.Hour))
	addEvent(t, w, a, "firewall", "firewall.rules_changed", "warning", `{"backend":"nft"}`, now.Add(-3*time.Hour))
	addEvent(t, w, b, "ports", "port.public_reachable", "critical", `{"host":"h","port":9000}`, now.Add(-time.Hour))
	addEvent(t, w, a, "fail2ban", "fail2ban.ban", "info", `{"jail":"sshd","ip":"198.51.100.3"}`, now.Add(-72*time.Hour)) // outside 24h

	type digest struct {
		Events []struct {
			Type  string `json:"type"`
			Count int    `json:"count"`
		} `json:"security_events"`
		DNS      *struct{ Total int } `json:"dns"`
		Security bool                 `json:"has_security"`
	}
	count := func(d digest, typ string) int {
		for _, e := range d.Events {
			if e.Type == typ {
				return e.Count
			}
		}
		return 0
	}
	get := func(c *client) digest {
		st, b := c.get("/api/v1/analytics/digest?range=24h")
		if st != 200 {
			t.Fatalf("%d %s", st, b)
		}
		var d digest
		if err := json.Unmarshal(b, &d); err != nil {
			t.Fatal(err)
		}
		return d
	}

	o := get(w.owner)
	if count(o, "fail2ban.ban") != 2 || count(o, "firewall.rules_changed") != 1 || count(o, "port.public_reachable") != 1 || !o.Security || o.DNS == nil {
		t.Fatalf("owner: %+v", o)
	}
	// A panel role sees the linked server's events only, and has no DNS part.
	v := get(w.viewer)
	if count(v, "fail2ban.ban") != 2 || count(v, "port.public_reachable") != 0 || v.DNS != nil {
		t.Fatalf("viewer: %+v", v)
	}
	if st, _ := w.owner.get("/api/v1/analytics/digest?range=nope"); st != 400 {
		t.Fatalf("a bad range answered %d", st)
	}
}
