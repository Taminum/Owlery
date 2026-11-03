package httpapi

import (
	"testing"
	"time"
)

func TestFleetSummaryCountsTheWindowAndHidesSignInsFromPeople(t *testing.T) {
	w := newAgentWorld(t)
	a := mkVPS(t, w, "exit-a", "203.0.113.1", w.work.ID)
	b := mkVPS(t, w, "exit-b", "203.0.113.2", w.work.ID)
	now := time.Now().UTC()
	addEvent(t, w, a, "fail2ban", "fail2ban.ban", "info", `{"jail":"sshd","ip":"198.51.100.1"}`, now.Add(-time.Hour))
	addEvent(t, w, a, "fail2ban", "fail2ban.ban", "info", `{"jail":"sshd","ip":"198.51.100.2"}`, now.Add(-2*time.Hour))
	addEvent(t, w, a, "fail2ban", "fail2ban.ban", "info", `{"jail":"sshd","ip":"198.51.100.3"}`, now.Add(-3*time.Hour))
	addEvent(t, w, b, "fail2ban", "fail2ban.bans_unobserved", "info", `{"jail":"sshd","count":5}`, now.Add(-4*time.Hour))
	addEvent(t, w, a, "fail2ban", "fail2ban.ban", "info", `{"jail":"sshd","ip":"198.51.100.9"}`, now.Add(-72*time.Hour)) // before the window
	addEvent(t, w, a, "firewall", "firewall.rules_changed", "warning", `{}`, now.Add(-time.Hour))
	if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO audit_log (action, object_type, ts) VALUES ('auth.login', 'account', now() - interval '1 hour'), ('auth.login_failed', 'account', now() - interval '1 hour'), ('terminal.open', 'server', now() - interval '1 hour')`); err != nil {
		t.Fatal(err)
	}

	st, body := w.owner.get("/api/v1/summary")
	if st != 200 {
		t.Fatalf("summary: %d %s", st, body)
	}
	got := parse[struct {
		Bans struct {
			Total   int `json:"total"`
			Servers []struct {
				Name  string `json:"name"`
				Count int    `json:"count"`
			} `json:"servers"`
		} `json:"bans"`
		Changes struct {
			Total int `json:"total"`
		} `json:"changes"`
		Owlery *struct {
			Logins    int `json:"logins"`
			Failed    int `json:"failed_logins"`
			Terminals int `json:"terminals"`
		} `json:"owlery"`
		Hourly []struct {
			Bans    int `json:"bans"`
			Changes int `json:"changes"`
			Access  int `json:"access"`
		} `json:"hourly"`
		TopIPs []struct {
			IP    string `json:"ip"`
			Jail  string `json:"jail"`
			Count int    `json:"count"`
		} `json:"top_ips"`
		Jails []struct {
			Name  string `json:"name"`
			Count int    `json:"count"`
		} `json:"jails"`
		Recent []struct {
			Server string `json:"server"`
			Type   string `json:"type"`
		} `json:"recent"`
	}](t, body)
	if got.Bans.Total != 8 || len(got.Bans.Servers) != 2 || got.Bans.Servers[0].Name != "exit-b" || got.Bans.Servers[0].Count != 5 || got.Bans.Servers[1].Count != 3 {
		t.Errorf("bans: %s", body)
	}
	if got.Changes.Total != 1 {
		t.Errorf("changes: %s", body)
	}
	if got.Owlery == nil || got.Owlery.Logins != 1 || got.Owlery.Failed != 1 || got.Owlery.Terminals != 1 {
		t.Errorf("owner should see what people did in Owlery: %s", body)
	}
	var hb, hc, ha int
	for _, h := range got.Hourly {
		hb, hc, ha = hb+h.Bans, hc+h.Changes, ha+h.Access
	}
	if len(got.Hourly) < 24 || hb != 8 || hc != 1 || ha != 1 {
		t.Errorf("hourly should hold every hour of the window and add up to the totals (bans %d, changes %d, access %d, %d hours): %s", hb, hc, ha, len(got.Hourly), body)
	}
	if len(got.TopIPs) != 3 || got.TopIPs[0].Jail != "sshd" || got.TopIPs[0].Count != 1 {
		t.Errorf("top addresses: %s", body)
	}
	if len(got.Jails) != 1 || got.Jails[0].Name != "sshd" || got.Jails[0].Count != 8 {
		t.Errorf("jails: %s", body)
	}
	if len(got.Recent) != 1 || got.Recent[0].Type != "firewall.rules_changed" || got.Recent[0].Server != "exit-a" {
		t.Errorf("recent should skip single bans: %s", body)
	}

	// A person who is not the owner sees the machines they may see, but never the sign-in counts.
	_, vb := w.viewer.get("/api/v1/summary")
	seen := parse[struct {
		Owlery *struct{} `json:"owlery"`
	}](t, vb)
	if seen.Owlery != nil {
		t.Errorf("a viewer must not see sign-ins: %s", vb)
	}
}
