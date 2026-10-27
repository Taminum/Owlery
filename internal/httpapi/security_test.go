package httpapi

import (
	"testing"

	"github.com/Taminum/Owlery/internal/store"
)

type vpsResp struct {
	store.VPS
	CanEdit bool `json:"can_edit"`
}

type vpsList struct {
	Items     []vpsResp `json:"items"`
	CanCreate bool      `json:"can_create"`
}

func TestSecurityVPSScopeRolesAndLinks(t *testing.T) {
	w := newAgentWorld(t)
	create := func(c *client, name string, addrs ...string) (int, []byte) {
		return c.do("POST", "/api/v1/security/vps", map[string]any{"name": name, "addresses": addrs})
	}

	// Only the owner adds a server; anonymous callers and panel roles cannot.
	st, b := create(w.owner, "Helsinki", "203.0.113.7", "2001:db8::1", "FI.Example.com")
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	helsinki := parse[vpsResp](t, b)
	if len(helsinki.Addresses) != 3 || !helsinki.CanEdit {
		t.Fatalf("%+v", helsinki)
	}
	kinds := map[string]string{}
	for _, a := range helsinki.Addresses {
		kinds[a.Address] = a.Kind
	}
	if kinds["203.0.113.7"] != "ipv4" || kinds["2001:db8::1"] != "ipv6" || kinds["fi.example.com"] != "domain" {
		t.Fatalf("addresses were not normalised: %v", kinds)
	}
	for who, c := range map[string]*client{"admin": w.adm, "operator": w.op, "viewer": w.viewer} {
		if st, _ := create(c, "x-"+who); st != 403 {
			t.Errorf("%s may not create: %d", who, st)
		}
	}
	if st, _ := create(w.h.anon(), "anon"); st != 401 {
		t.Errorf("anonymous: %d", st)
	}
	if st, _ := create(w.owner, "helsinki"); st != 409 {
		t.Errorf("a name is unique case-insensitively: %d", st)
	}
	for name, addr := range map[string]string{"cidr": "10.0.0.0/8", "asn": "AS15169", "junk": "not a host!"} {
		if st, _ := create(w.owner, "bad-"+name, addr); st != 422 {
			t.Errorf("%s as an address: %d", name, st)
		}
	}

	// A manual server with no links is the owner's: nobody else can see it, and it looks absent.
	_, lb := w.adm.get("/api/v1/security/vps")
	if l := parse[vpsList](t, lb); len(l.Items) != 0 || l.CanCreate {
		t.Fatalf("an unlinked server leaked: %+v", l)
	}
	if st, _ := w.adm.get("/api/v1/security/vps/" + helsinki.ID); st != 404 {
		t.Errorf("unlinked server for a panel admin: %d", st)
	}

	// Linking needs an administrator of that panel, and a node must belong to its panel.
	workNode := nodeID(t, w.owner, w.work.ID, "work-1")
	homeNode := nodeID(t, w.owner, w.home.ID, "home-a")
	link := func(c *client, panel, node string) (int, []byte) {
		return c.do("POST", "/api/v1/security/vps/"+helsinki.ID+"/links", map[string]any{"panel_id": panel, "node_id": node})
	}
	if st, b := link(w.owner, w.work.ID, workNode); st != 201 {
		t.Fatalf("owner links a node: %d %s", st, b)
	}
	if st, _ := link(w.owner, w.work.ID, workNode); st != 409 {
		t.Errorf("a link twice: %d", st)
	}
	if st, _ := link(w.owner, w.work.ID, homeNode); st != 404 {
		t.Errorf("a node of another panel: %d", st)
	}
	if st, b := link(w.owner, w.work.ID, ""); st != 201 {
		t.Fatalf("link the panel itself: %d %s", st, b)
	}

	// Now the Work admin sees it and can change it; the viewer sees it read-only.
	_, ab := w.adm.get("/api/v1/security/vps/" + helsinki.ID)
	if v := parse[vpsResp](t, ab); !v.CanEdit || len(v.Links) != 2 {
		t.Fatalf("%+v", v)
	}
	_, vb := w.viewer.get("/api/v1/security/vps/" + helsinki.ID)
	if v := parse[vpsResp](t, vb); v.CanEdit {
		t.Fatalf("viewer can edit: %+v", v)
	}
	if st, _ := w.viewer.do("PATCH", "/api/v1/security/vps/"+helsinki.ID, map[string]any{"name": "nope"}); st != 403 {
		t.Errorf("viewer patch: %d", st)
	}
	if st, b := w.adm.do("PATCH", "/api/v1/security/vps/"+helsinki.ID, map[string]any{"note": "edge", "addresses": []string{"203.0.113.7"}}); st != 200 {
		t.Fatalf("admin patch: %d %s", st, b)
	} else if v := parse[vpsResp](t, b); v.Note != "edge" || len(v.Addresses) != 1 {
		t.Fatalf("%+v", v)
	}
	if st, _ := w.adm.do("DELETE", "/api/v1/security/vps/"+helsinki.ID, nil); st != 403 {
		t.Errorf("only the owner archives: %d", st)
	}
	// Linking someone else's panel is refused even to an administrator elsewhere.
	if st, _ := link(w.adm, w.home.ID, ""); st != 404 {
		t.Errorf("a panel out of scope: %d", st)
	}

	// An unlink, then archive: the server disappears from every list.
	_, gb := w.owner.get("/api/v1/security/vps/" + helsinki.ID)
	first := parse[vpsResp](t, gb).Links[0].ID
	if st, _ := w.adm.do("DELETE", "/api/v1/security/vps/"+helsinki.ID+"/links/"+first, nil); st != 204 {
		t.Errorf("unlink: %d", st)
	}
	if st, _ := w.owner.do("DELETE", "/api/v1/security/vps/"+helsinki.ID, nil); st != 204 {
		t.Fatalf("archive: %d", st)
	}
	if st, _ := w.owner.get("/api/v1/security/vps/" + helsinki.ID); st != 404 {
		t.Errorf("archived server still visible: %d", st)
	}
	if st, _ := create(w.owner, "Helsinki"); st != 201 {
		t.Errorf("an archived name can be reused: %d", st)
	}
}

func TestServerCardsCarryTheFail2banCountWithItsFreshness(t *testing.T) {
	w := newAgentWorld(t)
	none := mkVPS(t, w, "NoAgent", "203.0.113.1", "")
	live := mkVPS(t, w, "Live", "203.0.113.2", "")
	old := mkVPS(t, w, "Old", "203.0.113.3", "")
	denied := mkVPS(t, w, "Denied", "203.0.113.4", "")
	for _, id := range []string{live, old, denied} {
		if st, _ := w.owner.do("POST", "/api/v1/security/vps/"+id+"/agent", nil); st != 201 {
			t.Fatal(st)
		}
	}
	snap := func(vps, status, data string, receivedAgo string) {
		if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO security_snapshot_state (vps_id, category, status, source_hash, observed_at, received_at, data)
			VALUES ($1,'fail2ban',$2,'h', now() - $4::interval, now() - $4::interval, $3::jsonb)`, vps, status, data, receivedAgo); err != nil {
			t.Fatal(err)
		}
	}
	two := `{"jails":[{"name":"sshd","currently_banned":2,"total_banned":40,"banned_ips":["1.1.1.1","2.2.2.2"]},{"name":"nginx","currently_banned":1,"total_banned":5,"banned_ips":["3.3.3.3"]}]}`
	snap(live, "ok", two, "10 seconds")
	snap(old, "ok", two, "1 hour")
	snap(denied, "permission_denied", `{}`, "10 seconds")
	if _, err := w.h.st.Pool().Exec(ctx, `UPDATE security_agents SET last_seen = now() WHERE vps_id = $1`, live); err != nil {
		t.Fatal(err)
	}

	_, b := w.owner.get("/api/v1/security/vps")
	var list struct {
		Items []struct {
			ID      string `json:"id"`
			Summary struct {
				Agent    string `json:"agent"`
				Fail2ban struct {
					State       string `json:"state"`
					Banned      int    `json:"banned"`
					TotalBanned int    `json:"total_banned"`
					Jails       int    `json:"jails"`
				} `json:"fail2ban"`
			} `json:"summary"`
		} `json:"items"`
	}
	list = parse[struct {
		Items []struct {
			ID      string `json:"id"`
			Summary struct {
				Agent    string `json:"agent"`
				Fail2ban struct {
					State       string `json:"state"`
					Banned      int    `json:"banned"`
					TotalBanned int    `json:"total_banned"`
					Jails       int    `json:"jails"`
				} `json:"fail2ban"`
			} `json:"summary"`
		} `json:"items"`
	}](t, b)
	by := map[string]int{}
	for i, it := range list.Items {
		by[it.ID] = i
	}
	get := func(id string) (string, string, int, int, int) {
		s := list.Items[by[id]].Summary
		return s.Agent, s.Fail2ban.State, s.Fail2ban.Banned, s.Fail2ban.TotalBanned, s.Fail2ban.Jails
	}
	if a, st, n, tot, j := get(none); a != "none" || st != "agent_required" || n != 0 {
		t.Errorf("a server with no agent shows no number: %s %s %d %d %d", a, st, n, tot, j)
	}
	if a, st, n, tot, j := get(live); a != "online" || st != "ok" || n != 3 || tot != 45 || j != 2 {
		t.Errorf("live: %s %s %d %d %d", a, st, n, tot, j)
	}
	// Old data keeps its last known number, but its state says "stale" so the screen shows it as old.
	if a, st, n, _, _ := get(old); a != "waiting" && a != "offline" || st != "stale" || n != 3 {
		t.Errorf("old data is called stale: %s %s %d", a, st, n)
	}
	if _, st, n, _, _ := get(denied); st != "permission_denied" || n != 0 {
		t.Errorf("a failed read shows no count: %s %d", st, n)
	}
}
