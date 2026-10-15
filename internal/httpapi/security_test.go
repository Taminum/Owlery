package httpapi

import (
	"testing"

	"github.com/Taminum/RemnaScope/internal/store"
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
