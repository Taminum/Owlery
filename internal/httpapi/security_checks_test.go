package httpapi

import (
	"encoding/json"
	"testing"
)

func TestSecurityChecksTargetsScopeAndRateLimit(t *testing.T) {
	w := newAgentWorld(t)
	_, b := w.owner.do("POST", "/api/v1/security/vps", map[string]any{"name": "Helsinki", "addresses": []string{"203.0.113.7", "fi.example.com"}})
	v := parse[vpsResp](t, b)
	base := "/api/v1/security/vps/" + v.ID
	// Link it to Work so that Work's roles can see it.
	if st, _ := w.owner.do("POST", base+"/links", map[string]any{"panel_id": w.work.ID}); st != 201 {
		t.Fatal(st)
	}

	// Only a registered address or domain can be checked, and the input is validated.
	post := func(c *client, path string, body map[string]any) (int, []byte) { return c.do("POST", base+path, body) }
	if st, b := post(w.owner, "/public-ports", map[string]any{"host": "198.51.100.9", "port": 443}); st != 422 || errCode(b) != "host_not_registered" {
		t.Errorf("an unregistered host: %d %s", st, b)
	}
	for name, body := range map[string]map[string]any{
		"port 0": {"host": "203.0.113.7", "port": 0}, "port big": {"host": "203.0.113.7", "port": 70000},
		"cidr": {"host": "203.0.113.0/24", "port": 80}, "url junk": {"host": "not a host!", "port": 80},
	} {
		if st, _ := post(w.owner, "/public-ports", body); st != 422 {
			t.Errorf("%s: %d", name, st)
		}
	}
	st, b := post(w.owner, "/public-ports", map[string]any{"host": "203.0.113.7", "port": 443, "expected": true})
	if st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	ep := parse[struct {
		ID       string `json:"id"`
		Expected bool   `json:"expected"`
		Source   string `json:"source"`
	}](t, b)
	if !ep.Expected || ep.Source != "manual" {
		t.Fatalf("%+v", ep)
	}
	// Adding the same one again updates it instead of failing or duplicating.
	if st, _ := post(w.owner, "/public-ports", map[string]any{"host": "203.0.113.7", "port": 443, "expected": false}); st != 201 {
		t.Errorf("%d", st)
	}
	if st, b := w.owner.do("PATCH", base+"/public-ports/"+ep.ID, map[string]any{"enabled": false}); st != 200 {
		t.Errorf("%d %s", st, b)
	}

	// Reads say where the check runs from and that it is not independent; coverage says only known endpoints.
	_, lb := w.viewer.get(base + "/public-ports")
	list := parse[struct {
		Items   []map[string]any `json:"items"`
		Vantage struct {
			ID          string `json:"id"`
			Independent bool   `json:"independent"`
		} `json:"vantage"`
		Coverage struct {
			Kind      string `json:"kind"`
			Discovery string `json:"discovery"`
		} `json:"coverage"`
	}](t, lb)
	if len(list.Items) != 1 || list.Vantage.ID != "api_server" || list.Vantage.Independent || list.Coverage.Kind != "known_endpoints" || list.Coverage.Discovery != "off" {
		t.Fatalf("%+v", list)
	}
	// A viewer may read, not change.
	if st, _ := w.viewer.do("POST", base+"/public-ports", map[string]any{"host": "203.0.113.7", "port": 80}); st != 403 {
		t.Errorf("viewer add: %d", st)
	}
	if st, _ := w.op.do("POST", base+"/checks/ports/run", nil); st != 403 {
		t.Errorf("operator manual run: %d", st)
	}

	// TLS: SNI must be a domain, a repeat is a conflict, an unregistered host is refused.
	if st, _ := post(w.adm, "/tls", map[string]any{"host": "fi.example.com", "port": 443, "sni": "https://x"}); st != 422 {
		t.Errorf("bad sni: %d", st)
	}
	if st, _ := post(w.adm, "/tls", map[string]any{"host": "evil.example.net", "port": 443}); st != 422 {
		t.Errorf("unregistered: %d", st)
	}
	if st, b := post(w.adm, "/tls", map[string]any{"host": "FI.example.com", "port": 443}); st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	if st, _ := post(w.adm, "/tls", map[string]any{"host": "fi.example.com", "port": 443}); st != 409 {
		t.Errorf("duplicate: %d", st)
	}
	_, tb := w.viewer.get(base + "/tls")
	if tl := parse[struct {
		Items   []map[string]any `json:"items"`
		Vantage struct {
			Independent bool `json:"independent"`
		} `json:"vantage"`
	}](t, tb); len(tl.Items) != 1 || tl.Vantage.Independent || tl.Items[0]["last_state"] != nil {
		t.Fatalf("an unchecked endpoint must show no state: %+v", tl)
	}

	// A manual run is accepted, then limited; an unknown kind is not found.
	if st, b := post(w.adm, "/checks/ports/run", nil); st != 202 {
		t.Fatalf("%d %s", st, b)
	}
	if st, _ := post(w.adm, "/checks/ports/run", nil); st != 429 {
		t.Errorf("a second run at once: %d", st)
	}
	if st, _ := post(w.adm, "/checks/tls/run", nil); st != 202 {
		t.Errorf("another kind has its own allowance: %d", st)
	}
	if st, _ := post(w.adm, "/checks/shell/run", nil); st != 404 {
		t.Errorf("unknown kind: %d", st)
	}

	// An unlinked server is invisible to a panel admin, for every one of these routes.
	_, ub := w.owner.do("POST", "/api/v1/security/vps", map[string]any{"name": "Private", "addresses": []string{"203.0.113.50"}})
	pv := parse[vpsResp](t, ub)
	for _, p := range []string{"/public-ports", "/tls"} {
		if st, _ := w.adm.get("/api/v1/security/vps/" + pv.ID + p); st != 404 {
			t.Errorf("%s: %d", p, st)
		}
	}
	if st, _ := w.adm.do("POST", "/api/v1/security/vps/"+pv.ID+"/checks/ports/run", nil); st != 404 {
		t.Errorf("manual run on an invisible server: %d", st)
	}
}

func TestDiscoveryScanIsOffUntilAnAdministratorTurnsItOn(t *testing.T) {
	w := newAgentWorld(t)
	v := mkVPS(t, w, "Scan", "203.0.113.60", w.work.ID)
	base := "/api/v1/security/vps/" + v
	type vpsScan struct {
		DiscoveryScan bool `json:"discovery_scan"`
	}
	_, b := w.owner.get(base)
	if parse[vpsScan](t, b).DiscoveryScan {
		t.Fatal("the scan must start off")
	}
	if st, _ := w.viewer.do("PATCH", base, map[string]any{"discovery_scan": true}); st != 403 {
		t.Fatalf("a viewer turned the scan on: %d", st)
	}
	st, b := w.owner.do("PATCH", base, map[string]any{"discovery_scan": true})
	if st != 200 || !parse[vpsScan](t, b).DiscoveryScan {
		t.Fatalf("%d %s", st, b)
	}
	_, pb := w.owner.get(base + "/public-ports")
	var ports struct {
		Coverage struct {
			Discovery string `json:"discovery"`
		} `json:"coverage"`
	}
	if err := json.Unmarshal(pb, &ports); err != nil || ports.Coverage.Discovery != "on" {
		t.Fatalf("%s", pb)
	}
	// Other fields leave it alone.
	st, b = w.owner.do("PATCH", base, map[string]any{"note": "x"})
	if st != 200 || !parse[vpsScan](t, b).DiscoveryScan {
		t.Fatalf("%d %s", st, b)
	}
}
