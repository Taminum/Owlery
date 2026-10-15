package httpapi

import (
	"encoding/json"
	"testing"
)

func TestVPSByAddressLinksOnlyRegisteredAddressesTheCallerCanSee(t *testing.T) {
	w := newAgentWorld(t)
	mkVPS(t, w, "Linked", "203.0.113.50", w.work.ID)
	mkVPS(t, w, "Private", "203.0.113.51", "")

	type resp struct {
		Items map[string]struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	ask := func(c *client, q string) (int, resp) {
		st, b := c.get("/api/v1/security/vps-by-address?" + q)
		var r resp
		_ = json.Unmarshal(b, &r)
		return st, r
	}
	st, r := ask(w.owner, "a=203.0.113.50&a=203.0.113.51&a=203.0.113.52&a=::ffff:203.0.113.50")
	if st != 200 || len(r.Items) != 2 || r.Items["203.0.113.50"].Name != "Linked" || r.Items["203.0.113.51"].Name != "Private" {
		t.Fatalf("%d %+v", st, r)
	}
	// A network neighbour of a server is not the server.
	if _, r := ask(w.owner, "a=203.0.113.53"); len(r.Items) != 0 {
		t.Fatalf("%+v", r)
	}
	// A panel role sees only the servers linked to its panels.
	if _, r := ask(w.viewer, "a=203.0.113.50&a=203.0.113.51"); len(r.Items) != 1 || r.Items["203.0.113.50"].Name != "Linked" {
		t.Fatalf("%+v", r)
	}
	if st, _ := ask(w.owner, "a=not-an-ip"); st != 400 {
		t.Fatalf("%d", st)
	}
}
