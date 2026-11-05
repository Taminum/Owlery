package httpapi

import (
	"context"
	"testing"
)

func TestServerListCarriesTheAddressItsAgentConnectedFrom(t *testing.T) {
	w := newAgentWorld(t)
	id := mkVPS(t, w, "office-1", "203.0.113.41", w.work.ID)
	st := w.h.st
	ctx := context.Background()

	ip := func() string {
		t.Helper()
		code, body := w.owner.get("/api/v1/servers/" + id)
		if code != 200 {
			t.Fatalf("card: %d %s", code, body)
		}
		return parse[struct {
			ExternalIP string `json:"external_ip"`
		}](t, body).ExternalIP
	}
	if ip() != "" {
		t.Error("a machine without an agent has no address to show")
	}
	ag, err := st.CreateSecAgent(ctx, id, "", []byte("h"))
	if err != nil {
		t.Fatal(err)
	}
	if ip() != "" {
		t.Error("an agent that has not connected has none either")
	}
	if err := st.SetSecAgentRemoteIP(ctx, ag.ID, "::ffff:198.51.100.7"); err != nil {
		t.Fatal(err)
	}
	if got := ip(); got != "198.51.100.7" {
		t.Errorf("a mapped address is shown as the plain one: %q", got)
	}
	if err := st.SetSecAgentRemoteIP(ctx, ag.ID, "invalid IP"); err != nil {
		t.Fatal(err)
	}
	if got := ip(); got != "" {
		t.Errorf("what is not an address is not kept: %q", got)
	}
	if err := st.SetSecAgentRemoteIP(ctx, ag.ID, "198.51.100.8"); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeSecAgent(ctx, id); err != nil {
		t.Fatal(err)
	}
	if got := ip(); got != "" {
		t.Errorf("a revoked agent says nothing: %q", got)
	}
}
