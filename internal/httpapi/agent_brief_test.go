package httpapi

import (
	"context"
	"testing"
)

func TestServerListCarriesTheVersionOfItsAgentAndWhetherItMayBeUpdated(t *testing.T) {
	w := newAgentWorld(t)
	id := mkVPS(t, w, "office-2", "203.0.113.42", w.work.ID)
	st := w.h.st
	ctx := context.Background()

	type brief struct {
		Agent *struct {
			Version   string `json:"version"`
			Online    bool   `json:"online"`
			CanUpdate bool   `json:"can_update"`
		} `json:"agent"`
	}
	get := func() brief {
		t.Helper()
		code, body := w.owner.get("/api/v1/servers/" + id)
		if code != 200 {
			t.Fatalf("card: %d %s", code, body)
		}
		return parse[brief](t, body)
	}
	if get().Agent != nil {
		t.Error("a machine without an agent has no agent word")
	}
	ag, err := st.CreateSecAgent(ctx, id, "", []byte("h"))
	if err != nil {
		t.Fatal(err)
	}
	if b := get(); b.Agent == nil || b.Agent.Online || b.Agent.CanUpdate || b.Agent.Version != "" {
		t.Errorf("an agent that has not spoken yet: %+v", b.Agent)
	}
	if _, err := st.SecAgentHello(ctx, ag.ID, "e1", "v0.5.15", "box", []string{"shell"}); err != nil {
		t.Fatal(err)
	}
	if err := st.TouchSecAgent(ctx, ag.ID); err != nil {
		t.Fatal(err)
	}
	if b := get(); b.Agent == nil || b.Agent.Version != "v0.5.15" || !b.Agent.Online || b.Agent.CanUpdate {
		t.Errorf("connected, but the machine did not allow updates: %+v", b.Agent)
	}
	if _, err := st.SecAgentHello(ctx, ag.ID, "e1", "v0.5.15", "box", []string{"shell", "self_update"}); err != nil {
		t.Fatal(err)
	}
	if b := get(); b.Agent == nil || !b.Agent.CanUpdate {
		t.Errorf("the machine allowed updates: %+v", b.Agent)
	}
	if err := st.RevokeSecAgent(ctx, id); err != nil {
		t.Fatal(err)
	}
	if get().Agent != nil {
		t.Error("a revoked agent says nothing")
	}
}
