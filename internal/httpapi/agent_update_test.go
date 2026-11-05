package httpapi

import (
	"context"
	"testing"

	"github.com/Taminum/Owlery/internal/secproto"
)

func TestUpdatingAnAgentFromTheCard(t *testing.T) {
	w := newAgentWorld(t)
	id := mkVPS(t, w, "exit-nl", "203.0.113.51", w.work.ID)
	ctx := context.Background()
	st := w.h.st
	hub := w.h.srv.SecOps
	w.h.srv.LatestRelease = func(context.Context) (string, error) { return "v0.5.15", nil }

	ag, err := st.CreateSecAgent(ctx, id, "", []byte("h"))
	if err != nil {
		t.Fatal(err)
	}
	connect := func(caps []string, version string, answer secproto.UpdateResult) *[]secproto.UpdateReq {
		if _, err := st.SecAgentHello(ctx, ag.ID, "e", version, "h", caps); err != nil {
			t.Fatal(err)
		}
		var got []secproto.UpdateReq
		hub.Register(ag.ID, func(_ context.Context, v any) error {
			req := v.(secproto.UpdateReq)
			got = append(got, req)
			answer.ID = req.ID
			go hub.DeliverUpdate(ag.ID, answer)
			return nil
		})
		return &got
	}
	post := func(c *client, body any) (int, []byte) {
		return c.do("POST", "/api/v1/security/vps/"+id+"/agent/update", body)
	}
	code := func(b []byte) string {
		return parse[struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}](t, b).Error.Code
	}

	// Not connected: nothing to ask.
	if st, b := post(w.owner, map[string]string{"version": "v0.5.15"}); st != 409 || code(b) != "agent_offline" {
		t.Errorf("offline: %d %s", st, b)
	}
	// Connected, but the machine did not allow updates.
	got := connect([]string{"hardware_read"}, "v0.5.14", secproto.UpdateResult{Type: "update_result", OK: true})
	if st, b := post(w.owner, map[string]string{"version": "v0.5.15"}); st != 409 || code(b) != "update_not_allowed" {
		t.Errorf("not allowed: %d %s", st, b)
	}
	if len(*got) != 0 {
		t.Error("nothing was sent to a machine that did not allow it")
	}
	// Allowed.
	got = connect([]string{"hardware_read", secproto.CapSelfUpdate}, "v0.5.14", secproto.UpdateResult{Type: "update_result", OK: true})
	if st, _ := post(w.viewer, map[string]string{"version": "v0.5.15"}); st == 200 {
		t.Error("a viewer may not update an agent")
	}
	if st, b := post(w.owner, map[string]string{"version": "v0.5.15"}); st != 200 {
		t.Fatalf("update: %d %s", st, b)
	}
	if len(*got) != 1 || (*got)[0].Version != "v0.5.15" || (*got)[0].Type != "update_req" {
		t.Errorf("the agent was asked: %+v", *got)
	}
	// Empty or "latest" is the newest release; the server picks the number, not the caller.
	if st, _ := post(w.owner, map[string]string{}); st != 200 {
		t.Errorf("newest: %d", st)
	}
	if len(*got) != 2 || (*got)[1].Version != "v0.5.15" {
		t.Errorf("the newest: %+v", *got)
	}
	// Not newer, not a version, not a number at all.
	for _, c := range []struct {
		version, code string
		status        int
	}{{"v0.5.14", "up_to_date", 409}, {"v0.5.13", "up_to_date", 409}, {"../etc", "invalid_version", 422}, {"v1", "invalid_version", 422}} {
		if s, b := post(w.owner, map[string]string{"version": c.version}); s != c.status || code(b) != c.code {
			t.Errorf("%q: %d %s", c.version, s, b)
		}
	}
	// The agent refuses: its own words come back.
	connect([]string{secproto.CapSelfUpdate}, "v0.5.14", secproto.UpdateResult{Type: "update_result", OK: false, Error: "the signature does not match"})
	if s, b := post(w.owner, map[string]string{"version": "v0.5.15"}); s != 409 || code(b) != "update_failed" {
		t.Errorf("refused: %d %s", s, b)
	}
}

func TestTheNewestReleaseIsLookedUpForTheCard(t *testing.T) {
	w := newAgentWorld(t)
	w.h.srv.LatestRelease = func(context.Context) (string, error) { return "v0.5.15", nil }
	st, b := w.owner.get("/api/v1/agent/latest")
	if st != 200 || parse[struct {
		Version string `json:"version"`
	}](t, b).Version != "v0.5.15" {
		t.Errorf("%d %s", st, b)
	}
}
