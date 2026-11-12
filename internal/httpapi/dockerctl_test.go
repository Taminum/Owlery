package httpapi

import (
	"context"
	"strings"
	"testing"

	"github.com/Taminum/Owlery/internal/secproto"
)

func TestDockerLogsAndRestartNeedTheHelperAnAdministratorAndLeaveAnAuditTrail(t *testing.T) {
	w := newAgentWorld(t)
	ctx := context.Background()
	hub := w.h.srv.SecOps
	id := mkVPS(t, w, "box", "203.0.113.81", w.work.ID)
	caps := []string{"hardware_read"}
	ag, err := w.h.st.CreateSecAgent(ctx, id, "", []byte{7})
	if err != nil {
		t.Fatal(err)
	}
	hello := func(c []string) {
		if _, err := w.h.st.SecAgentHello(ctx, ag.ID, "e", "v0.5.23", "h", c); err != nil {
			t.Fatal(err)
		}
	}
	hello(caps)
	logs := "/api/v1/servers/" + id + "/docker/remnascope-api/logs?tail=50"
	restart := "/api/v1/servers/" + id + "/docker/remnascope-api/restart"

	if st, b := w.owner.get(logs); st != 409 || errCode(b) != "agent_offline" {
		t.Errorf("offline: %d %s", st, b)
	}
	var asked []secproto.DockerReq
	off := hub.Register(ag.ID, func(_ context.Context, v any) error {
		req := v.(secproto.DockerReq)
		asked = append(asked, req)
		res := secproto.DockerResult{Type: "docker_result", ID: req.ID, OK: true, Code: "ok"}
		if req.Op == secproto.DockerLogs {
			res.Log = "2026-11-12T10:00:00Z started\n"
		} else {
			res.Running = true
		}
		go hub.DeliverDocker(ag.ID, res)
		return nil
	})
	defer off()
	if st, b := w.owner.get(logs); st != 409 || errCode(b) != "not_enabled" {
		t.Errorf("an agent without the helper: %d %s", st, b)
	}
	if _, b := w.owner.get("/api/v1/servers/" + id); !strings.Contains(string(b), `"docker_ctl":false`) {
		t.Errorf("the card must say it is off: %s", b)
	}
	hello(append(caps, secproto.CapDockerCtl))
	if _, b := w.owner.get("/api/v1/servers/" + id); !strings.Contains(string(b), `"docker_ctl":true`) {
		t.Errorf("the card must say it is on: %s", b)
	}
	if st, _ := w.viewer.get(logs); st != 403 {
		t.Errorf("a viewer must not read logs: %d", st)
	}
	if st, _ := w.viewer.do("POST", restart, nil); st != 403 {
		t.Errorf("a viewer must not restart: %d", st)
	}
	if st, b := w.owner.get("/api/v1/servers/" + id + "/docker/bad%20name/logs"); st != 422 {
		t.Errorf("a bad name: %d %s", st, b)
	}
	st, b := w.owner.get(logs)
	if st != 200 || !strings.Contains(string(b), "started") {
		t.Fatalf("logs: %d %s", st, b)
	}
	if asked[len(asked)-1].Tail != 50 || asked[len(asked)-1].Name != "remnascope-api" {
		t.Errorf("%+v", asked[len(asked)-1])
	}
	st, b = w.owner.do("POST", restart, nil)
	if st != 200 || !strings.Contains(string(b), `"running":true`) {
		t.Fatalf("restart: %d %s", st, b)
	}
	var n int
	if err := w.h.st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action IN ('docker.logs','docker.restart')`).Scan(&n); err != nil || n != 2 {
		t.Errorf("both must be in the audit log: %d %v", n, err)
	}
}
