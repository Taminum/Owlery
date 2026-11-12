package httpapi

import (
	"context"
	"strings"
	"testing"

	"github.com/Taminum/Owlery/internal/secproto"
)

func TestLinuxCtlNeedsTheHelperAnAdministratorAndLeavesAnAuditTrailForChangesJournalsAndFiles(t *testing.T) {
	w := newAgentWorld(t)
	ctx := context.Background()
	hub := w.h.srv.SecOps
	id := mkVPS(t, w, "box", "203.0.113.82", w.work.ID)
	caps := []string{"hardware_read"}
	ag, err := w.h.st.CreateSecAgent(ctx, id, "", []byte{8})
	if err != nil {
		t.Fatal(err)
	}
	hello := func(c []string) {
		if _, err := w.h.st.SecAgentHello(ctx, ag.ID, "e", "v0.5.24", "h", c); err != nil {
			t.Fatal(err)
		}
	}
	hello(caps)
	url := "/api/v1/servers/" + id + "/linux"
	post := func(c *client, body map[string]any) (int, []byte) { return c.do("POST", url, body) }

	if st, b := post(w.owner, map[string]any{"op": "list"}); st != 409 || errCode(b) != "agent_offline" {
		t.Errorf("offline: %d %s", st, b)
	}
	var asked []secproto.LinuxReq
	off := hub.Register(ag.ID, func(_ context.Context, v any) error {
		req := v.(secproto.LinuxReq)
		asked = append(asked, req)
		res := secproto.LinuxResult{Type: "linux_result", ID: req.ID, OK: true, Code: "ok"}
		switch req.Op {
		case secproto.LinuxList:
			res.Units = []secproto.LinuxUnit{{Name: "nginx.service", Load: "loaded", Active: "active", Sub: "running", Manage: true}}
		case secproto.LinuxCat:
			if req.Path == "/etc/shadow" {
				res.OK, res.Code = false, "not_allowed"
			} else {
				res.Text = "line one\n"
			}
		case secproto.LinuxRestart:
			res.Active = "active"
		case secproto.LinuxJournal:
			res.Text = "started\n"
		case secproto.LinuxLs:
			res.Dirs = []string{"/var/log"}
		}
		go hub.DeliverLinux(ag.ID, res)
		return nil
	})
	defer off()
	if st, b := post(w.owner, map[string]any{"op": "list"}); st != 409 || errCode(b) != "not_enabled" {
		t.Errorf("an agent without the helper: %d %s", st, b)
	}
	hello(append(caps, secproto.CapLinuxCtl))
	if _, b := w.owner.get("/api/v1/servers/" + id); !strings.Contains(string(b), `"can_linux":true`) {
		t.Errorf("the card must say it is on: %s", b)
	}
	if st, _ := post(w.viewer, map[string]any{"op": "list"}); st != 403 {
		t.Errorf("a viewer must not look: %d", st)
	}
	for _, bad := range []map[string]any{
		{"op": "exec"}, {"op": "restart", "name": "nginx"}, {"op": "restart", "name": "-x.service"}, {"op": "journal", "name": "a b.service"}, {"op": "cat"},
	} {
		if st, b := post(w.owner, bad); st != 422 {
			t.Errorf("%v: %d %s", bad, st, b)
		}
	}
	if st, b := post(w.owner, map[string]any{"op": "list"}); st != 200 || !strings.Contains(string(b), "nginx.service") {
		t.Fatalf("list: %d %s", st, b)
	}
	if st, b := post(w.owner, map[string]any{"op": "ls"}); st != 200 || !strings.Contains(string(b), "/var/log") || !strings.Contains(string(b), `"entries":[]`) {
		t.Fatalf("ls: %d %s", st, b)
	}
	if st, b := post(w.owner, map[string]any{"op": "restart", "name": "nginx.service"}); st != 200 || !strings.Contains(string(b), `"active":"active"`) {
		t.Fatalf("restart: %d %s", st, b)
	}
	if st, b := post(w.owner, map[string]any{"op": "journal", "name": "nginx.service", "tail": 50}); st != 200 || !strings.Contains(string(b), "started") {
		t.Fatalf("journal: %d %s", st, b)
	}
	if st, b := post(w.owner, map[string]any{"op": "cat", "path": "/var/log/syslog"}); st != 200 || !strings.Contains(string(b), "line one") {
		t.Fatalf("cat: %d %s", st, b)
	}
	if st, b := post(w.owner, map[string]any{"op": "cat", "path": "/etc/shadow"}); st != 403 || errCode(b) != "not_allowed" {
		t.Fatalf("a path the machine refuses: %d %s", st, b)
	}
	last := asked[len(asked)-1]
	if last.Op != "cat" || last.Path != "/etc/shadow" {
		t.Errorf("%+v", last)
	}
	var n int
	if err := w.h.st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action IN ('linux.restart','linux.journal','linux.cat')`).Scan(&n); err != nil || n != 4 {
		t.Errorf("a change, a journal and two files must be in the audit log: %d %v", n, err)
	}
	if err := w.h.st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action IN ('linux.list','linux.ls')`).Scan(&n); err != nil || n != 0 {
		t.Errorf("a plain list must not be: %d %v", n, err)
	}
}
