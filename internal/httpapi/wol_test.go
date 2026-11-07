package httpapi

import (
	"context"
	"strings"
	"testing"

	"github.com/Taminum/Owlery/internal/secproto"
)

func TestWakeOnLanKeepsAnAddressOnlyWhileOnAndWakesThroughANeighbour(t *testing.T) {
	w := newAgentWorld(t)
	ctx := context.Background()
	st := w.h.st
	hub := w.h.srv.SecOps
	target := mkVPS(t, w, "home-pc", "203.0.113.71", w.work.ID)
	helper := mkVPS(t, w, "nas", "203.0.113.72", w.work.ID)
	elsewhere := mkVPS(t, w, "far", "203.0.113.73", w.work.ID)
	caps := []string{"hardware_read", secproto.CapWol}
	var agents [3]string
	for i, id := range []string{target, helper, elsewhere} {
		ag, err := st.CreateSecAgent(ctx, id, "", []byte{byte(i + 1)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.SecAgentHello(ctx, ag.ID, "e", "v0.5.22", "h", caps); err != nil {
			t.Fatal(err)
		}
		ip := "198.51.100.1" // the same outside address: one network
		if i == 2 {
			ip = "198.51.100.99"
		}
		if err := st.SetSecAgentRemoteIP(ctx, ag.ID, ip); err != nil {
			t.Fatal(err)
		}
		agents[i] = ag.ID
	}
	var sent []secproto.WolReq
	connect := func(i int) func() {
		return hub.Register(agents[i], func(_ context.Context, v any) error {
			req := v.(secproto.WolReq)
			res := secproto.WolResult{Type: "wol_result", ID: req.ID, OK: true}
			if req.Op == secproto.WolReport {
				res.NICs = []secproto.WolNIC{{Name: "Ethernet", MAC: "AA:BB:CC:DD:EE:01", IPs: []string{"192.168.1.5"}}, {Name: "Wi-Fi", MAC: "AA:BB:CC:DD:EE:02"}}
			} else {
				sent = append(sent, req)
				res.Sent = 1
			}
			go hub.DeliverWol(agents[i], res)
			return nil
		})
	}
	put := func(c *client, body any) (int, []byte) { return c.do("PUT", "/api/v1/servers/"+target+"/wol", body) }
	wake := func(c *client) (int, []byte) { return c.do("POST", "/api/v1/servers/"+target+"/wake", nil) }

	if st, b := put(w.owner, map[string]any{"enabled": true}); st != 409 || errCode(b) != "agent_offline" {
		t.Errorf("turning it on needs the machine on: %d %s", st, b)
	}
	if st, b := wake(w.owner); st != 409 || errCode(b) != "wol_off" {
		t.Errorf("not turned on: %d %s", st, b)
	}
	offTarget := connect(0)
	if st, _ := put(w.viewer, map[string]any{"enabled": true}); st != 403 {
		t.Errorf("a viewer must not turn it on: %d", st)
	}
	if st, b := put(w.owner, map[string]any{"enabled": true, "mac": "11:22:33:44:55:66"}); st != 422 {
		t.Errorf("an address that is not the machine's: %d %s", st, b)
	}
	if st, b := put(w.owner, map[string]any{"enabled": true}); st != 200 || !strings.Contains(string(b), `"mac":"aa:bb:cc:dd:ee:01"`) {
		t.Fatalf("turn on: %d %s", st, b)
	}
	if st, b := put(w.owner, map[string]any{"enabled": true, "mac": "AA:BB:CC:DD:EE:02"}); st != 200 || !strings.Contains(string(b), `"mac":"aa:bb:cc:dd:ee:02"`) {
		t.Fatalf("choose the other card: %d %s", st, b)
	}
	if _, b := w.owner.get("/api/v1/servers/" + target); !strings.Contains(string(b), `"wol":true`) {
		t.Errorf("the card must say Wake-on-LAN is on: %s", b)
	}
	if st, _ := w.owner.do("PUT", "/api/v1/servers/"+target+"/maintenance", map[string]any{"hours": 1, "note": "update"}); st != 200 {
		t.Fatal(st)
	}
	if _, b := w.owner.get("/api/v1/servers/" + target); !strings.Contains(string(b), `"maint_until"`) || !strings.Contains(string(b), `"maint_note":"update"`) {
		t.Errorf("the card must show the open window: %s", b)
	}
	if st, b := wake(w.owner); st != 409 || errCode(b) != "already_on" {
		t.Errorf("a machine that is on: %d %s", st, b)
	}
	offTarget() // the machine is off now

	if st, b := wake(w.owner); st != 409 || errCode(b) != "no_helper" {
		t.Errorf("nobody on to send it: %d %s", st, b)
	}
	offFar := connect(2) // on, but in another network
	if st, b := wake(w.owner); st != 409 || errCode(b) != "no_helper" {
		t.Errorf("a machine in another network must not be used: %d %s", st, b)
	}
	offFar()
	connect(1)
	if st, _ := wake(w.viewer); st != 403 {
		t.Errorf("a viewer must not wake a machine: %d", st)
	}
	if st, b := wake(w.owner); st != 200 {
		t.Fatalf("wake: %d %s", st, b)
	}
	if len(sent) != 1 || sent[0].MAC != "aa:bb:cc:dd:ee:02" || sent[0].Op != secproto.WolSend {
		t.Errorf("the neighbour was asked: %+v", sent)
	}
	if st, b := put(w.owner, map[string]any{"enabled": false}); st != 200 {
		t.Fatalf("turn off: %d %s", st, b)
	}
	var n int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM wol_targets`).Scan(&n); err != nil || n != 0 {
		t.Errorf("an address must not be kept for a machine that is turned off: %d %v", n, err)
	}
}
