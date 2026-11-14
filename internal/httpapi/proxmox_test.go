package httpapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/alerts"
	"github.com/Taminum/Owlery/internal/secproto"
)

func TestProxmoxHomeIsOwnersOnlyEmptyWhileOffAndRaisesAlertsWhenOn(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	now := time.Now().UTC()
	vps, err := w.h.st.CreateVPS(ctx, "", "pve", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	no := false
	reading := secproto.Proxmox{Node: "pve", Online: true, CPUs: 12, MemUsed: 5, MemTotal: 63, DiskUsed: 18, DiskTotal: 100, Uptime: 700, Tailnet: "100.1.1.1",
		Guests: []secproto.PVEGuest{
			{ID: 205, Kind: "lxc", Name: "cloud", Status: "running", DiskUsed: 95, DiskMax: 100, LAN: "192.168.1.205", Tailnet: "100.2.2.2", TSOnline: &no},
			{ID: 300, Kind: "qemu", Name: "vm1", Status: "stopped"}}}
	if err := w.h.st.SavePVE(ctx, vps.ID, reading, now); err != nil {
		t.Fatal(err)
	}

	type resp struct {
		Enabled bool `json:"enabled"`
		Hosts   []struct {
			Name    string `json:"name"`
			LXC     int    `json:"lxc"`
			VMs     int    `json:"vms"`
			Running int    `json:"running"`
			Fresh   bool   `json:"fresh"`
			Guests  []struct {
				ID   int    `json:"id"`
				Kind string `json:"kind"`
				LAN  string `json:"lan"`
			} `json:"guests"`
		} `json:"hosts"`
	}
	if st, _ := w.viewer.get("/api/v1/home/proxmox"); st != 403 {
		t.Fatalf("a viewer may not see the house: %d", st)
	}
	if st, body := w.owner.get("/api/v1/home/proxmox"); st != 200 || parse[resp](t, body).Enabled || len(parse[resp](t, body).Hosts) != 0 {
		t.Fatalf("off by default and empty: %d %s", st, body)
	}
	if st, _ := w.owner.do("PUT", "/api/v1/modules/proxmox", map[string]any{"enabled": true}); st != 200 {
		t.Fatalf("turn on: %d", st)
	}
	st, body := w.owner.get("/api/v1/home/proxmox")
	got := parse[resp](t, body)
	if st != 200 || !got.Enabled || len(got.Hosts) != 1 {
		t.Fatalf("%d %s", st, body)
	}
	if h := got.Hosts[0]; h.Name != "pve" || h.LXC != 1 || h.VMs != 1 || h.Running != 1 || !h.Fresh || len(h.Guests) != 2 || h.Guests[0].LAN != "192.168.1.205" || h.Guests[1].Kind != "qemu" {
		t.Fatalf("host: %+v", h)
	}

	if _, _, err := alerts.Evaluate(ctx, w.h.st, now); err != nil {
		t.Fatal(err)
	}
	_, ab := w.owner.get("/api/v1/alerts")
	if !strings.Contains(string(ab), "pve_disk") || !strings.Contains(string(ab), "pve_tailscale") {
		t.Fatalf("a nearly full disk and a guest out of Tailscale are told: %s", ab)
	}
	if st, _ := w.owner.do("PUT", "/api/v1/modules/proxmox", map[string]any{"enabled": false}); st != 200 {
		t.Fatalf("turn off: %d", st)
	}
	if _, _, err := alerts.Evaluate(ctx, w.h.st, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	_, ab = w.owner.get("/api/v1/alerts?open=1")
	for _, a := range parse[alertsResp](t, ab).Alerts {
		if strings.HasPrefix(a.Kind, "pve_") && a.ResolvedAt == nil {
			t.Fatalf("with the module off its alerts close: %+v", a)
		}
	}
}
