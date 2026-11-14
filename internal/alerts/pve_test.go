package alerts

import (
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/store"
)

func TestPVEConditionsNameGuestsThatStoppedDisksBackupsAndTailscale(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	no, yes := false, true
	host := store.PVEHost{VPSID: "v1", VPSName: "pve", UpdatedAt: now.Add(-time.Minute), Data: secproto.Proxmox{
		Node: "pve", LastBackupOK: &no,
		Storages: []secproto.PVEStorage{{Name: "local", Used: 90, Total: 100, Active: true}, {Name: "usb", Used: 10, Total: 100, Active: true}},
		Guests: []secproto.PVEGuest{
			{ID: 200, Kind: "lxc", Name: "media", Status: "stopped"},
			{ID: 201, Kind: "lxc", Name: "idle", Status: "stopped"},
			{ID: 205, Kind: "lxc", Name: "cloud", Status: "running", DiskUsed: 88, DiskMax: 100, Backup: now.Add(-60 * time.Hour).Unix(), TSOnline: &no},
			{ID: 206, Kind: "lxc", Name: "ok", Status: "running", DiskUsed: 10, DiskMax: 100, Backup: now.Add(-time.Hour).Unix(), TSOnline: &yes},
			{ID: 900, Kind: "lxc", Name: "tmpl", Status: "stopped", Template: true},
		}}}
	was := func(_ string, id int) bool { return id == 200 }
	days := func(_ string, id int) (float64, bool) { return 9, id == 205 }
	got := map[string]store.Condition{}
	for _, c := range PVEConditions([]store.PVEHost{host}, was, days, now) {
		got[c.Subject] = c
	}
	for _, want := range []string{"v1:job", "v1:s:local", "v1:g:200", "v1:g:205", "v1:b:205", "v1:t:205"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("missing %s in %v", want, got)
		}
	}
	for _, not := range []string{"v1:s:usb", "v1:g:201", "v1:g:206", "v1:b:206", "v1:g:900"} {
		if _, ok := got[not]; ok {
			t.Fatalf("%s must not alert: %+v", not, got[not])
		}
	}
	if d := got["v1:g:205"].Detail; !strings.Contains(d, "88%") || !strings.Contains(d, "9 дн.") {
		t.Fatalf("disk detail: %s", d)
	}
	if len(PVEConditions([]store.PVEHost{{VPSID: "v1", UpdatedAt: now.Add(-time.Hour), Data: host.Data}}, was, days, now)) != 0 {
		t.Fatal("a host that has gone quiet is left to the silent-agent alert")
	}
}
