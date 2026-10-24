package httpapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/alerts"
	"github.com/Taminum/RemnaScope/internal/secproto"
)

func TestHostResourcesAreListedChartedAndRaiseAlertsForAFullDisk(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	vps, err := w.h.st.CreateVPS(ctx, "", "exit-test", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	gb := int64(1 << 30)
	now := time.Now().UTC()
	host := func(cpu float64, diskUsed int64) secproto.Host {
		return secproto.Host{Type: "host", At: now, OS: "Ubuntu 24.04", Kernel: "6.8.0", Arch: "amd64", CPUModel: "Test CPU", CPUs: 2, MemTotal: 4 * gb, MemUsed: gb,
			CPUPct: cpu, Load1: 0.5, UptimeSec: 3600, NetRX: 1000, NetTX: 2000, Disks: []secproto.HostDisk{{Mount: "/", FS: "ext4", Total: 100 * gb, Used: diskUsed}},
			Procs: []secproto.HostProc{{Name: "xray", Unit: "docker:0123456789ab", Count: 1, CPU: 41.27, RSS: gb / 4}, {Name: "", Count: 3}, {Name: "ghost", Count: 0, CPU: 5}, {Name: "weird", Count: 1, CPU: -5, RSS: -1}}}
	}
	// A server with no reading is listed, without data.
	_, b := w.owner.get("/api/v1/hosts")
	if !strings.Contains(string(b), `"has_data":false`) || !strings.Contains(string(b), "exit-test") {
		t.Fatalf("%s", b)
	}
	// Ten minutes of one reading a minute; the disk is 95% full.
	for i := 10; i >= 0; i-- {
		h := host(20, 95*gb)
		h.NetRX, h.NetTX = int64(1000+i*0)+int64(10-i)*60000, int64(2000)+int64(10-i)*120000
		if err := w.h.st.SaveHost(ctx, vps.ID, h, now.Add(-time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	_, b = w.owner.get("/api/v1/hosts")
	for _, want := range []string{`"has_data":true`, `"os":"Ubuntu 24.04"`, `"cpus":2`, `"cpu":20`, `"mem_used":1073741824`, `"mount":"/"`} {
		if !strings.Contains(string(b), want) && !strings.Contains(strings.ReplaceAll(string(b), `"m":"/"`, `"mount":"/"`), want) {
			t.Errorf("%s is missing from %s", want, b)
		}
	}
	// The busiest programs are kept; a group with no name or no process is not, and numbers are made sensible.
	if !strings.Contains(string(b), `"n":"xray"`) || !strings.Contains(string(b), `"cpu":41.3`) || strings.Contains(string(b), "ghost") {
		t.Fatalf("%s", b)
	}
	if strings.Contains(string(b), `"rss":-1`) || strings.Contains(string(b), `"cpu":-5`) {
		t.Fatalf("a negative figure got through: %s", b)
	}
	st, sb := w.owner.get("/api/v1/hosts/" + vps.ID + "/series?hours=1")
	if st != 200 || !strings.Contains(string(sb), `"rx_bps":1000`) || !strings.Contains(string(sb), `"disk_pct":95`) {
		t.Fatalf("%d %s", st, sb)
	}
	if st, _ := w.owner.get("/api/v1/hosts/" + vps.ID + "/series?hours=999"); st != 422 {
		t.Fatalf("an absurd range: %d", st)
	}
	if st, _ := w.owner.get("/api/v1/hosts/00000000-0000-0000-0000-000000000000/series"); st != 404 {
		t.Fatalf("an unknown server: %d", st)
	}

	// A disk at 95% raises an alert; the processor and the memory are fine.
	if _, _, err := alerts.Evaluate(ctx, w.h.st, now); err != nil {
		t.Fatal(err)
	}
	_, ab := w.owner.get("/api/v1/alerts")
	if !strings.Contains(string(ab), "host_disk") || strings.Contains(string(ab), "host_cpu") || strings.Contains(string(ab), "host_mem") {
		t.Fatalf("%s", ab)
	}
	// It closes when the disk is no longer full.
	if err := w.h.st.SaveHost(ctx, vps.ID, host(20, 50*gb), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := alerts.Evaluate(ctx, w.h.st, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	_, ab = w.owner.get("/api/v1/alerts")
	if strings.Contains(string(ab), `"resolved_at":null`) && strings.Contains(string(ab), "host_disk") {
		t.Fatalf("the alert did not close: %s", ab)
	}
	// People who are not linked to the server see nothing of it.
	if _, vb := w.viewer.get("/api/v1/hosts"); strings.Contains(string(vb), "exit-test") {
		t.Fatalf("a viewer sees an unlinked server: %s", vb)
	}
}

func TestAFloodOfTrafficRaisesAnAlertThatNamesTheNumbersAndClosesWhenItEnds(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	vps, err := w.h.st.CreateVPS(ctx, "", "exit-flood", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Minute)
	var rx, rxp int64
	send := func(at time.Time, bps, pps float64, syn int) {
		rx += int64(bps * 60)
		rxp += int64(pps * 60)
		h := secproto.Host{Type: "host", At: at, MemTotal: 1 << 30, MemUsed: 1 << 29, NetRX: rx, NetRXPkts: rxp, SynRecv: syn, Estab: 40}
		if err := w.h.st.SaveHost(ctx, vps.ID, h, at); err != nil {
			t.Fatal(err)
		}
	}
	open := func(at time.Time) bool {
		if _, _, err := alerts.Evaluate(ctx, w.h.st, at); err != nil {
			t.Fatal(err)
		}
		_, b := w.owner.get("/api/v1/alerts")
		return strings.Contains(string(b), "host_flood") && strings.Contains(string(b), `"resolved_at":null`)
	}
	// An ordinary evening, then twelve minutes of 400 Mbit/s and 120 thousand packets a second.
	for i := 40; i > 12; i-- {
		send(now.Add(-time.Duration(i)*time.Minute), 1e6, 1500, 3)
	}
	if open(now.Add(-13 * time.Minute)) {
		t.Fatal("an ordinary evening raised the alarm")
	}
	for i := 12; i >= 0; i-- {
		send(now.Add(-time.Duration(i)*time.Minute), 50e6, 120000, 5)
	}
	if !open(now) {
		t.Fatal("a flood must raise an alert")
	}
	_, b := w.owner.get("/api/v1/alerts")
	if !strings.Contains(string(b), "Похоже на DDoS: exit-flood") || !strings.Contains(string(b), "400 Мбит/с") {
		t.Fatalf("%s", b)
	}
	// The list shows the current rates and connections.
	_, lb := w.owner.get("/api/v1/hosts")
	if !strings.Contains(string(lb), `"rx_pps":120000`) || !strings.Contains(string(lb), `"estab":40`) {
		t.Fatalf("%s", lb)
	}
	// After a quiet quarter of an hour it closes.
	for i := 1; i <= 14; i++ {
		send(now.Add(time.Duration(i)*time.Minute), 1e6, 1500, 3)
	}
	if open(now.Add(14 * time.Minute)) {
		t.Fatal("the alert did not close")
	}
}
