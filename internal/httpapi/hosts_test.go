package httpapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/alerts"
	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/store"
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

func TestOnboardingCountsAreTheOwnersAndSayWhatIsSetUp(t *testing.T) {
	w := newWorld(t)
	for _, c := range []*client{w.viewer, w.op, w.adm} {
		if st, _ := c.get("/api/v1/onboarding"); st != 403 {
			t.Fatalf("only the owner: %d", st)
		}
	}
	st, b := w.owner.get("/api/v1/onboarding")
	if st != 200 || !strings.Contains(string(b), `"panels":2`) || !strings.Contains(string(b), `"notify_channels":0`) || !strings.Contains(string(b), `"bills":0`) {
		t.Fatalf("%d %s", st, b)
	}
	if _, err := w.h.st.CreateBill(context.Background(), store.BillInput{Name: "x", Amount: 1, Currency: "EUR", PeriodMonths: 1, NextDue: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, b = w.owner.get("/api/v1/onboarding"); !strings.Contains(string(b), `"bills":1`) {
		t.Fatalf("%s", b)
	}
}

func TestDiskForecastAlertOpensForADiskThatFillsSteadilyAndNotForOneThatIsFlat(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	gb := int64(1 << 30)
	now := time.Now().UTC().Truncate(time.Minute)
	mk := func(name string, startUsed, perDay int64) store.VPS {
		v, err := w.h.st.CreateVPS(ctx, "", name, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		// four days of one reading an hour, the disk growing by perDay a day
		for i := 96; i >= 0; i-- {
			at := now.Add(-time.Duration(i) * time.Hour)
			used := startUsed + perDay*int64(96-i)/24
			h := secproto.Host{Type: "host", At: at, OS: "Ubuntu", CPUs: 2, MemTotal: 4 * gb, MemUsed: gb, CPUPct: 5, Load1: 0.1, UptimeSec: 3600,
				Disks: []secproto.HostDisk{{Mount: "/", FS: "ext4", Total: 100 * gb, Used: used}}}
			if err := w.h.st.SaveHost(ctx, v.ID, h, at); err != nil {
				t.Fatal(err)
			}
		}
		return v
	}
	filling := mk("filling", 50*gb, 6*gb) // about 26 GB left of a 100 GB disk after 24 GB of growth: days away
	flat := mk("flat", 50*gb, 0)

	states, err := w.h.st.HostAlertStates(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	var kinds = map[string][]string{}
	for _, c := range alerts.HostConditions(states) {
		kinds[c.Subject] = append(kinds[c.Subject], c.Kind)
	}
	if got := kinds[filling.ID+":/"]; len(got) != 1 || got[0] != store.AlertHostDiskForecast {
		t.Errorf("a disk filling 6 GB a day must get the forecast alert: %v", kinds)
	}
	if len(kinds[flat.ID+":/"]) != 0 {
		t.Errorf("a flat disk must get none: %v", kinds)
	}
}

func TestAlertRulesAreSavedPerMachineAndAnAlertCanBePutOff(t *testing.T) {
	w := newAgentWorld(t)
	ctx := context.Background()
	gb := int64(1 << 30)
	id := mkVPS(t, w, "home-pc", "203.0.113.60", w.work.ID)
	h := secproto.Host{Type: "host", At: time.Now(), OS: "Windows", CPUs: 4, MemTotal: 16 * gb, MemUsed: 4 * gb, CPUPct: 5, Load1: 0.1, UptimeSec: 3600,
		Disks: []secproto.HostDisk{{Mount: "C:", FS: "NTFS", Total: 100 * gb, Used: 95 * gb}, {Mount: "D:", FS: "NTFS", Total: 100 * gb, Used: 99 * gb}}}
	if err := w.h.st.SaveHost(ctx, id, h, time.Now()); err != nil {
		t.Fatal(err)
	}
	type view struct {
		Rows []struct {
			Rule      string `json:"rule"`
			Enabled   bool   `json:"enabled"`
			Threshold int    `json:"threshold"`
			Changed   bool   `json:"changed"`
		} `json:"rows"`
		CanEdit bool `json:"can_edit"`
	}
	st, b := w.owner.get("/api/v1/servers/" + id + "/alert-rules")
	if st != 200 {
		t.Fatalf("get: %d %s", st, b)
	}
	got := parse[view](t, b)
	names := map[string]bool{}
	for _, r := range got.Rows {
		names[r.Rule] = r.Enabled
	}
	// By default C: is watched, the archive drive D: is not; the forecast, processor and memory are.
	if !names["disk:C:"] || names["disk:D:"] || !names["forecast"] || !names["cpu"] || !names["mem"] || len(got.Rows) != 5 {
		t.Errorf("defaults: %s", b)
	}

	put := map[string]any{"rules": []map[string]any{{"rule": "disk:C:", "enabled": true, "threshold": 97}, {"rule": "disk:D:", "enabled": true}}}
	if st, b := w.owner.do("PUT", "/api/v1/servers/"+id+"/alert-rules", put); st != 200 {
		t.Fatalf("put: %d %s", st, b)
	}
	_, b = w.owner.get("/api/v1/servers/" + id + "/alert-rules")
	got = parse[view](t, b)
	for _, r := range got.Rows {
		if r.Rule == "disk:C:" && (r.Threshold != 97 || !r.Changed) || r.Rule == "disk:D:" && (!r.Enabled || !r.Changed) {
			t.Errorf("saved rule: %+v", r)
		}
	}
	for name, bad := range map[string][]map[string]any{
		"unknown rule":   {{"rule": "gpu", "enabled": true}},
		"threshold":      {{"rule": "cpu", "enabled": true, "threshold": 0}},
		"forecast range": {{"rule": "forecast", "enabled": true, "threshold": 400}},
		"twice":          {{"rule": "cpu", "enabled": true}, {"rule": "cpu", "enabled": false}},
	} {
		if st, b := w.owner.do("PUT", "/api/v1/servers/"+id+"/alert-rules", map[string]any{"rules": bad}); st != 422 || errCode(b) != "invalid_rules" {
			t.Errorf("%s must be refused: %d %s", name, st, b)
		}
	}
	if st, _ := w.viewer.do("PUT", "/api/v1/servers/"+id+"/alert-rules", put); st != 403 {
		t.Errorf("a viewer must not change the rules: %d", st)
	}

	// Put an alert off: it closes, and the same condition is not reported while the time lasts.
	if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO alerts (kind, subject, label, opened_at) VALUES ('host_disk', $1, 'Диск почти полон', now())`, id+":C:"); err != nil {
		t.Fatal(err)
	}
	var alertID string
	if err := w.h.st.Pool().QueryRow(ctx, `SELECT id::text FROM alerts WHERE kind='host_disk' AND subject=$1`, id+":C:").Scan(&alertID); err != nil {
		t.Fatal(err)
	}
	if st, b := w.viewer.do("POST", "/api/v1/alerts/"+alertID+"/snooze", map[string]any{"hours": 24}); st != 403 {
		t.Errorf("only the owner puts an alert off: %d %s", st, b)
	}
	if st, b := w.owner.do("POST", "/api/v1/alerts/"+alertID+"/snooze", map[string]any{"hours": 0}); st != 422 {
		t.Errorf("hours out of range: %d %s", st, b)
	}
	if st, b := w.owner.do("POST", "/api/v1/alerts/"+alertID+"/snooze", map[string]any{"hours": 24}); st != 200 {
		t.Fatalf("snooze: %d %s", st, b)
	}
	var open int
	if err := w.h.st.Pool().QueryRow(ctx, `SELECT count(*) FROM alerts WHERE id=$1 AND resolved_at IS NULL`, alertID).Scan(&open); err != nil || open != 0 {
		t.Errorf("a put-off alert is closed: %d %v", open, err)
	}
	snoozed, err := w.h.st.ActiveSnoozes(ctx, time.Now())
	if err != nil || !snoozed["host_disk\x00"+id+":C:"] {
		t.Errorf("the snooze must be recorded: %v %v", snoozed, err)
	}
}
