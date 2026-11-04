package alerts

import (
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/store"
)

const gigabyte = int64(1 << 30)

// hourly makes n hourly readings, the disk using start bytes at the first and growing by perDay bytes a day.
func hourly(n int, start, perDay int64, wobble func(i int) int64) []store.DiskPoint {
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	out := make([]store.DiskPoint, n)
	for i := range out {
		used := start + perDay*int64(i)/24
		if wobble != nil {
			used += wobble(i)
		}
		out[i] = store.DiskPoint{At: t0.Add(time.Duration(i) * time.Hour), Used: used}
	}
	return out
}

func TestDiskDaysLeftFollowsASteadyGrowth(t *testing.T) {
	// 100 GB disk, about 60 GB used after four days of growing 2 GB a day: the 40 GB left are gone in 20 days.
	pts := hourly(96, 52*gigabyte, 2*gigabyte, nil)
	days, perDay, ok := DiskDaysLeft(pts, 100*gigabyte)
	if !ok || days < 19 || days > 21 || perDay < float64(2*gigabyte)*0.95 || perDay > float64(2*gigabyte)*1.05 {
		t.Errorf("days %.1f perDay %.2f GB ok %v", days, perDay/float64(gigabyte), ok)
	}
}

func TestDiskDaysLeftSaysNothingWhenThereIsNothingToSay(t *testing.T) {
	cases := map[string][]store.DiskPoint{
		"too little history":  hourly(10, 50*gigabyte, 5*gigabyte, nil),
		"a disk that is flat": hourly(96, 50*gigabyte, 0, nil),
		"a disk that shrinks": hourly(96, 80*gigabyte, -3*gigabyte, nil),
		"noise only":          hourly(96, 50*gigabyte, 10*1024*1024, func(i int) int64 { return int64((i*7919)%13) * gigabyte / 10 }),
	}
	for name, pts := range cases {
		if d, _, ok := DiskDaysLeft(pts, 100*gigabyte); ok {
			t.Errorf("%s: %.1f days, must be no forecast", name, d)
		}
	}
	// A saw tooth: fills for a day, is cleared, fills again. A line through it means nothing.
	saw := hourly(96, 0, 0, func(i int) int64 { return int64(i%24) * 2 * gigabyte })
	if d, _, ok := DiskDaysLeft(saw, 100*gigabyte); ok {
		t.Errorf("a saw tooth: %.1f days, must be no forecast", d)
	}
	if _, _, ok := DiskDaysLeft(hourly(96, 50*gigabyte, 2*gigabyte, nil), 0); ok {
		t.Error("a disk of no size has no forecast")
	}
}

func TestDiskForecastAlertIsRaisedOnlyForASteadilyFillingDiskThatIsNotAlreadyFull(t *testing.T) {
	trend := hourly(96, 52*gigabyte, 6*gigabyte, nil) // 6 GB a day: about 40 GB left is gone in a week
	h := store.HostAlertState{VPSID: "v1", Name: "Autocad", Online: true, MainMount: "C:", DiskTrend: trend, DiskTotal: 100 * gigabyte,
		Disks: []secproto.HostDisk{{Mount: "C:", Used: 58 * gigabyte, Total: 100 * gigabyte}}}
	got := HostConditions([]store.HostAlertState{h})
	if len(got) != 1 || got[0].Kind != store.AlertHostDiskForecast || got[0].Subject != "v1:C:" || !strings.Contains(got[0].Label, "Autocad C:") || !strings.Contains(got[0].Detail, "в сутки") {
		t.Fatalf("forecast alert: %+v", got)
	}
	// Nearly full already: the other alert says it, this one keeps quiet.
	h.Disks = []secproto.HostDisk{{Mount: "C:", Used: 95 * gigabyte, Total: 100 * gigabyte}}
	for _, c := range HostConditions([]store.HostAlertState{h}) {
		if c.Kind == store.AlertHostDiskForecast {
			t.Errorf("a disk already nearly full must not also get the forecast: %+v", c)
		}
	}
	// A data drive of a workstation is not watched.
	h2 := h
	h2.MainMount, h2.Disks = "D:", []secproto.HostDisk{{Mount: "D:", Used: 58 * gigabyte, Total: 100 * gigabyte}}
	if got := HostConditions([]store.HostAlertState{h2}); len(got) != 0 {
		t.Errorf("D: is not watched: %+v", got)
	}
	// Slow growth: far from full for a long time, no alert.
	slow := h
	slow.Disks = []secproto.HostDisk{{Mount: "C:", Used: 58 * gigabyte, Total: 100 * gigabyte}}
	slow.DiskTrend = hourly(96, 52*gigabyte, gigabyte/2, nil)
	if got := HostConditions([]store.HostAlertState{slow}); len(got) != 0 {
		t.Errorf("80 days left is no alert: %+v", got)
	}
}

func TestDaysTextIsRussian(t *testing.T) {
	for in, want := range map[float64]string{0.4: "меньше суток", 1.2: "около суток", 2: "2 дня", 5: "5 дней", 11: "11 дней", 21: "21 день", 13.6: "14 дней"} {
		if got := daysText(in); got != want {
			t.Errorf("%v days: %q, want %q", in, got, want)
		}
	}
}
