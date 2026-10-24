package alerts

import (
	"strings"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/store"
)

// series makes minute samples whose traffic is bps bytes a second and pps packets a second at every step.
func series(start time.Time, n int, bps, pps float64, syn int) []store.FloodSample {
	var out []store.FloodSample
	var rx, rxp int64
	for i := 0; i < n; i++ {
		rx += int64(bps * 60)
		rxp += int64(pps * 60)
		out = append(out, store.FloodSample{At: start.Add(time.Duration(i) * time.Minute), RX: rx, RXPkts: rxp, SynRecv: syn})
	}
	return out
}

func joined(base, recent []store.FloodSample) []store.FloodSample {
	// The recent samples continue the counters of the baseline.
	off := base[len(base)-1]
	for i := range recent {
		recent[i].RX += off.RX
		recent[i].RXPkts += off.RXPkts
	}
	return recent
}

func TestFloodConditionsSeeTrafficFarAboveTheUsualAndStaySilentOtherwise(t *testing.T) {
	now := time.Now()
	baseStart := now.Add(-24 * time.Hour)
	base := series(baseStart, 1000, 2e6, 3000, 5) // 16 Mbit/s and 3000 packets a second: a normal day
	recentStart := now.Add(-12 * time.Minute)
	host := func(recent []store.FloodSample) store.HostFloodState {
		return store.HostFloodState{VPSID: "v1", Name: "exit-nl", Online: true, Baseline: base, Recent: joined(base, recent)}
	}

	if got := FloodConditions([]store.HostFloodState{host(series(recentStart, 12, 2.5e6, 3500, 8))}); len(got) != 0 {
		t.Fatalf("a normal minute is not a flood: %+v", got)
	}
	// Above the floor and four times the usual for several minutes: a flood.
	got := FloodConditions([]store.HostFloodState{host(series(recentStart, 12, 40e6, 90000, 5))})
	if len(got) != 1 || got[0].Kind != store.AlertHostFlood || got[0].Subject != "v1" || !strings.Contains(got[0].Label, "exit-nl") {
		t.Fatalf("%+v", got)
	}
	if !strings.Contains(got[0].Detail, "320 Мбит/с") || !strings.Contains(got[0].Detail, "90 тыс/с") || !strings.Contains(got[0].Detail, "обычно") {
		t.Fatalf("it must say how far from the usual: %s", got[0].Detail)
	}
	// One lost minute of spike is not enough.
	spike := series(recentStart, 12, 2e6, 3000, 5)
	spike[6].RX += 600e6
	if got := FloodConditions([]store.HostFloodState{host(spike)}); len(got) != 0 {
		t.Fatalf("a single spike: %+v", got)
	}
	// Half-open connections alone are enough.
	if got := FloodConditions([]store.HostFloodState{host(series(recentStart, 12, 2e6, 3000, 4000))}); len(got) != 1 || !strings.Contains(got[0].Detail, "4000") {
		t.Fatalf("a SYN flood: %+v", got)
	}
	// A server that does not report is the agent's alert, not this one.
	off := host(series(recentStart, 12, 40e6, 90000, 5))
	off.Online = false
	if got := FloodConditions([]store.HostFloodState{off}); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestFloodUsualTrafficRaisesTheBarForABusyServer(t *testing.T) {
	now := time.Now()
	// A server that normally carries 80 Mbit/s: 100 Mbit/s is not a flood there, 600 is.
	base := series(now.Add(-24*time.Hour), 1000, 10e6, 9000, 5)
	h := func(bps float64) store.HostFloodState {
		return store.HostFloodState{VPSID: "v", Name: "busy", Online: true, Baseline: base, Recent: joined(base, series(now.Add(-12*time.Minute), 12, bps, 9000, 5))}
	}
	if got := FloodConditions([]store.HostFloodState{h(12.5e6)}); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
	if got := FloodConditions([]store.HostFloodState{h(75e6)}); len(got) != 1 {
		t.Fatalf("%+v", got)
	}
}

func TestFloodIgnoresAReboot(t *testing.T) {
	now := time.Now()
	recent := series(now.Add(-12*time.Minute), 12, 2e6, 3000, 5)
	for i := 6; i < 12; i++ { // the counters fall back to zero at the reboot
		recent[i].RX, recent[i].RXPkts = int64(i)*100, int64(i)*10
	}
	if got := FloodConditions([]store.HostFloodState{{VPSID: "v", Name: "r", Online: true, Recent: recent}}); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestFloodDoesNotMistakeAnExitServersOrdinaryTrafficOrAFewDroppedConnectionsForAnAttack(t *testing.T) {
	now := time.Now()
	start := now.Add(-12 * time.Minute)
	// 70 Mbit/s and 4 thousand packets a second with no history at all: what exit-2 carries on an ordinary day.
	steady := store.HostFloodState{VPSID: "v", Name: "exit-2", Online: true, Recent: series(start, 13, 70e6/8, 4000, 5)}
	if got := FloodConditions([]store.HostFloodState{steady}); len(got) != 0 {
		t.Fatalf("ordinary exit traffic raised an alarm: %+v", got)
	}
	// A few dropped connections every minute are ordinary; hundreds of them are not.
	queue := func(perMinute int64) store.HostFloodState {
		xs := series(start, 13, 1e6, 1500, 5)
		for i := range xs {
			xs[i].ListenDrops = int64(i) * perMinute
			xs[i].Cookies = int64(i) * perMinute
		}
		return store.HostFloodState{VPSID: "v", Name: "exit-nl", Online: true, Recent: xs}
	}
	if got := FloodConditions([]store.HostFloodState{queue(7)}); len(got) != 0 {
		t.Fatalf("a few drops raised an alarm: %+v", got)
	}
	if got := FloodConditions([]store.HostFloodState{queue(400)}); len(got) != 1 || !strings.Contains(got[0].Detail, "SYN") {
		t.Fatalf("hundreds of drops a minute must: %+v", got)
	}
}
