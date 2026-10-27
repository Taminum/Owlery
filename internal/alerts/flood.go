package alerts

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Taminum/Owlery/internal/store"
)

const (
	// FloodMinBps and FloodMinPps are the floors: below them traffic is never called a flood, however far it is
	// above what was usual. 200 Mbit/s and 60 thousand packets a second: an exit server carries tens of Mbit/s of
	// its users' traffic every day.
	FloodMinBps = 200e6 / 8
	FloodMinPps = 60000
	// FloodQueueDrops is how many SYN cookies or dropped connections in one minute count as a queue that overflows;
	// a handful now and then is ordinary.
	FloodQueueDrops = 100
	// FloodTimes is how far above the usual (its 95th percentile over the day before) counts as a flood.
	FloodTimes = 4.0
	// FloodSynRecv is how many half-open TCP connections at one moment point to a SYN flood.
	FloodSynRecv = 300
	// FloodSamples is how many of the last twelve minutes must look like it. Alerts close when fewer do.
	FloodSamples = 5
	// minBaseline is how many one-minute rates (three hours) are needed to call something "usual".
	minBaseline = 180
)

type rate struct {
	bps, pps      float64
	syn           int
	cookies, drop int64
}

func rates(xs []store.FloodSample) []rate {
	var out []rate
	for i := 1; i < len(xs); i++ {
		a, b := xs[i-1], xs[i]
		dt := b.At.Sub(a.At).Seconds()
		if dt <= 0 || b.RX < a.RX || b.RXPkts < a.RXPkts {
			continue // a reboot or a gap: no rate for that step
		}
		out = append(out, rate{
			bps: float64(b.RX-a.RX) / dt, pps: float64(b.RXPkts-a.RXPkts) / dt, syn: b.SynRecv,
			cookies: b.Cookies - a.Cookies, drop: b.ListenDrops - a.ListenDrops,
		})
	}
	return out
}

func p95(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	return s[int(float64(len(s)-1)*0.95)]
}

func mbit(bps float64) string { return fmt.Sprintf("%.0f Мбит/с", bps*8/1e6) }

func perSec(pps float64) string {
	if pps >= 1000 {
		return fmt.Sprintf("%.0f тыс/с", pps/1000)
	}
	return fmt.Sprintf("%.0f/с", pps)
}

// FloodConditions says which servers look under a flood of packets or connections. It cannot tell an attack from
// a legitimate surge, so the wording is "looks like"; it asks only whether traffic is far above what this server
// usually has, or the kernel itself says its queues are overflowing.
func FloodConditions(states []store.HostFloodState) []store.Condition {
	var out []store.Condition
	for _, h := range states {
		if !h.Online {
			continue
		}
		recent := rates(h.Recent)
		if len(recent) < FloodSamples {
			continue
		}
		base := rates(h.Baseline)
		var bb, bp []float64
		for _, r := range base {
			bb = append(bb, r.bps)
			bp = append(bp, r.pps)
		}
		usualBps, usualPps := p95(bb), p95(bp)
		bpsLimit, ppsLimit := float64(FloodMinBps), float64(FloodMinPps)
		known := len(base) >= minBaseline
		if known {
			bpsLimit, ppsLimit = max(bpsLimit, FloodTimes*usualBps), max(ppsLimit, FloodTimes*usualPps)
		}
		var volume, conns, cookies, drops int
		var peakBps, peakPps float64
		var peakSyn int
		for _, r := range recent {
			if r.bps >= bpsLimit || r.pps >= ppsLimit {
				volume++
			}
			if r.syn >= FloodSynRecv {
				conns++
			}
			if r.cookies >= FloodQueueDrops {
				cookies++
			}
			if r.drop >= FloodQueueDrops {
				drops++
			}
			peakBps, peakPps = max(peakBps, r.bps), max(peakPps, r.pps)
			peakSyn = max(peakSyn, r.syn)
		}
		var why []string
		if volume >= FloodSamples {
			s := fmt.Sprintf("входящий трафик до %s и до %s пакетов", mbit(peakBps), perSec(peakPps))
			if known {
				s += fmt.Sprintf(" (обычно до %s и %s)", mbit(usualBps), perSec(usualPps))
			}
			why = append(why, s)
		}
		if conns >= FloodSamples {
			why = append(why, fmt.Sprintf("полуоткрытых TCP-соединений до %d", peakSyn))
		}
		if cookies >= FloodSamples {
			why = append(why, "ядро включало SYN-куки (очередь соединений переполнена)")
		}
		if drops >= FloodSamples {
			why = append(why, "очередь входящих соединений отбрасывает новые")
		}
		if len(why) == 0 {
			continue
		}
		out = append(out, store.Condition{Kind: store.AlertHostFlood, Subject: h.VPSID, Label: "Похоже на DDoS: " + h.Name,
			Detail: strings.Join(why, "; ") + ". Это может быть и обычный всплеск нагрузки: проверьте, кто подключается."})
	}
	return out
}
