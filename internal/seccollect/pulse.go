package seccollect

import (
	"sync"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

// pulseRaw is what one look at the system gives: counters that only mean something against the previous look.
type pulseRaw struct {
	haveCPU     bool
	busy, total uint64
	memUsed     int64
	memTotal    int64
	rx, tx      int64
}

type pulseState struct {
	mu      sync.Mutex
	haveCPU bool
	busy    uint64
	total   uint64
	haveNet bool
	rx, tx  int64
	at      time.Time
}

// Pulse takes the light reading: processor use and network speed against the last pulse, and memory now. It keeps its own
// previous readings, so it does not disturb the full reading's processor share.
func (h *HostReader) Pulse(now time.Time) secproto.Pulse {
	raw := h.pulseOS()
	out := secproto.Pulse{Type: "pulse", At: now.UTC(), CPUPct: -1, MemUsed: raw.memUsed, MemTotal: raw.memTotal}
	st := &h.pulse
	st.mu.Lock()
	defer st.mu.Unlock()
	if raw.haveCPU {
		if st.haveCPU && raw.total > st.total && raw.busy >= st.busy {
			out.CPUPct = min(float64(raw.busy-st.busy)*100/float64(raw.total-st.total), 100)
		}
		st.busy, st.total, st.haveCPU = raw.busy, raw.total, true
	}
	if secs := now.Sub(st.at).Seconds(); st.haveNet && secs > 0 && raw.rx >= st.rx && raw.tx >= st.tx {
		out.RXBps = int64(float64(raw.rx-st.rx) / secs)
		out.TXBps = int64(float64(raw.tx-st.tx) / secs)
	}
	st.rx, st.tx, st.at, st.haveNet = raw.rx, raw.tx, now, true
	return out
}

// pulseProcfs reads the three things from /proc.
func (h *HostReader) pulseProcfs() pulseRaw {
	var r pulseRaw
	if busy, total, ok := ParseCPUStat(h.read("stat")); ok {
		r.busy, r.total, r.haveCPU = busy, total, true
	}
	mem := ParseMeminfo(h.read("meminfo"))
	r.memTotal = mem["MemTotal"]
	if avail, ok := mem["MemAvailable"]; ok {
		r.memUsed = r.memTotal - avail
	} else {
		r.memUsed = r.memTotal - mem["MemFree"] - mem["Buffers"] - mem["Cached"]
	}
	nc := ParseNetCounters(h.read("net/dev"))
	r.rx, r.tx = nc.RXBytes, nc.TXBytes
	return r
}
