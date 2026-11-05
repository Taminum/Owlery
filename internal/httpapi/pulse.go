package httpapi

import (
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

// pulseFresh is how old a quick reading may be and still be shown instead of the last full one: a few intervals of five seconds.
const pulseFresh = 20 * time.Second

// applyPulse lays the machine's quick reading over its last full one, so the numbers on the server list and card move between the
// full readings. Only what the pulse measures is replaced; an old pulse, or none, leaves the full reading as it was.
func (s *Server) applyPulse(h *store.HostRow, vpsID string, now time.Time) {
	if h == nil || !h.HasData || s.Pulses == nil {
		return
	}
	p, ok := s.Pulses.Get(vpsID, now, pulseFresh)
	if !ok {
		return
	}
	if p.CPUPct >= 0 && p.CPUPct <= 100 {
		v := p.CPUPct
		h.CPUPct = &v
	}
	if p.MemTotal > 0 && p.MemUsed >= 0 && p.MemUsed <= p.MemTotal {
		h.MemUsed = p.MemUsed
		h.MemTotal = p.MemTotal
	}
	if p.RXBps >= 0 && p.TXBps >= 0 {
		h.RXBps, h.TXBps = float64(p.RXBps), float64(p.TXBps)
	}
}
