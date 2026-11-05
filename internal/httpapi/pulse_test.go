package httpapi

import (
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/pulse"
	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/store"
)

func TestAFreshPulseReplacesWhatItMeasuresAndNothingElse(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	cache := pulse.New()
	s := &Server{Pulses: cache}
	cpu := 10.0
	host := func() *store.HostRow {
		return &store.HostRow{HasData: true, CPUPct: &cpu, MemUsed: 100, MemTotal: 1000, RXBps: 1, TXBps: 2, Load1: 0.7, Estab: 5}
	}
	// No pulse: the full reading stands.
	h := host()
	s.applyPulse(h, "a", now)
	if *h.CPUPct != 10 || h.MemUsed != 100 {
		t.Fatalf("%+v", h)
	}
	cache.Set("a", secproto.Pulse{CPUPct: 42.5, MemUsed: 600, MemTotal: 1000, RXBps: 5000, TXBps: 7000}, now)
	h = host()
	s.applyPulse(h, "a", now.Add(5*time.Second))
	if *h.CPUPct != 42.5 || h.MemUsed != 600 || h.RXBps != 5000 || h.TXBps != 7000 {
		t.Errorf("the pulse's numbers: %+v", h)
	}
	if h.Load1 != 0.7 || h.Estab != 5 {
		t.Errorf("what the pulse does not measure stays: %+v", h)
	}
	// An old pulse, a machine without data and nonsense do nothing.
	h = host()
	s.applyPulse(h, "a", now.Add(time.Minute))
	if *h.CPUPct != 10 {
		t.Errorf("an old pulse: %v", *h.CPUPct)
	}
	nodata := &store.HostRow{CPUPct: &cpu}
	s.applyPulse(nodata, "a", now)
	if *nodata.CPUPct != 10 {
		t.Error("no data, no pulse")
	}
	cache.Set("b", secproto.Pulse{CPUPct: 500, MemUsed: 2000, MemTotal: 1000, RXBps: -1}, now)
	h = host()
	s.applyPulse(h, "b", now)
	if *h.CPUPct != 10 || h.MemUsed != 100 || h.RXBps != 1 {
		t.Errorf("nonsense is not shown: %+v", h)
	}
	s.applyPulse(nil, "a", now)
	(&Server{}).applyPulse(host(), "a", now)
}
