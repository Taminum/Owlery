package pulse

import (
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

func TestAPulseIsUsedWhileFreshAndForgotten(t *testing.T) {
	c := New()
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	if _, ok := c.Get("a", now, 15*time.Second); ok {
		t.Fatal("nothing yet")
	}
	c.Set("a", secproto.Pulse{CPUPct: 12.5, MemUsed: 100}, now)
	p, ok := c.Get("a", now.Add(10*time.Second), 15*time.Second)
	if !ok || p.CPUPct != 12.5 || p.MemUsed != 100 {
		t.Fatalf("%+v %v", p, ok)
	}
	if _, ok := c.Get("a", now.Add(16*time.Second), 15*time.Second); ok {
		t.Fatal("an old pulse says nothing about now")
	}
	if _, ok := c.Get("b", now, 15*time.Second); ok {
		t.Fatal("another machine has none")
	}
	c.Forget("a")
	if _, ok := c.Get("a", now, 15*time.Second); ok {
		t.Fatal("forgotten")
	}
}
