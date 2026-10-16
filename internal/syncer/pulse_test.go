package syncer

import (
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/store"
)

func TestPulseShowsOnlyThePanelsInScopeAndKeepsTheLastReadingOnAFailure(t *testing.T) {
	p := NewPulse()
	p.set(PanelPulse{PanelID: "a", At: time.Now(), Nodes: []NodeSpeed{{Name: "n", DownBps: 5}}})
	p.set(PanelPulse{PanelID: "b", At: time.Now()})
	if got := p.For(store.Scope{IDs: []string{"a"}}, []string{"a", "b"}); len(got) != 1 || got[0].PanelID != "a" {
		t.Fatalf("%+v", got)
	}
	// A failed try marks the error on the old reading and does not erase it.
	p.mu.Lock()
	v := p.last["a"]
	p.mu.Unlock()
	v.Err = "timeout"
	p.set(v)
	if got := p.For(store.Scope{All: true}, []string{"a"}); got[0].Err != "timeout" || len(got[0].Nodes) != 1 {
		t.Fatalf("%+v", got)
	}
	p.forget("a")
	if got := p.For(store.Scope{All: true}, []string{"a"}); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}
