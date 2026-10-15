package secops

import (
	"context"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/secproto"
)

func TestProbeIsAnsweredOnlyByTheAgentItWasSentTo(t *testing.T) {
	h := New()
	sent := make(chan secproto.Probe, 1)
	h.Register("a1", func(_ context.Context, v any) error {
		sent <- v.(secproto.Probe)
		return nil
	})
	h.Register("a2", func(context.Context, any) error { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan secproto.ProbeResult, 1)
	go func() {
		r, err := h.Probe(ctx, "a1", secproto.Probe{Kind: "tcp", Host: "203.0.113.5", Port: 80})
		if err != nil {
			t.Error(err)
		}
		done <- r
	}()
	p := <-sent
	if p.Type != "probe" || p.ID == "" {
		t.Fatalf("%+v", p)
	}
	if h.Deliver("a2", secproto.ProbeResult{ID: p.ID, Result: "reachable"}) {
		t.Fatal("another agent answered for a1")
	}
	if h.Deliver("a1", secproto.ProbeResult{ID: "not-asked"}) {
		t.Fatal("an answer nobody asked for was taken")
	}
	if !h.Deliver("a1", secproto.ProbeResult{ID: p.ID, Result: "reachable"}) {
		t.Fatal("the right answer was dropped")
	}
	if r := <-done; r.Result != "reachable" {
		t.Fatalf("%+v", r)
	}
	// Nothing is left waiting, and an offline agent fails at once.
	if _, err := h.Probe(ctx, "gone", secproto.Probe{Kind: "tcp"}); err != ErrOffline {
		t.Fatalf("%v", err)
	}
	if h.Deliver("a1", secproto.ProbeResult{ID: p.ID}) {
		t.Fatal("a finished probe can be answered twice")
	}
}

func TestProbeTimesOutWithoutAnAnswer(t *testing.T) {
	h := New()
	h.Register("a1", func(context.Context, any) error { return nil })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := h.Probe(ctx, "a1", secproto.Probe{Kind: "tcp"}); err != ErrNoAnswer {
		t.Fatalf("%v", err)
	}
}
