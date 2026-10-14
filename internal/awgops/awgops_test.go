package awgops

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/ingestproto"
)

func TestACommandReachesOnlyItsAgentAndTheAnswerComesBack(t *testing.T) {
	h := New()
	got := make(chan ingestproto.AWGOp, 1)
	h.Register("agent-a", func(_ context.Context, v any) error { got <- v.(ingestproto.AWGOp); return nil })
	h.Register("agent-b", func(context.Context, any) error { t.Error("another agent was sent the command"); return nil })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan ingestproto.AWGOpResult, 1)
	go func() {
		r, err := h.Do(ctx, "agent-a", ingestproto.AWGOp{Op: "add", Container: "c", Name: "Phone"})
		if err != nil {
			t.Error(err)
		}
		done <- r
	}()
	op := <-got
	if op.Type != "awg_op" || op.ID == "" || op.Op != "add" {
		t.Fatalf("%+v", op)
	}
	h.Deliver("agent-b", ingestproto.AWGOpResult{ID: op.ID, Status: "ok", Key: "spoofed"}) // not the agent asked: ignored
	h.Deliver("agent-a", ingestproto.AWGOpResult{ID: "no-such-command", Status: "ok"})     // unknown id: ignored
	select {
	case r := <-done:
		t.Fatalf("answered by the wrong party: %+v", r)
	case <-time.After(100 * time.Millisecond):
	}
	h.Deliver("agent-a", ingestproto.AWGOpResult{ID: op.ID, Status: "ok", Key: "real"})
	if r := <-done; r.Key != "real" {
		t.Fatalf("%+v", r)
	}
}

func TestOfflineTimeoutAndReconnect(t *testing.T) {
	h := New()
	if _, err := h.Do(context.Background(), "x", ingestproto.AWGOp{}); !errors.Is(err, ErrOffline) {
		t.Fatalf("%v", err)
	}
	un1 := h.Register("x", func(context.Context, any) error { return nil })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := h.Do(ctx, "x", ingestproto.AWGOp{}); !errors.Is(err, ErrTimeout) {
		t.Fatalf("%v", err)
	}
	// a new connection replaces the old; the old one's cleanup must not remove the new one
	un2 := h.Register("x", func(context.Context, any) error { return nil })
	un1()
	if !h.Online("x") {
		t.Fatal("the newer connection was removed by the older one's cleanup")
	}
	un2()
	if h.Online("x") {
		t.Fatal("still online")
	}
	h.Register("y", func(context.Context, any) error { return errors.New("write failed") })
	if _, err := h.Do(context.Background(), "y", ingestproto.AWGOp{}); !errors.Is(err, ErrOffline) {
		t.Fatalf("a failed send: %v", err)
	}
}
