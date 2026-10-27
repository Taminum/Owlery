package secops

import (
	"context"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Taminum/Owlery/internal/secproto"
)

func TestShellIsPairedOnlyWithTheAgentItWasAskedOf(t *testing.T) {
	h := New()
	asked := make(chan secproto.ShellOpen, 1)
	h.Register("a1", func(_ context.Context, v any) error {
		asked <- v.(secproto.ShellOpen)
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type res struct {
		c       *websocket.Conn
		release func()
		err     error
	}
	got := make(chan res, 1)
	go func() {
		c, rel, err := h.OpenShell(ctx, "a1", 100, 30)
		got <- res{c, rel, err}
	}()
	req := <-asked
	if req.Type != "shell_open" || req.ID == "" || req.Cols != 100 || req.Rows != 30 {
		t.Fatalf("%+v", req)
	}
	if h.AttachShell("a2", req.ID, &websocket.Conn{}) {
		t.Fatal("another agent took the session")
	}
	conn := &websocket.Conn{}
	attached := make(chan bool, 1)
	go func() { attached <- h.AttachShell("a1", req.ID, conn) }()
	r := <-got
	if r.err != nil || r.c != conn {
		t.Fatalf("%+v", r)
	}
	select {
	case <-attached:
		t.Fatal("the agent's side ended before the session")
	case <-time.After(50 * time.Millisecond):
	}
	r.release()
	if !<-attached {
		t.Fatal("attach reported a refusal")
	}
	if h.AttachShell("a1", req.ID, conn) {
		t.Fatal("a finished session was taken again")
	}
}

func TestShellTimesOutAndOfflineFails(t *testing.T) {
	h := New()
	h.Register("a1", func(context.Context, any) error { return nil })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := h.OpenShell(ctx, "a1", 80, 24); err != ErrNoShell {
		t.Fatalf("%v", err)
	}
	if _, _, err := h.OpenShell(context.Background(), "gone", 80, 24); err != ErrOffline {
		t.Fatalf("%v", err)
	}
}
