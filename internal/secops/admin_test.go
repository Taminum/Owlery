package secops

import (
	"context"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

func TestAdminAnswerComesOnlyFromTheAgentAsked(t *testing.T) {
	h := New()
	asked := make(chan secproto.AdminReq, 1)
	h.Register("a1", func(_ context.Context, v any) error {
		asked <- v.(secproto.AdminReq)
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got := make(chan secproto.AdminResult, 1)
	go func() {
		r, err := h.Admin(ctx, "a1", secproto.AdminReq{Op: secproto.AdminProcs})
		if err != nil {
			t.Error(err)
		}
		got <- r
	}()
	req := <-asked
	if req.Type != "admin_req" || req.ID == "" || req.Op != secproto.AdminProcs {
		t.Fatalf("%+v", req)
	}
	if h.DeliverAdmin("a2", secproto.AdminResult{ID: req.ID, OK: true}) {
		t.Fatal("another agent answered")
	}
	if !h.DeliverAdmin("a1", secproto.AdminResult{ID: req.ID, OK: true}) {
		t.Fatal("the right agent was refused")
	}
	if r := <-got; !r.OK {
		t.Fatalf("%+v", r)
	}
	if h.DeliverAdmin("a1", secproto.AdminResult{ID: req.ID, OK: true}) {
		t.Fatal("an answer was accepted twice")
	}
}

func TestAdminOfflineAndTimeout(t *testing.T) {
	h := New()
	if _, err := h.Admin(context.Background(), "gone", secproto.AdminReq{Op: secproto.AdminProcs}); err != ErrOffline {
		t.Fatalf("%v", err)
	}
	h.Register("a1", func(context.Context, any) error { return nil })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := h.Admin(ctx, "a1", secproto.AdminReq{Op: secproto.AdminProcs}); err != ErrNoAnswer {
		t.Fatalf("%v", err)
	}
}
