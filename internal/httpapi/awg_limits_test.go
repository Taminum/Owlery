package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/awglimits"
	"io"
	"log/slog"
)

func TestADeviceIsRevokedWhenItsTimeOrAllowanceIsOver(t *testing.T) {
	w, host, _ := managedWorld(t)
	ctx := context.Background()
	rows, err := w.h.st.Pool().Query(ctx, `SELECT id::text FROM awg_peers WHERE gone_at IS NULL ORDER BY label`)
	if err != nil {
		t.Fatal(err)
	}
	var peers []string
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		peers = append(peers, id)
	}
	rows.Close()
	if len(peers) < 2 {
		t.Fatalf("the fixture needs two devices: %d", len(peers))
	}
	expiring, heavy := peers[0], peers[1]
	wk := &awglimits.Worker{Store: w.h.st, Ops: host.hub, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// Validation: only the owner, only a future date, only a sensible allowance.
	put := func(c *client, id string, body map[string]any) int {
		st, _ := c.do("PUT", "/api/v1/awg/peers/"+id+"/limits", body)
		return st
	}
	if st := put(w.viewer, expiring, map[string]any{"expires_at": time.Now().Add(time.Hour)}); st != 403 {
		t.Fatalf("a viewer set a limit: %d", st)
	}
	if st := put(w.owner, expiring, map[string]any{"expires_at": time.Now().Add(-time.Hour)}); st != 422 {
		t.Fatalf("a past expiry was accepted: %d", st)
	}
	if st := put(w.owner, heavy, map[string]any{"traffic_limit_bytes": 1000}); st != 422 {
		t.Fatalf("a tiny allowance was accepted: %d", st)
	}
	if st := put(w.owner, expiring, map[string]any{"expires_at": time.Now().Add(time.Hour)}); st != 204 {
		t.Fatalf("%d", st)
	}
	if st := put(w.owner, heavy, map[string]any{"traffic_limit_bytes": 20 << 20}); st != 204 {
		t.Fatalf("%d", st)
	}

	// Nothing is due yet.
	if n := wk.Round(ctx); n != 0 {
		t.Fatalf("revoked too early: %d", n)
	}
	host.mu.Lock()
	before := len(host.ops)
	host.mu.Unlock()

	// Time passes for one device; the other uses more than its allowance since the limit was set.
	if _, err := w.h.st.Pool().Exec(ctx, `UPDATE awg_peers SET expires_at = now() - interval '1 minute' WHERE id=$1`, expiring); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().Add(time.Minute)
	for i, rx := range []int64{0, 15 << 20, 30 << 20} {
		if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO awg_samples (peer_id, ts, rx_bytes, tx_bytes) VALUES ($1,$2,$3,0)`, heavy, t0.Add(time.Duration(i)*time.Minute), rx); err != nil {
			t.Fatal(err)
		}
	}
	if n := wk.Round(ctx); n != 2 {
		t.Fatalf("revoked %d, want 2", n)
	}
	host.mu.Lock()
	ops := host.ops[before:]
	host.mu.Unlock()
	if len(ops) != 2 || ops[0].Op != "revoke" || ops[1].Op != "revoke" {
		t.Fatalf("%+v", ops)
	}
	reason := func(id string) (string, bool) {
		var r *string
		var gone bool
		_ = w.h.st.Pool().QueryRow(ctx, `SELECT auto_revoked_reason, gone_at IS NOT NULL FROM awg_peers WHERE id=$1`, id).Scan(&r, &gone)
		if r == nil {
			return "", gone
		}
		return *r, gone
	}
	if r, g := reason(expiring); r != "expired" || !g {
		t.Fatalf("expiring: %q %v", r, g)
	}
	if r, g := reason(heavy); r != "traffic_limit" || !g {
		t.Fatalf("heavy: %q %v", r, g)
	}
	// A second round finds nothing more to do, and the list says why each device went.
	if n := wk.Round(ctx); n != 0 {
		t.Fatalf("revoked again: %d", n)
	}
	_, b := w.owner.get("/api/v1/awg")
	if !strings.Contains(string(b), `"auto_revoked":"expired"`) || !strings.Contains(string(b), `"auto_revoked":"traffic_limit"`) {
		var any map[string]any
		_ = json.Unmarshal(b, &any)
		t.Fatalf("the list does not say why: %s", b)
	}
}

func TestLimitsAreRefusedOnAReadOnlyServer(t *testing.T) {
	w, _, _ := managedWorld(t)
	ctx := context.Background()
	var peer string
	if err := w.h.st.Pool().QueryRow(ctx, `SELECT id::text FROM awg_peers WHERE gone_at IS NULL LIMIT 1`).Scan(&peer); err != nil {
		t.Fatal(err)
	}
	if _, err := w.h.st.Pool().Exec(ctx, `UPDATE awg_instances SET mode='read_only'`); err != nil {
		t.Fatal(err)
	}
	st, b := w.owner.do("PUT", "/api/v1/awg/peers/"+peer+"/limits", map[string]any{"traffic_limit_bytes": 50 << 20})
	if st != 409 || !strings.Contains(string(b), "not_managed") {
		t.Fatalf("%d %s", st, b)
	}
}
