// Package awglimits revokes AmneziaWG devices whose expiry date has passed or whose traffic allowance is used
// up. It does nothing the owner could not do by hand: it sends the same "revoke" command the Revoke button
// sends, to the agent that owns the device, and writes the outcome to the operations log and the audit log.
//
// A device is revoked only on a server the host lets Owlery manage, and only when its agent is connected;
// an offline agent is simply tried again on the next round. Nothing is queued on the host.
package awglimits

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/Taminum/Owlery/internal/awgops"
	"github.com/Taminum/Owlery/internal/ingestproto"
	"github.com/Taminum/Owlery/internal/store"
)

const (
	Every     = time.Minute
	opTimeout = 75 * time.Second
	maxPerRun = 20 // a bad clock or a mass expiry must not become a mass revocation in one minute
)

type Worker struct {
	Store *store.Store
	Ops   *awgops.Hub
	Log   *slog.Logger
	Now   func() time.Time
}

func (w *Worker) now() time.Time {
	if w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}

// Run checks every minute until ctx ends.
func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(Every)
	defer t.Stop()
	for {
		w.Round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Round revokes what is due, a few devices at a time. It returns how many were revoked.
func (w *Worker) Round(ctx context.Context) int {
	if w.Ops == nil {
		return 0
	}
	due, err := w.Store.AWGLimitsDue(ctx, w.now())
	if err != nil {
		w.Log.Error("awg limits: listing", "err", err)
		return 0
	}
	n := 0
	for _, d := range due {
		if n >= maxPerRun {
			break
		}
		if !w.Ops.Online(d.AgentID) {
			continue
		}
		octx, cancel := context.WithTimeout(ctx, opTimeout)
		res, err := w.Ops.Do(octx, d.AgentID, ingestproto.AWGOp{Op: "revoke", Container: d.Container, Key: d.Key})
		cancel()
		switch {
		case errors.Is(err, awgops.ErrOffline), errors.Is(err, awgops.ErrTimeout):
			continue // try again next round
		case err != nil:
			continue
		case res.Status != "ok" && res.Code != "not_found":
			// The host refused: leave the device as it is and say so, once per round, in the operations log.
			_ = w.Store.RecordAWGOperation(ctx, d.InstanceID, "revoke", d.Key, d.Label, "error", "auto_"+res.Code, "")
			w.Log.Warn("awg limits: the host refused a revocation", "container", d.Container, "code", res.Code)
			continue
		}
		// "not_found" means it is already absent on the host, which is what was wanted.
		if err := w.Store.MarkAWGAutoRevoked(ctx, d.PeerID, d.Reason); err != nil {
			w.Log.Error("awg limits: marking", "err", err)
			continue
		}
		_ = w.Store.RecordAWGOperation(ctx, d.InstanceID, "revoke", d.Key, d.Label, "ok", "auto_"+d.Reason, "")
		_ = w.Store.WriteAudit(ctx, store.AuditEntry{ActorName: "Owlery (device limit)", Action: "awg.auto_revoke", ObjectType: "awg_peer", ObjectID: d.PeerID,
			Metadata: map[string]any{"reason": d.Reason, "container": d.Container, "name": d.Label}})
		w.Log.Info("awg limits: device revoked", "container", d.Container, "reason", d.Reason)
		n++
	}
	return n
}
