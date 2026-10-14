package demo

import (
	"context"
	"errors"
	"time"

	"github.com/Taminum/RemnaScope/internal/store"
)

// Seed makes the demo panels real rows (flagged demo, no credential, never synced),
// so the same RBAC that protects real panels protects them too. It is idempotent.
func Seed(ctx context.Context, st *store.Store) error {
	for _, p := range Panels {
		if _, err := st.GetPanel(ctx, store.Scope{All: true}, p.ID); err == nil {
			continue
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if _, err := st.CreatePanel(ctx, p.ID, store.PanelInput{
			Name: p.Name, BaseURL: "https://demo.invalid", Demo: true, Status: "active",
			SyncOptions: store.SyncOptions{Nodes: true, Users: true},
		}, nil); err != nil {
			return err
		}
		recs := make([]store.NodeRecord, 0, len(p.Nodes))
		for _, n := range p.Nodes {
			recs = append(recs, store.NodeRecord{RemoteUUID: n.ID, Name: n.Name})
		}
		if _, err := st.UpsertNodes(ctx, p.ID, time.Now().UTC(), recs); err != nil {
			return err
		}
	}
	return nil
}
