package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Taminum/Owlery/internal/netdev"
)

// AlertNetForward: a router opened a port to the outside that the owner has not looked at yet.
const AlertNetForward = "net_new_forward"

const (
	// fwSeenWithin is how recently a router must have listed a forward for it to count as open now.
	fwSeenWithin = 10 * time.Minute
	// fwBaselineWindow keeps the pieces of the first list together: what arrives within it after the first piece is still baseline.
	fwBaselineWindow = 3 * time.Minute
)

func forwardKey(n netdev.NatRule) string {
	return strings.Join([]string{n.Chain, n.Action, n.DstPort, n.ToAddr, n.ToPorts}, "|")
}

// recordForwards keeps the destination-NAT rules of one report. The first list a router gives is the baseline and counts as known.
func recordForwards(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID, r netdev.Report, now time.Time) error {
	var base *time.Time
	if err := tx.QueryRow(ctx, `SELECT fw_baseline_at FROM net_devices WHERE id=$1`, deviceID).Scan(&base); err != nil {
		return err
	}
	if base == nil && !r.ResetNat {
		return nil // no complete list yet: wait for the one that starts with the reset
	}
	known := base == nil || now.Sub(*base) < fwBaselineWindow
	for _, n := range r.Nat {
		if n.Chain != "dstnat" || n.Off || strings.HasPrefix(n.Action, "upnp") {
			continue
		}
		raw, err := json.Marshal(n)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO net_forwards (device_id, key, rule, first_seen, last_seen, confirmed) VALUES ($1,$2,$3,$4,$4,$5)
ON CONFLICT (device_id, key) DO UPDATE SET rule=EXCLUDED.rule, last_seen=EXCLUDED.last_seen`, deviceID, forwardKey(n), raw, now, known); err != nil {
			return err
		}
	}
	if base == nil {
		_, err := tx.Exec(ctx, `UPDATE net_devices SET fw_baseline_at=$2 WHERE id=$1`, deviceID, now)
		return err
	}
	return nil
}

// NewForwards lists, for each router, the open forwards nobody has looked at yet and that the router still lists.
func (s *Store) newForwards(ctx context.Context, now time.Time) (map[string][]netdev.NatRule, error) {
	rows, err := s.pool.Query(ctx, `SELECT device_id, rule FROM net_forwards WHERE NOT confirmed AND last_seen > $1 AND rule->>'action' NOT LIKE 'upnp%' ORDER BY first_seen, key`, now.Add(-fwSeenWithin))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]netdev.NatRule{}
	for rows.Next() {
		var id uuid.UUID
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		var n netdev.NatRule
		if json.Unmarshal(raw, &n) == nil {
			out[id.String()] = append(out[id.String()], n)
		}
	}
	return out, rows.Err()
}

// ConfirmForwards marks every forward of a router as looked at. It reports whether the router exists.
func (s *Store) ConfirmForwards(ctx context.Context, id string) error {
	vid, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM net_devices WHERE id=$1 AND archived_at IS NULL`, vid).Scan(&n); err != nil || n == 0 {
		if err != nil {
			return err
		}
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `UPDATE net_forwards SET confirmed=true WHERE device_id=$1`, vid)
	return err
}

// AllowForward records a rule as known: the owner made it themselves, so no alert is due.
func (s *Store) AllowForward(ctx context.Context, id string, n netdev.NatRule) error {
	vid, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	raw, err := json.Marshal(n)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO net_forwards (device_id, key, rule, confirmed) VALUES ($1,$2,$3,true)
ON CONFLICT (device_id, key) DO UPDATE SET confirmed=true`, vid, forwardKey(n), raw)
	return err
}
