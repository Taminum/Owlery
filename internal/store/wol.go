package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Taminum/Owlery/internal/secproto"
)

// WolTarget is what is kept for a machine that Wake-on-LAN is turned on for.
type WolTarget struct {
	MAC  string
	NICs []secproto.WolNIC
}

// GetWol returns a machine's Wake-on-LAN setting; ok is false when it is off.
func (s *Store) GetWol(ctx context.Context, vpsID string) (t WolTarget, ok bool, err error) {
	id, perr := ParseID(vpsID)
	if perr != nil {
		return t, false, nil
	}
	var raw []byte
	err = s.pool.QueryRow(ctx, `SELECT mac, nics FROM wol_targets WHERE vps_id=$1`, id).Scan(&t.MAC, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, false, nil
	}
	if err != nil {
		return t, false, err
	}
	_ = json.Unmarshal(raw, &t.NICs)
	return t, true, nil
}

// SetWol turns Wake-on-LAN on for a machine, or renews its cards and chosen address.
func (s *Store) SetWol(ctx context.Context, vpsID, mac string, nics []secproto.WolNIC) error {
	id, err := ParseID(vpsID)
	if err != nil {
		return ErrNotFound
	}
	raw, _ := json.Marshal(nics)
	_, err = s.pool.Exec(ctx, `INSERT INTO wol_targets (vps_id, mac, nics) VALUES ($1, $2, $3)
		ON CONFLICT (vps_id) DO UPDATE SET mac=$2, nics=$3, updated_at=now()`, id, mac, raw)
	return err
}

// ClearWol turns it off and forgets the address.
func (s *Store) ClearWol(ctx context.Context, vpsID string) error {
	id, err := ParseID(vpsID)
	if err != nil {
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `DELETE FROM wol_targets WHERE vps_id=$1`, id)
	return err
}

// WolNeighbors lists the live agents of other machines that connected from the same outside address as this machine's agent: the
// same network, so one of them can broadcast the packet.
func (s *Store) WolNeighbors(ctx context.Context, vpsID string) ([]SecAgent, error) {
	id, err := ParseID(vpsID)
	if err != nil {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT `+secAgentCols+` FROM security_agents
		WHERE status='active' AND vps_id <> $1 AND remote_ip <> ''
		  AND remote_ip = (SELECT remote_ip FROM security_agents WHERE vps_id=$1 AND status <> 'revoked' AND remote_ip <> '' LIMIT 1)
		ORDER BY last_seen DESC NULLS LAST`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecAgent
	for rows.Next() {
		a, err := scanSecAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// WolEnabled says, of the given machines, which have Wake-on-LAN turned on.
func (s *Store) WolEnabled(ctx context.Context, vpsIDs []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(vpsIDs) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT vps_id::text FROM wol_targets WHERE vps_id = ANY($1::uuid[])`, vpsIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}
