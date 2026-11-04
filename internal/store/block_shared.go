package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// SharedBlock is an address one machine blocked that the others are asked to block too.
type SharedBlock struct {
	IP    string
	Since time.Time
	Until *time.Time // nil: no end
}

// MaxSharedBlocks bounds what is passed to a machine that has just connected.
const MaxSharedBlocks = 200

// ShareBlock records an address a machine blocked. It says whether this is news: false when the address is already on the
// list and its block has not ended, so one block is passed on once, not at every report.
func (s *Store) ShareBlock(ctx context.Context, vpsID, ip string, since time.Time, until *time.Time) (bool, error) {
	vid, err := ParseID(vpsID)
	if err != nil {
		return false, ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO security_shared_blocks (ip, source_vps, since, until) VALUES ($1, $2, $3, $4)
		ON CONFLICT (ip) DO UPDATE SET source_vps=$2, since=$3, until=$4
		WHERE security_shared_blocks.until IS NOT NULL AND security_shared_blocks.until <= now()`, ip, vid, since, until)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// DropSharedBlock takes an address off the list, so that it is not passed on again to machines that connect later.
func (s *Store) DropSharedBlock(ctx context.Context, ip string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM security_shared_blocks WHERE ip=$1`, ip)
	return err
}

// ActiveSharedBlocks lists the blocks still in force that other machines made.
func (s *Store) ActiveSharedBlocks(ctx context.Context, exceptVPS string) ([]SharedBlock, error) {
	vid, err := ParseID(exceptVPS)
	if err != nil {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT ip, since, until FROM security_shared_blocks WHERE source_vps <> $1 AND (until IS NULL OR until > now()) ORDER BY since DESC LIMIT $2`, vid, MaxSharedBlocks)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SharedBlock
	for rows.Next() {
		var b SharedBlock
		if err := rows.Scan(&b.IP, &b.Since, &b.Until); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ShareOn says whether a machine takes part in the shared list (it does until somebody turns it off).
func (s *Store) ShareOn(ctx context.Context, vpsID string) bool {
	vid, err := ParseID(vpsID)
	if err != nil {
		return false
	}
	on := true
	err = s.pool.QueryRow(ctx, `SELECT share FROM security_block_settings WHERE vps_id=$1`, vid).Scan(&on)
	if err != nil && err != pgx.ErrNoRows {
		return false
	}
	return on
}

// SharePeers lists the other live machines that take part in the shared list.
func (s *Store) SharePeers(ctx context.Context, exceptVPS string) ([]string, error) {
	vid, err := ParseID(exceptVPS)
	if err != nil {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT v.id::text FROM security_vps v LEFT JOIN security_block_settings b ON b.vps_id = v.id
		WHERE v.id <> $1 AND v.archived_at IS NULL AND v.enabled AND COALESCE(b.share, true)`, vid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
