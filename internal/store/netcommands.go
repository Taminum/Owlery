package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The things a router that reports by a script may be asked to do. The script knows exactly these and nothing else.
const (
	CmdBlock     = "block"     // a1 = MAC
	CmdUnblock   = "unblock"   // a1 = MAC
	CmdReserve   = "reserve"   // a1 = MAC, a2 = the address it has now
	CmdUnreserve = "unreserve" // a1 = MAC
	CmdReboot    = "reboot"
)

var netCommandKinds = map[string]bool{CmdBlock: true, CmdUnblock: true, CmdReserve: true, CmdUnreserve: true, CmdReboot: true}

const (
	maxPendingCommands = 20
	commandRetryAfter  = 3 * time.Minute
	commandTries       = 3
)

// NetCommand is one thing asked of a router, and how it went.
type NetCommand struct {
	ID        int64      `json:"id"`
	Kind      string     `json:"kind"`
	A1        string     `json:"a1,omitempty"`
	A2        string     `json:"a2,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	State     string     `json:"state"` // waiting, sent, done, failed
	Note      string     `json:"note,omitempty"`
	DoneAt    *time.Time `json:"done_at,omitempty"`
}

// EnqueueNetCommand asks a router (one that reports by a script) to do something. The same thing already waiting is not asked twice.
func (s *Store) EnqueueNetCommand(ctx context.Context, deviceID, kind, a1, a2 string) (int64, error) {
	vid, err := ParseID(deviceID)
	if err != nil || !netCommandKinds[kind] {
		return 0, ErrNotFound
	}
	var id int64
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var k string
		if err := tx.QueryRow(ctx, `SELECT kind FROM net_devices WHERE id=$1 AND archived_at IS NULL FOR UPDATE`, vid).Scan(&k); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if k == KindKeenetic {
			return ErrNotFound // a Keenetic is changed by Owlery itself, not through a queue
		}
		if err := tx.QueryRow(ctx, `SELECT id FROM net_commands WHERE device_id=$1 AND kind=$2 AND a1=$3 AND a2=$4 AND done_at IS NULL AND tries<$5`, vid, kind, a1, a2, commandTries).Scan(&id); err == nil {
			return nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var pending int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM net_commands WHERE device_id=$1 AND done_at IS NULL AND tries<$2`, vid, commandTries).Scan(&pending); err != nil {
			return err
		}
		if pending >= maxPendingCommands {
			return ErrConflict
		}
		return tx.QueryRow(ctx, `INSERT INTO net_commands (device_id, kind, a1, a2) VALUES ($1,$2,$3,$4) RETURNING id`, vid, kind, a1, a2).Scan(&id)
	})
	return id, err
}

// NextNetCommand hands the router its oldest open command, or none. A command that was handed out and not answered is handed out
// again after a while, up to a few times; a reboot is never handed out twice, because it cannot answer before it is gone.
func (s *Store) NextNetCommand(ctx context.Context, deviceID string, now time.Time) (*NetCommand, error) {
	vid, err := ParseID(deviceID)
	if err != nil {
		return nil, ErrNotFound
	}
	var c NetCommand
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id, kind, a1, a2, created_at FROM net_commands
WHERE device_id=$1 AND done_at IS NULL AND tries<$2 AND (sent_at IS NULL OR sent_at < $3)
ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED`, vid, commandTries, now.Add(-commandRetryAfter)).Scan(&c.ID, &c.Kind, &c.A1, &c.A2, &c.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if c.Kind == CmdReboot {
			_, err = tx.Exec(ctx, `UPDATE net_commands SET sent_at=$2, tries=tries+1, done_at=$2, ok=true, note='sent' WHERE id=$1`, c.ID, now)
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE net_commands SET sent_at=$2, tries=tries+1 WHERE id=$1`, c.ID, now)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// AckNetCommand records how a command went on the router.
func (s *Store) AckNetCommand(ctx context.Context, deviceID string, id int64, ok bool, note string, now time.Time) error {
	vid, err := ParseID(deviceID)
	if err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE net_commands SET done_at=$3, ok=$4, note=$5 WHERE id=$1 AND device_id=$2 AND done_at IS NULL`, id, vid, now, ok, cleanText(note, 120))
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// recentNetCommands lists, for each router, what was asked of it in the last day, newest first, at most five.
func (s *Store) recentNetCommands(ctx context.Context, now time.Time) (map[string][]NetCommand, error) {
	rows, err := s.pool.Query(ctx, `SELECT device_id, id, kind, a1, a2, created_at, done_at, ok, note, tries FROM (
  SELECT *, row_number() OVER (PARTITION BY device_id ORDER BY id DESC) AS rn FROM net_commands WHERE created_at > $1) x WHERE rn <= 5 ORDER BY id DESC`, now.Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]NetCommand{}
	for rows.Next() {
		var dev uuid.UUID
		var c NetCommand
		var ok *bool
		var tries int
		if err := rows.Scan(&dev, &c.ID, &c.Kind, &c.A1, &c.A2, &c.CreatedAt, &c.DoneAt, &ok, &c.Note, &tries); err != nil {
			return nil, err
		}
		switch {
		case c.DoneAt != nil && ok != nil && *ok:
			c.State = "done"
		case c.DoneAt != nil:
			c.State = "failed"
		case tries >= commandTries:
			c.State, c.Note = "failed", "роутер не ответил"
		case tries > 0:
			c.State = "sent"
		default:
			c.State = "waiting"
		}
		out[dev.String()] = append(out[dev.String()], c)
	}
	return out, rows.Err()
}

// RotateNetToken gives a router that reports by a script a new token (the old one stops working at once).
func (s *Store) RotateNetToken(ctx context.Context, id string, hash []byte) error {
	vid, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE net_devices SET token_hash=$2 WHERE id=$1 AND archived_at IS NULL AND kind <> $3`, vid, hash, KindKeenetic)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
