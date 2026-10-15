package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// NotifyChannel is one place notifications go to. Its secret is sealed and never leaves the store through
// the list: only Open (for the sender) returns it.
type NotifyChannel struct {
	ID        string     `json:"id"`
	Kind      string     `json:"kind"`
	Name      string     `json:"name"`
	ChatHint  string     `json:"chat_hint"`
	Enabled   bool       `json:"enabled"`
	OnAlerts  bool       `json:"on_alerts"`
	DigestHr  *int       `json:"digest_hour"`
	DigestTZ  string     `json:"digest_tz"`
	LastOKAt  *time.Time `json:"last_ok_at"`
	LastError *string    `json:"last_error"`
	CreatedAt time.Time  `json:"created_at"`
	DigestOn  *time.Time `json:"-"`
}

// NotifySecret is the sealed credential of a channel.
type NotifySecret struct {
	Ciphertext, Nonce []byte
	KeyVersion        int
}

const notifyCols = `id, kind, name, chat_hint, enabled, on_alerts, digest_hour, digest_tz, last_ok_at, last_error, created_at, digest_sent_on`

func scanNotify(r pgx.Row) (NotifyChannel, error) {
	var c NotifyChannel
	var id uuid.UUID
	err := r.Scan(&id, &c.Kind, &c.Name, &c.ChatHint, &c.Enabled, &c.OnAlerts, &c.DigestHr, &c.DigestTZ, &c.LastOKAt, &c.LastError, &c.CreatedAt, &c.DigestOn)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	c.ID = id.String()
	return c, err
}

const MaxNotifyChannels = 5

// CreateNotifyChannel stores a channel. Alerts that are open now are marked as announced, so that adding a
// channel does not start with a flood about things the owner can already see.
func (s *Store) CreateNotifyChannel(ctx context.Context, name, hint string, sec NotifySecret, onAlerts bool, digestHour *int, tz string) (NotifyChannel, error) {
	var out NotifyChannel
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM notify_channels`).Scan(&n); err != nil {
			return err
		}
		if n >= MaxNotifyChannels {
			return ErrLimit
		}
		var err error
		out, err = scanNotify(tx.QueryRow(ctx, `INSERT INTO notify_channels (kind, name, secret_ct, secret_nonce, secret_key_version, chat_hint, on_alerts, digest_hour, digest_tz)
			VALUES ('telegram',$1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+notifyCols, name, sec.Ciphertext, sec.Nonce, sec.KeyVersion, hint, onAlerts, digestHour, tz))
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE alerts SET notified_open_at = COALESCE(notified_open_at, now()) WHERE resolved_at IS NULL`)
		return err
	})
	return out, err
}

func (s *Store) ListNotifyChannels(ctx context.Context) ([]NotifyChannel, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+notifyCols+` FROM notify_channels ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NotifyChannel{}
	for rows.Next() {
		c, err := scanNotify(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// NotifyChannelSecret returns the sealed credential of one channel.
func (s *Store) NotifyChannelSecret(ctx context.Context, id string) (NotifySecret, error) {
	u, err := ParseID(id)
	if err != nil {
		return NotifySecret{}, ErrNotFound
	}
	var sec NotifySecret
	err = s.pool.QueryRow(ctx, `SELECT secret_ct, secret_nonce, secret_key_version FROM notify_channels WHERE id=$1`, u).Scan(&sec.Ciphertext, &sec.Nonce, &sec.KeyVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return sec, ErrNotFound
	}
	return sec, err
}

type NotifyPatch struct {
	Enabled    *bool
	OnAlerts   *bool
	SetDigest  bool // DigestHour is applied (nil clears the digest)
	DigestHour *int
	DigestTZ   *string
}

func (s *Store) PatchNotifyChannel(ctx context.Context, id string, p NotifyPatch) (NotifyChannel, error) {
	u, err := ParseID(id)
	if err != nil {
		return NotifyChannel{}, ErrNotFound
	}
	return scanNotify(s.pool.QueryRow(ctx, `UPDATE notify_channels SET enabled=COALESCE($2, enabled), on_alerts=COALESCE($3, on_alerts),
			digest_hour = CASE WHEN $4 THEN $5::integer ELSE digest_hour END, digest_tz = COALESCE($6, digest_tz),
			digest_sent_on = CASE WHEN $4 THEN NULL ELSE digest_sent_on END
		WHERE id=$1 RETURNING `+notifyCols, u, p.Enabled, p.OnAlerts, p.SetDigest, p.DigestHour, p.DigestTZ))
}

func (s *Store) DeleteNotifyChannel(ctx context.Context, id string) error {
	u, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM notify_channels WHERE id=$1`, u)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// NotifyResult records how the last send went. The error is a fixed word, never the response body.
func (s *Store) NotifyResult(ctx context.Context, id string, ok bool, code string) error {
	u, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	if ok {
		_, err = s.pool.Exec(ctx, `UPDATE notify_channels SET last_ok_at=now(), last_error=NULL WHERE id=$1`, u)
	} else {
		_, err = s.pool.Exec(ctx, `UPDATE notify_channels SET last_error=$2 WHERE id=$1`, u, code)
	}
	return err
}

// MarkDigestSent remembers that the digest of the given local day was sent.
func (s *Store) MarkDigestSent(ctx context.Context, id string, day time.Time) error {
	u, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `UPDATE notify_channels SET digest_sent_on=$2::date WHERE id=$1`, u, day.Format("2006-01-02"))
	return err
}

// PendingAlertNotice is an alert that has to be announced as opened or as closed.
type PendingAlertNotice struct {
	ID       string
	Kind     string
	Label    string
	Detail   string
	Closed   bool
	OpenedAt time.Time
}

// PendingAlertNotices lists alerts not yet announced: opened ones, and closed ones whose opening was announced.
func (s *Store) PendingAlertNotices(ctx context.Context, limit int) ([]PendingAlertNotice, error) {
	rows, err := s.pool.Query(ctx, `
SELECT id, kind, label, detail, false, opened_at FROM alerts WHERE resolved_at IS NULL AND notified_open_at IS NULL
UNION ALL
SELECT id, kind, label, detail, true, opened_at FROM alerts WHERE resolved_at IS NOT NULL AND notified_open_at IS NOT NULL AND notified_close_at IS NULL
ORDER BY 6 LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingAlertNotice
	for rows.Next() {
		var n PendingAlertNotice
		var id uuid.UUID
		if err := rows.Scan(&id, &n.Kind, &n.Label, &n.Detail, &n.Closed, &n.OpenedAt); err != nil {
			return nil, err
		}
		n.ID = id.String()
		out = append(out, n)
	}
	return out, rows.Err()
}

// MarkAlertsNotified records that the given announcements went out.
func (s *Store) MarkAlertsNotified(ctx context.Context, opened, closed []string) error {
	if len(opened) > 0 {
		if _, err := s.pool.Exec(ctx, `UPDATE alerts SET notified_open_at=now() WHERE id = ANY($1::uuid[])`, uuids(opened)); err != nil {
			return err
		}
	}
	if len(closed) > 0 {
		if _, err := s.pool.Exec(ctx, `UPDATE alerts SET notified_close_at=now() WHERE id = ANY($1::uuid[])`, uuids(closed)); err != nil {
			return err
		}
	}
	return nil
}
