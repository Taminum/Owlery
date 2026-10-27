package store

import (
	"context"
	"encoding/json"
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
	// Fine tuning.
	Prefs      NotifyPrefs `json:"prefs"`
	Commands   bool        `json:"commands"`
	MutedUntil *time.Time  `json:"muted_until"`
	BotOffset  int64       `json:"-"`
}

// NotifyPrefs are the owner's choices about what is announced. The zero value announces everything.
type NotifyPrefs struct {
	Off         []string `json:"off,omitempty"`          // alert groups that are not announced
	NoResolved  bool     `json:"no_resolved,omitempty"`  // do not announce that an alert closed
	QuietOn     bool     `json:"quiet_on,omitempty"`     // hold what is not critical during the quiet hours
	QuietFrom   string   `json:"quiet_from,omitempty"`   // "23:00", in the channel's time zone
	QuietTo     string   `json:"quiet_to,omitempty"`     // "08:00"
	RemindHours int      `json:"remind_hours,omitempty"` // repeat an alert that is still open every so many hours; 0 never
}

// GroupOff says whether an alert kind belongs to a group the owner switched off.
func (p NotifyPrefs) GroupOff(kind string) bool {
	g := AlertGroupOf(kind)
	if g == "" {
		return false
	}
	for _, o := range p.Off {
		if o == g {
			return true
		}
	}
	return false
}

// NotifySecret is the sealed credential of a channel.
type NotifySecret struct {
	Ciphertext, Nonce []byte
	KeyVersion        int
}

const notifyCols = `id, kind, name, chat_hint, enabled, on_alerts, digest_hour, digest_tz, last_ok_at, last_error, created_at, digest_sent_on, prefs, commands, muted_until, bot_offset`

func scanNotify(r pgx.Row) (NotifyChannel, error) {
	var c NotifyChannel
	var id uuid.UUID
	var prefs []byte
	err := r.Scan(&id, &c.Kind, &c.Name, &c.ChatHint, &c.Enabled, &c.OnAlerts, &c.DigestHr, &c.DigestTZ, &c.LastOKAt, &c.LastError, &c.CreatedAt, &c.DigestOn, &prefs, &c.Commands, &c.MutedUntil, &c.BotOffset)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	c.ID = id.String()
	if len(prefs) > 0 {
		_ = json.Unmarshal(prefs, &c.Prefs)
	}
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
	Prefs      *NotifyPrefs
	Commands   *bool
	SetMute    bool // MutedUntil is applied (nil clears the mute)
	MutedUntil *time.Time
}

func (s *Store) PatchNotifyChannel(ctx context.Context, id string, p NotifyPatch) (NotifyChannel, error) {
	u, err := ParseID(id)
	if err != nil {
		return NotifyChannel{}, ErrNotFound
	}
	var prefs []byte
	if p.Prefs != nil {
		prefs, _ = json.Marshal(p.Prefs)
	}
	return scanNotify(s.pool.QueryRow(ctx, `UPDATE notify_channels SET enabled=COALESCE($2, enabled), on_alerts=COALESCE($3, on_alerts),
			digest_hour = CASE WHEN $4 THEN $5::integer ELSE digest_hour END, digest_tz = COALESCE($6, digest_tz),
			digest_sent_on = CASE WHEN $4 THEN NULL ELSE digest_sent_on END,
			prefs = COALESCE($7::jsonb, prefs), commands = COALESCE($8, commands),
			muted_until = CASE WHEN $9 THEN $10::timestamptz ELSE muted_until END
		WHERE id=$1 RETURNING `+notifyCols, u, p.Enabled, p.OnAlerts, p.SetDigest, p.DigestHour, p.DigestTZ, prefs, p.Commands, p.SetMute, p.MutedUntil))
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
SELECT id, kind, label, detail, false, opened_at FROM alerts WHERE resolved_at IS NULL AND notified_open_at IS NULL AND opened_at <= now() - make_interval(secs => $2)
UNION ALL
SELECT id, kind, label, detail, true, opened_at FROM alerts WHERE resolved_at IS NOT NULL AND notified_open_at IS NOT NULL AND notified_close_at IS NULL
ORDER BY 6 LIMIT $1`, limit, AlertGrace.Seconds())
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

// AlertsDueReminder lists open, already announced alerts whose last announcement (the opening or the last
// reminder) is older than the cut-off.
func (s *Store) AlertsDueReminder(ctx context.Context, before time.Time, limit int) ([]PendingAlertNotice, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, kind, label, detail, opened_at FROM alerts
		WHERE resolved_at IS NULL AND notified_open_at IS NOT NULL AND COALESCE(reminded_at, notified_open_at) < $1 ORDER BY opened_at LIMIT $2`, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingAlertNotice
	for rows.Next() {
		var n PendingAlertNotice
		var id uuid.UUID
		if err := rows.Scan(&id, &n.Kind, &n.Label, &n.Detail, &n.OpenedAt); err != nil {
			return nil, err
		}
		n.ID = id.String()
		out = append(out, n)
	}
	return out, rows.Err()
}

// MarkAlertsReminded records that the given alerts were repeated now.
func (s *Store) MarkAlertsReminded(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx, `UPDATE alerts SET reminded_at=now() WHERE id = ANY($1::uuid[])`, uuids(ids))
	return err
}

// SetBotOffset remembers the last update of the bot that was handled.
func (s *Store) SetBotOffset(ctx context.Context, id string, offset int64) error {
	u, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `UPDATE notify_channels SET bot_offset=$2 WHERE id=$1`, u, offset)
	return err
}
