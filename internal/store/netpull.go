package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Taminum/Owlery/internal/netdev"
	"github.com/Taminum/Owlery/internal/secrets"
)

// KindKeenetic is a router that Owlery asks itself, the others post what they know.
const KindKeenetic = "keenetic"

// NetPullAAD binds the sealed password of a router to that router.
func NetPullAAD(id string) string { return "netpull:" + id }

// NewNetDeviceID makes the id of a device before it is stored, so that its password can be sealed for it.
func NewNetDeviceID() string { return uuid.NewString() }

// CreatePullDevice adds a router that Owlery asks, with the address and login to ask with and its sealed password. The first
// reading is kept at once, so the page has something to show.
func (s *Store) CreatePullDevice(ctx context.Context, id, name, kind, url, login string, sealed secrets.Sealed, first netdev.Report, now time.Time) (NetDevice, error) {
	vid, err := ParseID(id)
	if err != nil {
		return NetDevice{}, ErrNotFound
	}
	name = cleanText(name, 60)
	if name == "" {
		return NetDevice{}, errors.New("store: empty name")
	}
	var d NetDevice
	err = s.pool.QueryRow(ctx, `INSERT INTO net_devices (id, name, kind, token_hash, pull_url, pull_login, pull_secret, pull_nonce, pull_key_version)
		VALUES ($1,$2,$3,'\x'::bytea,$4,$5,$6,$7,$8) RETURNING name, kind, created_at`,
		vid, name, kind, url, login, sealed.Ciphertext, sealed.Nonce, sealed.KeyVersion).Scan(&d.Name, &d.Kind, &d.CreatedAt)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return NetDevice{}, ErrConflict
	}
	if err != nil {
		return NetDevice{}, err
	}
	d.ID, d.View, d.PullURL = id, decodeView(nil), url
	if err := s.SaveNetReport(ctx, id, first, now); err != nil {
		return NetDevice{}, err
	}
	return d, nil
}

// PullDevice is what the poller needs to ask one router.
type PullDevice struct {
	ID     string
	Name   string
	URL    string
	Login  string
	Sealed secrets.Sealed
}

// PullDevices lists the live routers that are asked.
func (s *Store) PullDevices(ctx context.Context) ([]PullDevice, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, pull_url, pull_login, pull_secret, pull_nonce, pull_key_version FROM net_devices
		WHERE archived_at IS NULL AND pull_url IS NOT NULL AND pull_secret IS NOT NULL ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PullDevice
	for rows.Next() {
		var d PullDevice
		var id uuid.UUID
		if err := rows.Scan(&id, &d.Name, &d.URL, &d.Login, &d.Sealed.Ciphertext, &d.Sealed.Nonce, &d.Sealed.KeyVersion); err != nil {
			return nil, err
		}
		d.ID = id.String()
		out = append(out, d)
	}
	return out, rows.Err()
}

// SavePullError keeps why the last ask failed, for the page: a short code, not the router's words.
func (s *Store) SavePullError(ctx context.Context, id, code string, now time.Time) error {
	vid, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `UPDATE net_devices SET pull_error=$2, pull_error_at=$3 WHERE id=$1 AND archived_at IS NULL`, vid, cleanText(code, 20), now)
	return err
}

// SetPullSecret replaces the sealed password of a router that is asked, and forgets the old failure.
func (s *Store) SetPullSecret(ctx context.Context, id string, sealed secrets.Sealed) error {
	vid, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE net_devices SET pull_secret=$2, pull_nonce=$3, pull_key_version=$4, pull_error=NULL, pull_error_at=NULL
		WHERE id=$1 AND archived_at IS NULL AND pull_url IS NOT NULL`, vid, sealed.Ciphertext, sealed.Nonce, sealed.KeyVersion)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// NetPullRef is one sealed router password, for re-encrypting under a new master key.
type NetPullRef struct {
	DeviceID string
	Sealed   secrets.Sealed
}

func (s *Store) AllNetPull(ctx context.Context) ([]NetPullRef, error) {
	rs, err := s.pool.Query(ctx, `SELECT id, pull_secret, pull_nonce, pull_key_version FROM net_devices WHERE pull_secret IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []NetPullRef
	for rs.Next() {
		var r NetPullRef
		var id uuid.UUID
		if err := rs.Scan(&id, &r.Sealed.Ciphertext, &r.Sealed.Nonce, &r.Sealed.KeyVersion); err != nil {
			return nil, err
		}
		r.DeviceID = id.String()
		out = append(out, r)
	}
	return out, rs.Err()
}

// ReplaceNetPullIf swaps a password for its re-encrypted copy only if it still has the old key version.
func (s *Store) ReplaceNetPullIf(ctx context.Context, id string, oldVersion int, sl secrets.Sealed) (bool, error) {
	vid, err := ParseID(id)
	if err != nil {
		return false, ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE net_devices SET pull_secret=$2, pull_nonce=$3, pull_key_version=$4 WHERE id=$1 AND pull_key_version=$5`,
		vid, sl.Ciphertext, sl.Nonce, sl.KeyVersion, oldVersion)
	return tag.RowsAffected() == 1, err
}
