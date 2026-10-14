package store

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Account struct {
	ID                string
	Username          string
	PasswordHash      string
	IsOwner           bool
	Disabled          bool
	FailedLogins      int
	LockedUntil       *time.Time
	PasswordChangedAt time.Time
	LastLoginAt       *time.Time
	CreatedAt         time.Time
	TOTPEnabled       bool
}

type Membership struct {
	PanelID string `json:"panel_id"`
	Role    string `json:"role"`
}

const accountCols = `id, username, password_hash, is_owner, disabled, failed_logins, locked_until, password_changed_at, last_login_at, created_at, totp_enabled_at IS NOT NULL`

func scanAccount(r pgx.Row) (Account, error) {
	var a Account
	var id uuid.UUID
	err := r.Scan(&id, &a.Username, &a.PasswordHash, &a.IsOwner, &a.Disabled, &a.FailedLogins, &a.LockedUntil, &a.PasswordChangedAt, &a.LastLoginAt, &a.CreatedAt, &a.TOTPEnabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	a.ID = id.String()
	return a, err
}

func (s *Store) CreateAccount(ctx context.Context, username, passwordHash string, owner bool) (Account, error) {
	row := s.pool.QueryRow(ctx, `INSERT INTO accounts (username, password_hash, is_owner) VALUES ($1,$2,$3) RETURNING `+accountCols, username, passwordHash, owner)
	a, err := scanAccount(row)
	if IsUniqueViolation(err) {
		return a, ErrConflict
	}
	return a, err
}

func (s *Store) AccountByUsername(ctx context.Context, username string) (Account, error) {
	return scanAccount(s.pool.QueryRow(ctx, `SELECT `+accountCols+` FROM accounts WHERE lower(username)=lower($1)`, username))
}

func (s *Store) AccountByID(ctx context.Context, id string) (Account, error) {
	u, err := ParseID(id)
	if err != nil {
		return Account{}, err
	}
	return scanAccount(s.pool.QueryRow(ctx, `SELECT `+accountCols+` FROM accounts WHERE id=$1`, u))
}

func (s *Store) CountAccounts(ctx context.Context) (int, error) {
	var n int
	return n, s.pool.QueryRow(ctx, `SELECT count(*) FROM accounts`).Scan(&n)
}

func (s *Store) ListAccounts(ctx context.Context) ([]Account, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+accountCols+` FROM accounts ORDER BY lower(username)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) SetAccountDisabled(ctx context.Context, id string, disabled bool) error {
	u, err := ParseID(id)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE accounts SET disabled=$2 WHERE id=$1`, u, disabled)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if disabled {
			_, err = tx.Exec(ctx, `DELETE FROM sessions WHERE account_id=$1`, u)
		}
		return err
	})
}

// SetPassword replaces the hash, clears lockout and signs the account out everywhere.
func (s *Store) SetPassword(ctx context.Context, id, hash string) error {
	u, err := ParseID(id)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE accounts SET password_hash=$2, password_changed_at=now(), failed_logins=0, locked_until=NULL WHERE id=$1`, u, hash)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		_, err = tx.Exec(ctx, `DELETE FROM sessions WHERE account_id=$1`, u)
		return err
	})
}

// UpgradeHash stores a re-hashed password without touching sessions or lockout.
func (s *Store) UpgradeHash(ctx context.Context, id, hash string) error {
	u, err := ParseID(id)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE accounts SET password_hash=$2 WHERE id=$1`, u, hash)
	return err
}

// RecordLoginFailure counts the failure and locks the account with exponential
// backoff once it passes the free attempts. It returns the new lock time (nil if none).
func (s *Store) RecordLoginFailure(ctx context.Context, id string, freeAttempts int, base, max time.Duration) (*time.Time, error) {
	u, err := ParseID(id)
	if err != nil {
		return nil, err
	}
	var failed int
	if err := s.pool.QueryRow(ctx, `UPDATE accounts SET failed_logins=failed_logins+1 WHERE id=$1 RETURNING failed_logins`, u).Scan(&failed); err != nil {
		return nil, err
	}
	if failed < freeAttempts {
		return nil, nil
	}
	d := base << uint(min(failed-freeAttempts, 16))
	if d > max || d <= 0 {
		d = max
	}
	until := s.now().Add(d)
	_, err = s.pool.Exec(ctx, `UPDATE accounts SET locked_until=$2 WHERE id=$1`, u, until)
	return &until, err
}

func (s *Store) RecordLoginSuccess(ctx context.Context, id string) error {
	u, err := ParseID(id)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE accounts SET failed_logins=0, locked_until=NULL, last_login_at=now() WHERE id=$1`, u)
	return err
}

func (s *Store) Memberships(ctx context.Context, accountID string) ([]Membership, error) {
	u, err := ParseID(accountID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT m.panel_id, m.role FROM memberships m JOIN panels p ON p.id=m.panel_id
		WHERE m.account_id=$1 AND p.deleted_at IS NULL ORDER BY p.name`, u)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Membership
	for rows.Next() {
		var pid uuid.UUID
		var m Membership
		if err := rows.Scan(&pid, &m.Role); err != nil {
			return nil, err
		}
		m.PanelID = pid.String()
		out = append(out, m)
	}
	return out, rows.Err()
}

// SetMemberships replaces the account's panel roles atomically.
func (s *Store) SetMemberships(ctx context.Context, accountID string, ms []Membership) error {
	u, err := ParseID(accountID)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM accounts WHERE id=$1)`, u).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		if _, err := tx.Exec(ctx, `DELETE FROM memberships WHERE account_id=$1`, u); err != nil {
			return err
		}
		for _, m := range ms {
			pid, err := ParseID(m.PanelID)
			if err != nil {
				return ErrNotFound
			}
			if _, err := tx.Exec(ctx, `INSERT INTO memberships (account_id, panel_id, role) VALUES ($1,$2,$3)`, u, pid, m.Role); err != nil {
				return err
			}
		}
		return nil
	})
}

type Session struct {
	ID         string
	AccountID  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

func (s *Store) CreateSession(ctx context.Context, accountID string, tokenHash []byte, expires time.Time, ip netip.Addr, userAgent string) (string, error) {
	u, err := ParseID(accountID)
	if err != nil {
		return "", err
	}
	var ipArg any
	if ip.IsValid() {
		ipArg = ip.String()
	}
	if len(userAgent) > 200 {
		userAgent = userAgent[:200]
	}
	var id uuid.UUID
	err = s.pool.QueryRow(ctx, `INSERT INTO sessions (token_hash, account_id, expires_at, ip, user_agent) VALUES ($1,$2,$3,$4::inet,$5) RETURNING id`,
		tokenHash, u, expires, ipArg, userAgent).Scan(&id)
	return id.String(), err
}

// SessionByTokenHash returns the session only while it is unexpired and the
// account is enabled.
func (s *Store) SessionByTokenHash(ctx context.Context, tokenHash []byte) (Session, Account, error) {
	var se Session
	var sid, aid uuid.UUID
	row := s.pool.QueryRow(ctx, `SELECT s.id, s.account_id, s.created_at, s.last_seen_at, s.expires_at, `+prefixed("a", accountCols)+`
		FROM sessions s JOIN accounts a ON a.id=s.account_id
		WHERE s.token_hash=$1 AND s.expires_at > now() AND NOT a.disabled`, tokenHash)
	var a Account
	var accID uuid.UUID
	err := row.Scan(&sid, &aid, &se.CreatedAt, &se.LastSeenAt, &se.ExpiresAt,
		&accID, &a.Username, &a.PasswordHash, &a.IsOwner, &a.Disabled, &a.FailedLogins, &a.LockedUntil, &a.PasswordChangedAt, &a.LastLoginAt, &a.CreatedAt, &a.TOTPEnabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return se, a, ErrNotFound
	}
	se.ID, se.AccountID, a.ID = sid.String(), aid.String(), accID.String()
	return se, a, err
}

func prefixed(alias, cols string) string {
	out := ""
	start := 0
	for i := 0; i <= len(cols); i++ {
		if i == len(cols) || cols[i] == ',' {
			col := cols[start:i]
			for len(col) > 0 && col[0] == ' ' {
				col = col[1:]
			}
			if out != "" {
				out += ", "
			}
			out += alias + "." + col
			start = i + 1
		}
	}
	return out
}

func (s *Store) TouchSession(ctx context.Context, id string) error {
	u, err := ParseID(id)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE sessions SET last_seen_at=now() WHERE id=$1`, u)
	return err
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1`, tokenHash)
	return err
}

func (s *Store) PurgeExpiredSessions(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= now()`)
	return err
}
