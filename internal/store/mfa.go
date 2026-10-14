package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Taminum/RemnaScope/internal/secrets"
)

// TOTP is an account's stored second factor. The secret is sealed; Enabled is false while it is
// only pending confirmation.
type TOTP struct {
	Sealed   secrets.Sealed
	Enabled  bool
	LastStep int64
}

// TOTPAAD is what binds a sealed secret to its account.
func TOTPAAD(accountID string) string { return "totp:" + accountID }

func (s *Store) AccountTOTP(ctx context.Context, accountID string) (TOTP, bool, error) {
	id, err := ParseID(accountID)
	if err != nil {
		return TOTP{}, false, ErrNotFound
	}
	var t TOTP
	var ver *int
	var enabled *time.Time
	err = s.pool.QueryRow(ctx, `SELECT totp_ciphertext, totp_nonce, totp_key_version, totp_enabled_at, totp_last_step FROM accounts WHERE id=$1`, id).
		Scan(&t.Sealed.Ciphertext, &t.Sealed.Nonce, &ver, &enabled, &t.LastStep)
	if errors.Is(err, pgx.ErrNoRows) {
		return TOTP{}, false, ErrNotFound
	}
	if err != nil || ver == nil || len(t.Sealed.Ciphertext) == 0 {
		return TOTP{}, false, err
	}
	t.Sealed.KeyVersion, t.Enabled = *ver, enabled != nil
	return t, true, nil
}

// SetPendingTOTP stores a new, unconfirmed secret. It refuses when TOTP is already enabled:
// the factor has to be switched off (with the password and a code) before it can be replaced.
func (s *Store) SetPendingTOTP(ctx context.Context, accountID string, sl secrets.Sealed) error {
	id, err := ParseID(accountID)
	if err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE accounts SET totp_ciphertext=$2, totp_nonce=$3, totp_key_version=$4, totp_last_step=0
		WHERE id=$1 AND totp_enabled_at IS NULL`, id, sl.Ciphertext, sl.Nonce, sl.KeyVersion)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

func hashRecovery(code string) []byte {
	h := sha256.Sum256([]byte(code))
	return h[:]
}

// EnableTOTP confirms the pending secret and stores the recovery codes (already normalised), in
// one step. step is the code step that confirmed it, so that code cannot be used to sign in.
func (s *Store) EnableTOTP(ctx context.Context, accountID string, step int64, recovery []string) error {
	id, err := ParseID(accountID)
	if err != nil {
		return ErrNotFound
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE accounts SET totp_enabled_at=now(), totp_last_step=$2
			WHERE id=$1 AND totp_enabled_at IS NULL AND totp_ciphertext IS NOT NULL`, id, step)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrConflict
		}
		if _, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE account_id=$1`, id); err != nil {
			return err
		}
		for _, c := range recovery {
			if _, err := tx.Exec(ctx, `INSERT INTO recovery_codes (account_id, code_hash) VALUES ($1,$2)`, id, hashRecovery(c)); err != nil {
				return err
			}
		}
		return nil
	})
}

// DisableTOTP removes the factor, its recovery codes and any sign-in waiting for a code.
func (s *Store) DisableTOTP(ctx context.Context, accountID string) error {
	id, err := ParseID(accountID)
	if err != nil {
		return ErrNotFound
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE accounts SET totp_ciphertext=NULL, totp_nonce=NULL, totp_key_version=NULL, totp_enabled_at=NULL, totp_last_step=0 WHERE id=$1`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM recovery_codes WHERE account_id=$1`, id); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM mfa_challenges WHERE account_id=$1`, id)
		return err
	})
}

// AdvanceTOTPStep records the step of a code that was just accepted. It returns false if another
// request got there first (or the step is not newer), so one code can never sign in twice.
func (s *Store) AdvanceTOTPStep(ctx context.Context, accountID string, step int64) (bool, error) {
	id, err := ParseID(accountID)
	if err != nil {
		return false, ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE accounts SET totp_last_step=$2 WHERE id=$1 AND totp_last_step < $2 AND totp_enabled_at IS NOT NULL`, id, step)
	return tag.RowsAffected() == 1, err
}

// UseRecoveryCode spends a recovery code (normalised); it works once.
func (s *Store) UseRecoveryCode(ctx context.Context, accountID, code string) (bool, error) {
	id, err := ParseID(accountID)
	if err != nil {
		return false, ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE recovery_codes SET used_at=now() WHERE account_id=$1 AND code_hash=$2 AND used_at IS NULL`, id, hashRecovery(code))
	return tag.RowsAffected() == 1, err
}

func (s *Store) RecoveryCodesLeft(ctx context.Context, accountID string) (int, error) {
	id, err := ParseID(accountID)
	if err != nil {
		return 0, ErrNotFound
	}
	var n int
	return n, s.pool.QueryRow(ctx, `SELECT count(*) FROM recovery_codes WHERE account_id=$1 AND used_at IS NULL`, id).Scan(&n)
}

// CreateMFAChallenge opens the window between a correct password and a correct code.
func (s *Store) CreateMFAChallenge(ctx context.Context, accountID string, tokenHash []byte, expires time.Time) error {
	id, err := ParseID(accountID)
	if err != nil {
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO mfa_challenges (token_hash, account_id, expires_at) VALUES ($1,$2,$3)`, tokenHash, id, expires)
	return err
}

// MFAAttempt finds a live challenge and counts this attempt against it in one statement. ok is
// false for an unknown, expired or used-up challenge: after maxAttempts tries it is dead.
func (s *Store) MFAAttempt(ctx context.Context, tokenHash []byte, now time.Time, maxAttempts int) (accountID string, ok bool, err error) {
	var id uuid.UUID
	err = s.pool.QueryRow(ctx, `UPDATE mfa_challenges SET attempts = attempts + 1 WHERE token_hash=$1 AND expires_at > $2 AND attempts < $3
		RETURNING account_id`, tokenHash, now, maxAttempts).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return id.String(), true, nil
}

func (s *Store) DeleteMFAChallenge(ctx context.Context, tokenHash []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM mfa_challenges WHERE token_hash=$1`, tokenHash)
	return err
}

func (s *Store) PurgeExpiredMFAChallenges(ctx context.Context, now time.Time) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM mfa_challenges WHERE expires_at <= $1`, now)
	return err
}

// TOTPRef is one stored second-factor secret, for key rotation.
type TOTPRef struct {
	AccountID string
	Sealed    secrets.Sealed
}

func (s *Store) AllTOTP(ctx context.Context) ([]TOTPRef, error) {
	rs, err := s.pool.Query(ctx, `SELECT id, totp_ciphertext, totp_nonce, totp_key_version FROM accounts WHERE totp_ciphertext IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []TOTPRef
	for rs.Next() {
		var r TOTPRef
		var id uuid.UUID
		if err := rs.Scan(&id, &r.Sealed.Ciphertext, &r.Sealed.Nonce, &r.Sealed.KeyVersion); err != nil {
			return nil, err
		}
		r.AccountID = id.String()
		out = append(out, r)
	}
	return out, rs.Err()
}

// ReplaceTOTPIf swaps a secret for its re-encrypted copy only if it still has the old key version.
func (s *Store) ReplaceTOTPIf(ctx context.Context, accountID string, oldVersion int, sl secrets.Sealed) (bool, error) {
	id, err := ParseID(accountID)
	if err != nil {
		return false, ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE accounts SET totp_ciphertext=$2, totp_nonce=$3, totp_key_version=$4 WHERE id=$1 AND totp_key_version=$5`,
		id, sl.Ciphertext, sl.Nonce, sl.KeyVersion, oldVersion)
	return tag.RowsAffected() == 1, err
}
