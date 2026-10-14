// Package store is the only code that talks SQL. Every read that returns panel data
// takes a Scope, so "which panels may this caller see" is enforced in the query itself.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: conflict")
)

type Store struct {
	pool *pgxpool.Pool
	Now  func() time.Time
}

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool, Now: time.Now} }

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

func (s *Store) now() time.Time { return s.Now().UTC() }

// Scope is the set of panels a caller may see. Owners get All; everyone else an
// explicit ID list. The zero value sees nothing.
type Scope struct {
	All bool
	IDs []string
}

func (sc Scope) Allows(id string) bool {
	if sc.All {
		return true
	}
	for _, v := range sc.IDs {
		if v == id {
			return true
		}
	}
	return false
}

// sql returns a predicate over the given column plus its args, appended after n existing args.
func (sc Scope) predicate(col string, n int) (string, []any) {
	if sc.All {
		return "TRUE", nil
	}
	ids := make([]uuid.UUID, 0, len(sc.IDs))
	for _, s := range sc.IDs {
		if u, err := uuid.Parse(s); err == nil {
			ids = append(ids, u)
		}
	}
	return col + " = ANY($" + itoa(n+1) + "::uuid[])", []any{ids}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// ParseID rejects anything that is not a UUID before it reaches SQL.
func ParseID(s string) (uuid.UUID, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, ErrNotFound
	}
	return u, nil
}

func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
