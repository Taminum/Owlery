package store

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// advisory lock key: "RMNA" - keeps concurrent API replicas from migrating at once.
const migrateLockKey int64 = 0x524d4e41

// Migrate applies every embedded *.sql file once, in filename order.
// A database created by M0 (0001 applied through docker-entrypoint-initdb.d,
// no bookkeeping table) is baselined instead of re-run.
func Migrate(ctx context.Context, pool *pgxpool.Pool, files fs.FS) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrateLockKey); err != nil {
		return err
	}
	defer func() { _, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrateLockKey) }()

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}

	var applied int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&applied); err != nil {
		return err
	}
	if applied == 0 {
		var legacy bool
		if err := conn.QueryRow(ctx, `SELECT to_regclass('public.panels') IS NOT NULL`).Scan(&legacy); err != nil {
			return err
		}
		if legacy {
			if _, err := conn.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ('0001_init.sql')`); err != nil {
				return err
			}
		}
	}

	entries, err := fs.Glob(files, "*.sql")
	if err != nil {
		return err
	}
	sort.Strings(entries)
	for _, name := range entries {
		var done bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version=$1)`, name).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		sqlText, err := fs.ReadFile(files, name)
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sqlText)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// IsUniqueViolation reports a Postgres 23505 error without importing pgconn everywhere.
func IsUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "SQLSTATE 23505")
}
