// Package storetest gives each test its own freshly migrated Postgres database.
// Set TEST_DATABASE_URL to an admin connection (e.g. postgres://postgres:pw@127.0.0.1:55432/postgres);
// without it, tests that need a database are skipped.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Taminum/Owlery/internal/store"
	"github.com/Taminum/Owlery/migrations"
)

func New(t *testing.T) *store.Store {
	t.Helper()
	admin := os.Getenv("TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping database test")
	}
	ctx := context.Background()
	ap, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "rs_test_" + hex.EncodeToString(b)
	if _, err := ap.Exec(ctx, `CREATE DATABASE `+name); err != nil {
		ap.Close()
		t.Fatal(err)
	}

	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = ap.Exec(c, `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`)
		ap.Close()
	})
	if err := store.Migrate(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	return store.New(pool)
}
