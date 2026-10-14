package store_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/secrets"
	"github.com/Taminum/RemnaScope/internal/store"
	"github.com/Taminum/RemnaScope/internal/store/storetest"
	"github.com/Taminum/RemnaScope/migrations"
)

var ctx = context.Background()

func mkPanel(t *testing.T, s *store.Store, name string) store.Panel {
	t.Helper()
	p, err := s.CreatePanel(ctx, store.NewPanelID(), store.PanelInput{Name: name, BaseURL: "https://" + name + ".example.com",
		SyncOptions: store.SyncOptions{Nodes: true, Users: true}, SyncIntervalSeconds: 300, RetentionDays: 30}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMigrateIsIdempotentAndBaselinesM0(t *testing.T) {
	s := storetest.New(t)
	if err := store.Migrate(ctx, s.Pool(), migrations.FS); err != nil {
		t.Fatalf("second run: %v", err)
	}
	var n int
	_ = s.Pool().QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n)
	files, _ := migrations.FS.ReadDir(".")
	want := 0
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".sql") {
			want++
		}
	}
	if n != want || want == 0 {
		t.Fatalf("want %d recorded migrations (one per file), got %d", want, n)
	}
	// Simulate an M0 database: tables exist, bookkeeping table does not.
	if _, err := s.Pool().Exec(ctx, `DROP TABLE schema_migrations`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool().Exec(ctx, `ALTER TABLE panels DROP COLUMN demo`); err != nil { // makes 0002 re-applicable only in part
		t.Fatal(err)
	}
	// Baseline must record 0001 and not re-run it (re-running would fail on existing tables).
	err := store.Migrate(ctx, s.Pool(), migrations.FS)
	if err == nil {
		t.Fatal("0002 should fail on a half-migrated schema, proving 0001 was not re-run before it")
	}
}

func TestScopeIsEnforcedInQueries(t *testing.T) {
	s := storetest.New(t)
	home, work := mkPanel(t, s, "home"), mkPanel(t, s, "work")

	all, _ := s.ListPanels(ctx, store.Scope{All: true})
	if len(all) != 2 {
		t.Fatalf("owner sees both, got %d", len(all))
	}
	only, _ := s.ListPanels(ctx, store.Scope{IDs: []string{work.ID}})
	if len(only) != 1 || only[0].ID != work.ID {
		t.Fatalf("scoped list leaked: %+v", only)
	}
	none, _ := s.ListPanels(ctx, store.Scope{})
	if len(none) != 0 {
		t.Fatal("zero scope must see nothing")
	}
	if _, err := s.GetPanel(ctx, store.Scope{IDs: []string{work.ID}}, home.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("out-of-scope panel must look like it does not exist, got %v", err)
	}
	if _, err := s.GetPanel(ctx, store.Scope{All: true}, "not-a-uuid"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("garbage id: %v", err)
	}
	if _, err := s.ListNodes(ctx, store.Scope{IDs: []string{work.ID}}, home.ID, false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("nodes of another panel: %v", err)
	}
	if _, _, err := s.ListUsers(ctx, store.Scope{IDs: []string{work.ID}}, home.ID, "", 10); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("users of another panel: %v", err)
	}
	if _, err := s.ListSyncRuns(ctx, store.Scope{IDs: []string{work.ID}}, home.ID, 10); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("sync runs of another panel: %v", err)
	}
	if _, err := s.UpdatePanel(ctx, store.Scope{IDs: []string{work.ID}}, home.ID, store.PanelPatch{Name: ptr("hacked")}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update across scope: %v", err)
	}
}

func ptr[T any](v T) *T { return &v }

func TestOverlappingRemoteIDsStayIsolatedPerPanel(t *testing.T) {
	s := storetest.New(t)
	home, work := mkPanel(t, s, "home"), mkPanel(t, s, "work")
	start := time.Now().UTC()

	same := "3f1c0a52-0000-4a00-8000-00000000a001"
	if _, err := s.UpsertNodes(ctx, home.ID, start, []store.NodeRecord{{RemoteUUID: same, Name: "alpha"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertNodes(ctx, work.ID, start, []store.NodeRecord{{RemoteUUID: same, Name: "alpha"}, {RemoteUUID: "x2", Name: "beta"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertUsers(ctx, home.ID, start, []store.UserRecord{{RemoteUUID: "u1", Username: "alice"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertUsers(ctx, work.ID, start, []store.UserRecord{{RemoteUUID: "u1", Username: "alice"}}); err != nil {
		t.Fatal(err)
	}

	hn, _ := s.ListNodes(ctx, store.Scope{All: true}, home.ID, false)
	wn, _ := s.ListNodes(ctx, store.Scope{All: true}, work.ID, false)
	if len(hn) != 1 || len(wn) != 2 || hn[0].ID == wn[0].ID && hn[0].PanelID == wn[0].PanelID {
		t.Fatalf("overlapping node UUIDs merged: %d %d", len(hn), len(wn))
	}
	hu, _, _ := s.ListUsers(ctx, store.Scope{All: true}, home.ID, "", 10)
	wu, _, _ := s.ListUsers(ctx, store.Scope{All: true}, work.ID, "", 10)
	if len(hu) != 1 || len(wu) != 1 || hu[0].ID == wu[0].ID {
		t.Fatal("the same remote user UUID in two panels must be two users")
	}
}

func TestNodeSyncMarksVanishedNodesAndRestoresReturnees(t *testing.T) {
	s := storetest.New(t)
	p := mkPanel(t, s, "home")
	t1 := time.Now().UTC().Add(-time.Hour)
	c, _ := s.UpsertNodes(ctx, p.ID, t1, []store.NodeRecord{{RemoteUUID: "a", Name: "a"}, {RemoteUUID: "b", Name: "b"}})
	if c.Added != 2 {
		t.Fatalf("%+v", c)
	}
	t2 := time.Now().UTC()
	c, _ = s.UpsertNodes(ctx, p.ID, t2, []store.NodeRecord{{RemoteUUID: "a", Name: "a2"}})
	if c.Updated != 1 || c.Removed != 1 || c.Added != 0 {
		t.Fatalf("%+v", c)
	}
	live, _ := s.ListNodes(ctx, store.Scope{All: true}, p.ID, false)
	all, _ := s.ListNodes(ctx, store.Scope{All: true}, p.ID, true)
	if len(live) != 1 || live[0].Name != "a2" || len(all) != 2 {
		t.Fatalf("live=%d all=%d", len(live), len(all))
	}
	t3 := t2.Add(time.Minute)
	c, _ = s.UpsertNodes(ctx, p.ID, t3, []store.NodeRecord{{RemoteUUID: "a", Name: "a2"}, {RemoteUUID: "b", Name: "b"}})
	if c.Removed != 0 {
		t.Fatalf("%+v", c)
	}
	live, _ = s.ListNodes(ctx, store.Scope{All: true}, p.ID, false)
	if len(live) != 2 {
		t.Fatal("a node that came back must be live again")
	}
}

func TestPanelNameUniqueAmongLivePanels(t *testing.T) {
	s := storetest.New(t)
	p := mkPanel(t, s, "home")
	_, err := s.CreatePanel(ctx, store.NewPanelID(), store.PanelInput{Name: "HOME", BaseURL: "https://x.example.com"}, nil)
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("case-insensitive duplicate must conflict, got %v", err)
	}
	if err := s.DeletePanel(ctx, p.ID, "archive"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePanel(ctx, store.NewPanelID(), store.PanelInput{Name: "home", BaseURL: "https://x.example.com"}, nil); err != nil {
		t.Fatalf("an archived panel frees its name: %v", err)
	}
}

func TestDeleteModes(t *testing.T) {
	s := storetest.New(t)
	ring, _ := secrets.NewKeyring(map[int][]byte{1: make([]byte, 32)}, 1)

	build := func(name string) store.Panel {
		id := store.NewPanelID()
		sl, _ := ring.Seal(id, []byte("tok"))
		p, err := s.CreatePanel(ctx, id, store.PanelInput{Name: name, BaseURL: "https://" + name + ".example.com"}, &sl)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = s.UpsertNodes(ctx, p.ID, time.Now().UTC(), []store.NodeRecord{{RemoteUUID: "n", Name: "n"}})
		_ = s.WriteAudit(ctx, store.AuditEntry{PanelID: p.ID, Action: "panel.create", ObjectType: "panel"})
		return p
	}

	purged := build("purged")
	if err := s.DeletePanel(ctx, purged.ID, "purge"); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.Pool().QueryRow(ctx, `SELECT (SELECT count(*) FROM nodes WHERE panel_id=$1)+(SELECT count(*) FROM panel_credentials WHERE panel_id=$1)+(SELECT count(*) FROM panels WHERE id=$1)`, purged.ID).Scan(&n)
	if n != 0 {
		t.Fatalf("purge must remove panel, nodes and credential, %d rows left", n)
	}
	_ = s.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE panel_id=$1`, purged.ID).Scan(&n)
	if n != 1 {
		t.Fatal("audit history must outlive the panel")
	}

	archived := build("archived")
	if err := s.DeletePanel(ctx, archived.ID, "archive"); err != nil {
		t.Fatal(err)
	}
	_ = s.Pool().QueryRow(ctx, `SELECT count(*) FROM panel_credentials WHERE panel_id=$1`, archived.ID).Scan(&n)
	if n != 0 {
		t.Fatal("archive must wipe the credential")
	}
	_ = s.Pool().QueryRow(ctx, `SELECT count(*) FROM nodes WHERE panel_id=$1`, archived.ID).Scan(&n)
	if n != 1 {
		t.Fatal("archive keeps synced data until retention expires")
	}
	if _, err := s.GetPanel(ctx, store.Scope{All: true}, archived.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("archived panel must be invisible: %v", err)
	}
	if err := s.DeletePanel(ctx, archived.ID, "archive"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if err := s.DeletePanel(ctx, build("x").ID, "shred"); err == nil {
		t.Fatal("unknown mode must be refused")
	}
}

func TestCredentialStorageHoldsOnlyCiphertext(t *testing.T) {
	s := storetest.New(t)
	ring, _ := secrets.NewKeyring(map[int][]byte{1: make([]byte, 32)}, 1)
	id := store.NewPanelID()
	sl, _ := ring.Seal(id, []byte("plaintext-token-xyz"))
	if _, err := s.CreatePanel(ctx, id, store.PanelInput{Name: "p", BaseURL: "https://p.example.com"}, &sl); err != nil {
		t.Fatal(err)
	}
	var found bool
	_ = s.Pool().QueryRow(ctx, `SELECT position('plaintext-token-xyz'::bytea in ciphertext) > 0 FROM panel_credentials WHERE panel_id=$1`, id).Scan(&found)
	if found {
		t.Fatal("plaintext found in the credential column")
	}
	got, err := s.Credential(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ring.Open(id, got)
	if err != nil || string(pt) != "plaintext-token-xyz" {
		t.Fatalf("%q %v", pt, err)
	}
	// Rotation compare-and-set.
	two, _ := secrets.NewKeyring(map[int][]byte{1: make([]byte, 32), 2: append(make([]byte, 31), 9)}, 2)
	re, _, _ := two.Reseal(id, got)
	ok, err := s.ReplaceCredentialIf(ctx, id, 1, re)
	if err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if ok, _ := s.ReplaceCredentialIf(ctx, id, 1, re); ok {
		t.Fatal("second swap from v1 must not apply")
	}
}

func TestSessionsAndLockout(t *testing.T) {
	s := storetest.New(t)
	a, err := s.CreateAccount(ctx, "Alice", "hash", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAccount(ctx, "alice", "hash", false); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("usernames are case-insensitive: %v", err)
	}
	got, err := s.AccountByUsername(ctx, "ALICE")
	if err != nil || got.ID != a.ID {
		t.Fatalf("%v", err)
	}

	hash := []byte("0123456789abcdef0123456789abcdef")
	if _, err := s.CreateSession(ctx, a.ID, hash, time.Now().Add(time.Hour), netip.MustParseAddr("203.0.113.5"), "ua"); err != nil {
		t.Fatal(err)
	}
	if _, acc, err := s.SessionByTokenHash(ctx, hash); err != nil || acc.ID != a.ID {
		t.Fatalf("%v", err)
	}
	if err := s.SetAccountDisabled(ctx, a.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SessionByTokenHash(ctx, hash); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("disabling an account must end its sessions")
	}
	_ = s.SetAccountDisabled(ctx, a.ID, false)

	expired := []byte("expired-expired-expired-expired!")
	_, _ = s.CreateSession(ctx, a.ID, expired, time.Now().Add(-time.Minute), netip.Addr{}, "")
	if _, _, err := s.SessionByTokenHash(ctx, expired); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("expired session must not authenticate")
	}

	var until *time.Time
	for i := 0; i < 7; i++ {
		until, _ = s.RecordLoginFailure(ctx, a.ID, 5, time.Second, time.Minute)
	}
	if until == nil || !until.After(time.Now()) {
		t.Fatalf("lockout expected after repeated failures, got %v", until)
	}
	_ = s.RecordLoginSuccess(ctx, a.ID)
	got, _ = s.AccountByID(ctx, a.ID)
	if got.FailedLogins != 0 || got.LockedUntil != nil {
		t.Fatalf("success must clear lockout: %+v", got)
	}

	_, _ = s.CreateSession(ctx, a.ID, hash, time.Now().Add(time.Hour), netip.Addr{}, "")
	if err := s.SetPassword(ctx, a.ID, "newhash"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SessionByTokenHash(ctx, hash); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a password change must sign the account out everywhere")
	}
}

func TestMembershipsAreReplacedAtomically(t *testing.T) {
	s := storetest.New(t)
	a, _ := s.CreateAccount(ctx, "bob", "h", false)
	p1, p2 := mkPanel(t, s, "one"), mkPanel(t, s, "two")
	if err := s.SetMemberships(ctx, a.ID, []store.Membership{{PanelID: p1.ID, Role: "viewer"}, {PanelID: p2.ID, Role: "admin"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMemberships(ctx, a.ID, []store.Membership{{PanelID: p1.ID, Role: "boss"}}); err == nil {
		t.Fatal("unknown role must be rejected by the database")
	}
	ms, _ := s.Memberships(ctx, a.ID)
	if len(ms) != 2 {
		t.Fatalf("failed replace must roll back, got %+v", ms)
	}
	if err := s.SetMemberships(ctx, a.ID, []store.Membership{{PanelID: p2.ID, Role: "operator"}}); err != nil {
		t.Fatal(err)
	}
	ms, _ = s.Memberships(ctx, a.ID)
	if len(ms) != 1 || ms[0].PanelID != p2.ID || ms[0].Role != "operator" {
		t.Fatalf("%+v", ms)
	}
	if err := s.SetMemberships(ctx, "00000000-0000-4000-8000-000000000000", nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown account: %v", err)
	}
}

func TestSyncBackoffAndCircuitBreaker(t *testing.T) {
	s := storetest.New(t)
	p := mkPanel(t, s, "flaky")
	now := time.Now().UTC()
	_ = s.RecordSyncOutcome(ctx, p.ID, true, "ok", 5*time.Minute, now, 0, 3, 15*time.Minute)

	for i := 1; i <= 3; i++ {
		_ = s.RecordSyncOutcome(ctx, p.ID, false, "failed", time.Minute, now, 0, 3, 15*time.Minute)
	}
	got, _ := s.GetPanel(ctx, store.Scope{All: true}, p.ID)
	if got.Status != "error" || got.ConsecutiveFailures != 3 || got.CircuitOpenUntil == nil || !got.CircuitOpenUntil.After(now.Add(14*time.Minute)) {
		t.Fatalf("breaker should be open: %+v", got)
	}
	if got.NextSyncAt == nil || !got.NextSyncAt.After(now.Add(5*time.Minute)) {
		t.Fatalf("backoff should grow with failures: %v", got.NextSyncAt)
	}
	due, _ := s.DuePanels(ctx, now.Add(2*time.Minute), 10)
	for _, d := range due {
		if d.ID == p.ID {
			t.Fatal("an open circuit must keep the panel out of the due list")
		}
	}
	_ = s.RecordSyncOutcome(ctx, p.ID, true, "ok", 5*time.Minute, now, 0, 3, 15*time.Minute)
	got, _ = s.GetPanel(ctx, store.Scope{All: true}, p.ID)
	if got.Status != "active" || got.ConsecutiveFailures != 0 || got.CircuitOpenUntil != nil {
		t.Fatalf("success must close the circuit: %+v", got)
	}
}

func TestRetryAfterWinsOverShorterBackoff(t *testing.T) {
	s := storetest.New(t)
	p := mkPanel(t, s, "limited")
	now := time.Now().UTC()
	_ = s.RecordSyncOutcome(ctx, p.ID, false, "rate_limited", time.Minute, now, 20*time.Minute, 10, time.Hour)
	got, _ := s.GetPanel(ctx, store.Scope{All: true}, p.ID)
	if got.NextSyncAt == nil || got.NextSyncAt.Before(now.Add(19*time.Minute)) {
		t.Fatalf("a 429 retry hint must be honoured: %v", got.NextSyncAt)
	}
}

func TestAuditScope(t *testing.T) {
	s := storetest.New(t)
	home, work := mkPanel(t, s, "home"), mkPanel(t, s, "work")
	_ = s.WriteAudit(ctx, store.AuditEntry{PanelID: home.ID, Action: "panel.test", ObjectType: "panel", ActorName: "owner", IP: "198.51.100.7"})
	_ = s.WriteAudit(ctx, store.AuditEntry{PanelID: work.ID, Action: "panel.test", ObjectType: "panel"})
	_ = s.WriteAudit(ctx, store.AuditEntry{Action: "auth.login", ObjectType: "account"}) // no panel

	all, _ := s.ListAudit(ctx, store.Scope{All: true}, "", time.Time{}, 50)
	if len(all) != 3 {
		t.Fatalf("owner sees all, got %d", len(all))
	}
	scoped, _ := s.ListAudit(ctx, store.Scope{IDs: []string{work.ID}}, "", time.Time{}, 50)
	if len(scoped) != 1 || *scoped[0].PanelID != work.ID {
		t.Fatalf("scoped audit leaked: %+v", scoped)
	}
	if _, err := s.ListAudit(ctx, store.Scope{IDs: []string{work.ID}}, home.ID, time.Time{}, 50); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestDatabaseRefusesCrossPanelLinks(t *testing.T) {
	s := storetest.New(t)
	home, work := mkPanel(t, s, "home"), mkPanel(t, s, "work")
	_, _ = s.UpsertNodes(ctx, work.ID, time.Now().UTC(), []store.NodeRecord{{RemoteUUID: "w", Name: "w"}})
	nodes, _ := s.ListNodes(ctx, store.Scope{All: true}, work.ID, false)
	_, err := s.Pool().Exec(ctx, `INSERT INTO agents (panel_id, node_id, token_hash) VALUES ($1,$2,'\x00')`, home.ID, nodes[0].ID)
	if err == nil {
		t.Fatal("an agent of one panel must not bind to a node of another")
	}
}
