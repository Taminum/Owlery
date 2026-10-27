package syncer

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/remnawave"
	"github.com/Taminum/Owlery/internal/safehttp"
	"github.com/Taminum/Owlery/internal/secrets"
	"github.com/Taminum/Owlery/internal/store"
	"github.com/Taminum/Owlery/internal/store/storetest"
)

var ctx = context.Background()

// fakePanel scripts what one panel answers. Panels never share a fake.
type fakePanel struct {
	mu         sync.Mutex
	nodes      []remnawave.Node
	nodesErr   error
	pages      []remnawave.UsersPage // by call index
	userErr    map[int]error         // by offset
	userCalls  []int
	gotToken   string
	block      chan struct{}
	entered    chan struct{}
	enterOnce  sync.Once
	alwaysNext bool
}

func (f *fakePanel) Probe(context.Context) remnawave.ProbeResult { return remnawave.ProbeResult{} }
func (f *fakePanel) GetCapabilities(context.Context) (remnawave.Capabilities, error) {
	return remnawave.Capabilities{}, nil
}
func (f *fakePanel) GetTrafficCounters(context.Context, time.Time, time.Time) ([]remnawave.TrafficCounter, error) {
	return nil, remnawave.ErrNotImplemented
}
func (f *fakePanel) ListNodes(context.Context) ([]remnawave.Node, error) {
	if f.entered != nil {
		f.enterOnce.Do(func() { close(f.entered) })
	}
	if f.block != nil {
		<-f.block
	}
	return f.nodes, f.nodesErr
}
func (f *fakePanel) ListUsers(_ context.Context, offset, _ int) (remnawave.UsersPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.userCalls = append(f.userCalls, offset)
	if err := f.userErr[offset]; err != nil {
		return remnawave.UsersPage{}, err
	}
	if f.alwaysNext {
		return remnawave.UsersPage{Users: []remnawave.User{{RemoteUUID: "u", Username: "u"}}, Total: 99, Next: offset + 1}, nil
	}
	i := len(f.userCalls) - 1
	if i >= len(f.pages) {
		return remnawave.UsersPage{Next: -1}, nil
	}
	return f.pages[i], nil
}

type env struct {
	st   *store.Store
	ring *secrets.Keyring
	sy   *Syncer
	fake map[string]*fakePanel
	now  time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := storetest.New(t)
	ring, _ := secrets.NewKeyring(map[int][]byte{1: make([]byte, 32)}, 1)
	e := &env{st: st, ring: ring, fake: map[string]*fakePanel{}, now: time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)}
	cfg := DefaultConfig()
	cfg.RPS, cfg.PageSize, cfg.MaxPages, cfg.BreakerAfter = 1000, 2, 5, 3
	e.sy = New(st, ring,
		func(p store.Panel, token string, g remnawave.Getter) (remnawave.PanelAdapter, error) {
			f := e.fake[p.ID]
			f.mu.Lock()
			f.gotToken = token
			f.mu.Unlock()
			return f, nil
		},
		func(store.Panel) remnawave.Getter { return nopGetter{} }, cfg, nil)
	e.sy.Now = func() time.Time { return e.now }
	st.Now = func() time.Time { return e.now }
	return e
}

type nopGetter struct{}

func (nopGetter) Get(context.Context, string, http.Header) (*safehttp.Response, error) {
	return nil, errors.New("not used")
}

func (e *env) panel(t *testing.T, name string, f *fakePanel, opts store.SyncOptions) store.Panel {
	t.Helper()
	id := store.NewPanelID()
	sl, _ := e.ring.Seal(id, []byte("token-for-"+name))
	p, err := e.st.CreatePanel(ctx, id, store.PanelInput{Name: name, BaseURL: "https://" + name + ".example.com", SyncOptions: opts, SyncIntervalSeconds: 300}, &sl)
	if err != nil {
		t.Fatal(err)
	}
	e.fake[p.ID] = f
	return p
}

var both = store.SyncOptions{Nodes: true, Users: true}

func uuidN(n string) string { return "00000000-0000-4000-8000-0000000000" + n }

func TestTwoPanelsSyncIndependently(t *testing.T) {
	e := newEnv(t)
	home := e.panel(t, "home", &fakePanel{
		nodes: []remnawave.Node{{RemoteUUID: uuidN("01"), Name: "h-a"}, {RemoteUUID: uuidN("02"), Name: "h-b"}},
		pages: []remnawave.UsersPage{{Users: []remnawave.User{{RemoteUUID: uuidN("11"), Username: "alice"}}, Total: 1, Next: -1}},
	}, both)
	work := e.panel(t, "work", &fakePanel{
		nodes: []remnawave.Node{{RemoteUUID: uuidN("01"), Name: "w-1"}}, // same remote UUID as a home node
		pages: []remnawave.UsersPage{{Users: []remnawave.User{{RemoteUUID: uuidN("11"), Username: "alice"}, {RemoteUUID: uuidN("12"), Username: "bob"}}, Total: 2, Next: -1}},
	}, both)

	for _, p := range []store.Panel{home, work} {
		r, err := e.sy.SyncPanel(ctx, p.ID, "manual")
		if err != nil || r.Status != "ok" {
			t.Fatalf("%s: %+v %v", p.Name, r, err)
		}
	}
	h, _ := e.st.GetPanel(ctx, store.Scope{All: true}, home.ID)
	w, _ := e.st.GetPanel(ctx, store.Scope{All: true}, work.ID)
	if h.NodeCount != 2 || h.UserCount != 1 || w.NodeCount != 1 || w.UserCount != 2 {
		t.Fatalf("counts leaked between panels: home=%d/%d work=%d/%d", h.NodeCount, h.UserCount, w.NodeCount, w.UserCount)
	}
	if h.Status != "active" || h.LastSyncStatus == nil || *h.LastSyncStatus != "ok" || h.NextSyncAt == nil || !h.NextSyncAt.Equal(e.now.Add(5*time.Minute)) {
		t.Fatalf("scheduling state: %+v", h)
	}
	if e.fake[home.ID].gotToken != "token-for-home" || e.fake[work.ID].gotToken != "token-for-work" {
		t.Fatal("each panel must be synced with its own decrypted token")
	}
	runs, _ := e.st.ListSyncRuns(ctx, store.Scope{All: true}, home.ID, 10)
	if len(runs) != 2 || runs[0].Status != "ok" || runs[0].Trigger != "manual" {
		t.Fatalf("sync runs: %+v", runs)
	}
}

func TestOnePanelFailingDoesNotAffectTheOther(t *testing.T) {
	e := newEnv(t)
	good := e.panel(t, "good", &fakePanel{nodes: []remnawave.Node{{RemoteUUID: uuidN("01"), Name: "g"}}}, store.SyncOptions{Nodes: true})
	bad := e.panel(t, "bad", &fakePanel{nodesErr: &remnawave.APIError{Code: remnawave.CodeUpstream, Status: 502}}, store.SyncOptions{Nodes: true})

	rb, _ := e.sy.SyncPanel(ctx, bad.ID, "schedule")
	rg, _ := e.sy.SyncPanel(ctx, good.ID, "schedule")
	if rb.Status != "failed" || rg.Status != "ok" {
		t.Fatalf("bad=%s good=%s", rb.Status, rg.Status)
	}
	b, _ := e.st.GetPanel(ctx, store.Scope{All: true}, bad.ID)
	g, _ := e.st.GetPanel(ctx, store.Scope{All: true}, good.ID)
	if b.Status != "error" || b.ConsecutiveFailures != 1 || g.Status != "active" || g.ConsecutiveFailures != 0 || g.NodeCount != 1 {
		t.Fatalf("bad=%+v good=%+v", b, g)
	}
	runs, _ := e.st.ListSyncRuns(ctx, store.Scope{All: true}, bad.ID, 5)
	if runs[0].Status != "failed" || runs[0].ErrorCode == nil || *runs[0].ErrorCode != remnawave.CodeUpstream {
		t.Fatalf("failure must be recorded with its code: %+v", runs[0])
	}
}

func TestBreakerOpensAfterRepeatedFailuresAndSkipsThePanel(t *testing.T) {
	e := newEnv(t)
	bad := e.panel(t, "dead", &fakePanel{nodesErr: &remnawave.APIError{Code: remnawave.CodeUpstream}}, store.SyncOptions{Nodes: true})
	for i := 0; i < 3; i++ {
		_, _ = e.sy.SyncPanel(ctx, bad.ID, "schedule")
	}
	p, _ := e.st.GetPanel(ctx, store.Scope{All: true}, bad.ID)
	if p.CircuitOpenUntil == nil || !p.CircuitOpenUntil.After(e.now) {
		t.Fatalf("breaker should be open: %+v", p)
	}
	due, _ := e.st.DuePanels(ctx, e.now.Add(10*time.Minute), 10) // inside the 15-minute cool-down
	for _, d := range due {
		if d.ID == bad.ID {
			t.Fatal("a panel behind an open breaker must not be scheduled")
		}
	}
	// Cool-down passes and the panel recovers.
	e.fake[bad.ID].nodesErr = nil
	e.fake[bad.ID].nodes = []remnawave.Node{{RemoteUUID: uuidN("01"), Name: "back"}}
	e.now = e.now.Add(20 * time.Minute)
	if r, _ := e.sy.SyncPanel(ctx, bad.ID, "schedule"); r.Status != "ok" {
		t.Fatalf("%+v", r)
	}
	p, _ = e.st.GetPanel(ctx, store.Scope{All: true}, bad.ID)
	if p.CircuitOpenUntil != nil || p.Status != "active" || p.ConsecutiveFailures != 0 {
		t.Fatalf("recovery: %+v", p)
	}
}

func TestRateLimitedPanelIsRetriedNoSoonerThanItAsked(t *testing.T) {
	e := newEnv(t)
	p := e.panel(t, "limited", &fakePanel{nodesErr: &remnawave.APIError{Code: remnawave.CodeRateLimited, Status: 429, RetryAfter: 45 * time.Minute}}, store.SyncOptions{Nodes: true})
	_, _ = e.sy.SyncPanel(ctx, p.ID, "schedule")
	got, _ := e.st.GetPanel(ctx, store.Scope{All: true}, p.ID)
	if got.NextSyncAt == nil || got.NextSyncAt.Before(e.now.Add(44*time.Minute)) {
		t.Fatalf("429 hint ignored: %v", got.NextSyncAt)
	}
}

func TestUserPaginationAcrossPagesAndRemovals(t *testing.T) {
	e := newEnv(t)
	f := &fakePanel{
		nodes: []remnawave.Node{{RemoteUUID: uuidN("01"), Name: "n"}},
		pages: []remnawave.UsersPage{
			{Users: []remnawave.User{{RemoteUUID: uuidN("11"), Username: "a"}, {RemoteUUID: uuidN("12"), Username: "b"}}, Total: 5, Next: 2},
			{Users: []remnawave.User{{RemoteUUID: uuidN("13"), Username: "c"}, {RemoteUUID: uuidN("14"), Username: "d"}}, Total: 5, Next: 4},
			{Users: []remnawave.User{{RemoteUUID: uuidN("15"), Username: "e"}}, Total: 5, Next: -1, Skipped: 1},
		},
	}
	p := e.panel(t, "paged", f, both)
	if r, _ := e.sy.SyncPanel(ctx, p.ID, "schedule"); r.Status != "ok" {
		t.Fatalf("%+v", r)
	}
	if got := f.userCalls; len(got) != 3 || got[0] != 0 || got[1] != 2 || got[2] != 4 {
		t.Fatalf("offsets %v", got)
	}
	got, _ := e.st.GetPanel(ctx, store.Scope{All: true}, p.ID)
	if got.UserCount != 5 {
		t.Fatalf("users %d", got.UserCount)
	}
	runs, _ := e.st.ListSyncRuns(ctx, store.Scope{All: true}, p.ID, 5)
	var users store.SyncRun
	for _, r := range runs {
		if r.Operation == "users" {
			users = r
		}
	}
	if string(users.Stats) == "" || users.Status != "ok" {
		t.Fatalf("%+v", users)
	}

	// Next sync: two users vanished from the panel and the listing completes.
	e.now = e.now.Add(10 * time.Minute)
	f.userCalls = nil
	f.pages = []remnawave.UsersPage{{Users: []remnawave.User{{RemoteUUID: uuidN("11"), Username: "a"}}, Total: 1, Next: -1}}
	_, _ = e.sy.SyncPanel(ctx, p.ID, "schedule")
	got, _ = e.st.GetPanel(ctx, store.Scope{All: true}, p.ID)
	if got.UserCount != 1 {
		t.Fatalf("vanished users should be marked removed, %d live", got.UserCount)
	}
}

func TestFailureMidListingKeepsWhatLandedAndRemovesNothing(t *testing.T) {
	e := newEnv(t)
	f := &fakePanel{
		nodes: []remnawave.Node{{RemoteUUID: uuidN("01"), Name: "n"}},
		pages: []remnawave.UsersPage{
			{Users: []remnawave.User{{RemoteUUID: uuidN("11"), Username: "a"}, {RemoteUUID: uuidN("12"), Username: "b"}}, Total: 4, Next: 2},
		},
		userErr: map[int]error{2: &remnawave.APIError{Code: remnawave.CodeUpstream}},
	}
	p := e.panel(t, "midway", f, both)
	// Pre-existing user that the incomplete listing must not delete.
	_, _ = e.st.UpsertUsers(ctx, p.ID, e.now.Add(-time.Hour), []store.UserRecord{{RemoteUUID: uuidN("99"), Username: "old"}})

	r, _ := e.sy.SyncPanel(ctx, p.ID, "schedule")
	if r.Status != "partial" {
		t.Fatalf("%+v", r)
	}
	got, _ := e.st.GetPanel(ctx, store.Scope{All: true}, p.ID)
	if got.UserCount != 3 {
		t.Fatalf("an interrupted listing must not remove users: %d live", got.UserCount)
	}
	if got.ConsecutiveFailures != 1 {
		t.Fatal("a transient mid-listing failure counts toward backoff")
	}
}

func TestMissingUsersPermissionIsAConfigurationStateNotAnOutage(t *testing.T) {
	e := newEnv(t)
	f := &fakePanel{
		nodes:   []remnawave.Node{{RemoteUUID: uuidN("01"), Name: "n"}},
		userErr: map[int]error{0: &remnawave.APIError{Code: remnawave.CodeForbidden, Status: 403}},
	}
	p := e.panel(t, "noperm", f, both)
	for i := 0; i < 5; i++ {
		r, _ := e.sy.SyncPanel(ctx, p.ID, "schedule")
		if r.Status != "partial" {
			t.Fatalf("run %d: %+v", i, r)
		}
	}
	got, _ := e.st.GetPanel(ctx, store.Scope{All: true}, p.ID)
	if got.ConsecutiveFailures != 0 || got.CircuitOpenUntil != nil || got.Status != "active" || got.NodeCount != 1 {
		t.Fatalf("nodes must keep syncing and the breaker stay closed: %+v", got)
	}
}

func TestListingThatNeverEndsIsStopped(t *testing.T) {
	e := newEnv(t)
	f := &fakePanel{nodes: []remnawave.Node{{RemoteUUID: uuidN("01"), Name: "n"}}, alwaysNext: true}
	p := e.panel(t, "endless", f, both)
	r, _ := e.sy.SyncPanel(ctx, p.ID, "schedule")
	if r.Status != "partial" || len(f.userCalls) != 5 {
		t.Fatalf("status %s after %d pages (max 5)", r.Status, len(f.userCalls))
	}
}

func TestSyncOptionsAndCapabilitiesAreRespected(t *testing.T) {
	e := newEnv(t)
	f := &fakePanel{nodes: []remnawave.Node{{RemoteUUID: uuidN("01"), Name: "n"}}, pages: []remnawave.UsersPage{{Total: 0, Next: -1}}}
	p := e.panel(t, "nodes-only", f, store.SyncOptions{Nodes: true})
	_, _ = e.sy.SyncPanel(ctx, p.ID, "schedule")
	if len(f.userCalls) != 0 {
		t.Fatal("users sync is off, the panel must not be asked for users")
	}

	f2 := &fakePanel{nodes: []remnawave.Node{{RemoteUUID: uuidN("01"), Name: "n"}}}
	p2 := e.panel(t, "no-users-cap", f2, both)
	if err := e.st.SavePanelProbe(ctx, p2.ID, nil, []byte(`{"nodes":true,"users":false}`), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	_, _ = e.sy.SyncPanel(ctx, p2.ID, "schedule")
	if len(f2.userCalls) != 0 {
		t.Fatal("a panel known not to support users must not be asked for them")
	}
}

func TestOverlappingSyncOfTheSamePanelIsRefused(t *testing.T) {
	e := newEnv(t)
	block := make(chan struct{})
	f := &fakePanel{nodes: []remnawave.Node{{RemoteUUID: uuidN("01"), Name: "n"}}, block: block, entered: make(chan struct{})}
	p := e.panel(t, "slow", f, store.SyncOptions{Nodes: true})

	done := make(chan struct{})
	go func() {
		_, _ = e.sy.SyncPanel(ctx, p.ID, "schedule")
		close(done)
	}()
	select {
	case <-f.entered: // the first sync now holds the panel
	case <-time.After(5 * time.Second):
		t.Fatal("first sync never started")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := e.sy.SyncPanel(ctx, p.ID, "manual"); errors.Is(err, ErrBusy) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("second sync was never refused")
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(block)
	<-done
}

func TestDemoAndDisabledPanelsAreNotSynced(t *testing.T) {
	e := newEnv(t)
	id := store.NewPanelID()
	demo, _ := e.st.CreatePanel(ctx, id, store.PanelInput{Name: "demo", BaseURL: "https://demo.invalid", Demo: true}, nil)
	if _, err := e.sy.SyncPanel(ctx, demo.ID, "manual"); !errors.Is(err, ErrNotSyncable) {
		t.Fatalf("demo: %v", err)
	}
	p := e.panel(t, "off", &fakePanel{}, both)
	_ = e.st.SetPanelStatus(ctx, p.ID, "disabled")
	if _, err := e.sy.SyncPanel(ctx, p.ID, "manual"); !errors.Is(err, ErrNotSyncable) {
		t.Fatalf("disabled: %v", err)
	}
	due, _ := e.st.DuePanels(ctx, e.now.Add(time.Hour), 10)
	for _, d := range due {
		if d.ID == demo.ID || d.ID == p.ID {
			t.Fatal("demo and disabled panels must never be due")
		}
	}
}

func TestUnreadableCredentialFailsClosed(t *testing.T) {
	e := newEnv(t)
	p := e.panel(t, "badkey", &fakePanel{nodes: []remnawave.Node{{RemoteUUID: uuidN("01"), Name: "n"}}}, store.SyncOptions{Nodes: true})
	other, _ := secrets.NewKeyring(map[int][]byte{1: append(make([]byte, 31), 7)}, 1) // wrong master key
	e.sy.Ring = other
	r, _ := e.sy.SyncPanel(ctx, p.ID, "schedule")
	got, _ := e.st.GetPanel(ctx, store.Scope{All: true}, p.ID)
	if r.Status != "failed" || got.Status != "error" || got.NodeCount != 0 {
		t.Fatalf("%+v %+v", r, got)
	}
	if got.LastSyncStatus == nil || *got.LastSyncStatus != "credential_unreadable" {
		t.Fatalf("%v", got.LastSyncStatus)
	}
}

func TestRunLoopPicksUpDuePanels(t *testing.T) {
	e := newEnv(t)
	f := &fakePanel{nodes: []remnawave.Node{{RemoteUUID: uuidN("01"), Name: "n"}}}
	p := e.panel(t, "loop", f, store.SyncOptions{Nodes: true})
	e.sy.Cfg.Tick = 20 * time.Millisecond
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { e.sy.Run(rctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, _ := e.st.GetPanel(ctx, store.Scope{All: true}, p.ID)
		if got.NodeCount == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scheduler never synced the due panel")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
}

func i64(v int64) *int64 { return &v }

// A sync stores the counters the panel reported as samples, per panel and per source, and says
// so in the run detail when the panel sent none at all.
func TestSyncRecordsTrafficCountersAndSaysWhenThereAreNone(t *testing.T) {
	e := newEnv(t)
	with := e.panel(t, "with", &fakePanel{
		nodes: []remnawave.Node{{RemoteUUID: uuidN("01"), Name: "n", TrafficUsedBytes: i64(5000)}},
		pages: []remnawave.UsersPage{{Users: []remnawave.User{
			{RemoteUUID: "7", Username: "life", LifetimeBytes: i64(900), UsedBytes: i64(10)},
			{RemoteUUID: "8", Username: "period", UsedBytes: i64(40)},
			{RemoteUUID: "9", Username: "none"},
		}, Total: 3, Next: -1, WithCounter: 2}},
	}, both)
	without := e.panel(t, "without", &fakePanel{
		nodes: []remnawave.Node{{RemoteUUID: uuidN("01"), Name: "n"}},
		pages: []remnawave.UsersPage{{Users: []remnawave.User{{RemoteUUID: "7", Username: "x"}}, Total: 1, Next: -1}},
	}, both)
	for _, p := range []store.Panel{with, without} {
		if r, err := e.sy.SyncPanel(ctx, p.ID, "manual"); err != nil || r.Status != "ok" {
			t.Fatalf("%+v %v", r, err)
		}
	}
	q := store.AnalyticsQuery{PanelIDs: []string{with.ID}, From: e.now.Add(-time.Hour), To: e.now.Add(time.Hour)}
	nodes, err := e.st.TrafficByNode(ctx, q)
	if err != nil || len(nodes) != 1 || nodes[0].Samples != 1 || nodes[0].Current != 5000 {
		t.Fatalf("node counters: %+v %v", nodes, err)
	}
	if _, err := e.sy.SyncPanel(ctx, with.ID, "manual"); err != nil { // a second pass adds a second sample
		t.Fatal(err)
	}
	e.now = e.now.Add(5 * time.Minute) // time moves between passes
	runs, _ := e.st.ListSyncRuns(ctx, store.Scope{All: true}, without.ID, 10)
	var detail string
	for _, r := range runs {
		if r.Detail != nil {
			detail += *r.Detail
		}
	}
	if !strings.Contains(detail, "no node traffic counter") || !strings.Contains(detail, "no user traffic counter") {
		t.Fatalf("a panel without counters must say so, got %q", detail)
	}
	other := store.AnalyticsQuery{PanelIDs: []string{without.ID}, From: e.now.Add(-time.Hour), To: e.now.Add(time.Hour)}
	if rows, _ := e.st.TrafficByNode(ctx, other); rows[0].Samples != 0 {
		t.Fatalf("invented counters: %+v", rows)
	}
}
