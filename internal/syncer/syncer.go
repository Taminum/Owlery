// Package syncer pulls nodes and users from each panel on its own schedule.
//
// Panels are independent: one job per panel, its own rate limiter, its own failure
// counter and circuit breaker. A slow, failing or rate-limited panel can delay
// only itself.
package syncer

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/Taminum/RemnaScope/internal/remnawave"
	"github.com/Taminum/RemnaScope/internal/safehttp"
	"github.com/Taminum/RemnaScope/internal/secrets"
	"github.com/Taminum/RemnaScope/internal/store"
)

// AdapterFactory builds the adapter for one panel. token is the decrypted API token;
// the factory must not retain it beyond the adapter's life.
type AdapterFactory func(p store.Panel, token string, g remnawave.Getter) (remnawave.PanelAdapter, error)

// Fetcher is the production Getter source: a hardened client per panel.
type Fetcher func(p store.Panel) remnawave.Getter

type Config struct {
	Tick          time.Duration // how often to look for due panels
	MaxConcurrent int           // panels syncing at once
	RPS           float64       // requests per second per panel
	PageSize      int
	MaxPages      int // hard stop for a listing that never ends
	BreakerAfter  int
	BreakerFor    time.Duration
	RunTimeout    time.Duration
}

func DefaultConfig() Config {
	return Config{Tick: 10 * time.Second, MaxConcurrent: 4, RPS: 4, PageSize: 200, MaxPages: 500,
		BreakerAfter: 5, BreakerFor: 15 * time.Minute, RunTimeout: 5 * time.Minute}
}

var (
	ErrBusy        = errors.New("syncer: panel is already syncing")
	ErrNotSyncable = errors.New("syncer: panel cannot be synced")
)

type Syncer struct {
	St      *store.Store
	Ring    *secrets.Keyring
	Factory AdapterFactory
	Fetch   Fetcher
	Cfg     Config
	Log     *slog.Logger
	Now     func() time.Time

	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func New(st *store.Store, ring *secrets.Keyring, factory AdapterFactory, fetch Fetcher, cfg Config, log *slog.Logger) *Syncer {
	if log == nil {
		log = slog.Default()
	}
	return &Syncer{St: st, Ring: ring, Factory: factory, Fetch: fetch, Cfg: cfg, Log: log, Now: time.Now, locks: map[string]*sync.Mutex{}}
}

func (s *Syncer) lockFor(id string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.locks[id]
	if !ok {
		m = &sync.Mutex{}
		s.locks[id] = m
	}
	return m
}

// Busy reports whether a sync of the panel is running right now.
func (s *Syncer) Busy(panelID string) bool {
	lk := s.lockFor(panelID)
	if lk.TryLock() {
		lk.Unlock()
		return false
	}
	return true
}

// Run looks for due panels until ctx ends.
func (s *Syncer) Run(ctx context.Context) {
	t := time.NewTicker(s.Cfg.Tick)
	defer t.Stop()
	sem := make(chan struct{}, s.Cfg.MaxConcurrent)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		s.tick(ctx, sem, &wg)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Syncer) tick(ctx context.Context, sem chan struct{}, wg *sync.WaitGroup) {
	due, err := s.St.DuePanels(ctx, s.Now().UTC(), 50)
	if err != nil {
		s.Log.Error("list due panels", "err", err)
		return
	}
	for _, p := range due {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		wg.Add(1)
		go func(p store.Panel) {
			defer wg.Done()
			defer func() { <-sem }()
			if _, err := s.SyncPanel(ctx, p.ID, "schedule"); err != nil && !errors.Is(err, ErrBusy) {
				s.Log.Warn("sync", "panel", p.ID, "err", err)
			}
		}(p)
	}
}

type Result struct {
	Status string // ok | partial | failed
	Runs   []string
}

type limitedGetter struct {
	g   remnawave.Getter
	lim *rate.Limiter
}

func (l limitedGetter) Get(ctx context.Context, u string, h http.Header) (*safehttp.Response, error) {
	if err := l.lim.Wait(ctx); err != nil {
		return nil, err
	}
	return l.g.Get(ctx, u, h)
}

// SyncPanel runs one full sync of a panel. It returns ErrBusy if one is already running.
func (s *Syncer) SyncPanel(ctx context.Context, panelID, trigger string) (Result, error) {
	lk := s.lockFor(panelID)
	if !lk.TryLock() {
		return Result{}, ErrBusy
	}
	defer lk.Unlock()

	p, err := s.St.GetPanel(ctx, store.Scope{All: true}, panelID)
	if err != nil {
		return Result{}, err
	}
	if p.Demo || p.Status == "disabled" || !p.HasCredential {
		return Result{}, ErrNotSyncable
	}
	ctx, cancel := context.WithTimeout(ctx, s.Cfg.RunTimeout)
	defer cancel()

	interval := time.Duration(p.SyncIntervalSeconds) * time.Second
	fail := func(code string, retry time.Duration) (Result, error) {
		_ = s.St.RecordSyncOutcome(ctx, p.ID, false, code, interval, s.Now().UTC(), retry, s.Cfg.BreakerAfter, s.Cfg.BreakerFor)
		return Result{Status: "failed"}, nil
	}

	sealed, err := s.St.Credential(ctx, p.ID)
	if err != nil {
		return fail("credential_missing", 0)
	}
	raw, err := s.Ring.Open(p.ID, sealed)
	if err != nil {
		s.Log.Error("credential cannot be decrypted", "panel", p.ID) // never log the error text: it may hint at key state
		return fail("credential_unreadable", 0)
	}
	token := string(raw)
	for i := range raw {
		raw[i] = 0
	}

	g := limitedGetter{g: s.Fetch(p), lim: rate.NewLimiter(rate.Limit(s.Cfg.RPS), 1)}
	ad, err := s.Factory(p, token, g)
	if err != nil {
		return fail("adapter_unavailable", 0)
	}

	start := s.Now().UTC()
	res := Result{Status: "ok"}
	var retry time.Duration
	hardFail := false

	if p.SyncOptions.Nodes {
		id, st, code, rt := s.syncNodes(ctx, p, ad, start, trigger)
		res.Runs = append(res.Runs, id)
		retry = max(retry, rt)
		if st != "ok" {
			res.Status, hardFail = "failed", true
			_ = code
		}
	}
	if p.SyncOptions.Users && usersSupported(p) {
		id, st, code, rt := s.syncUsers(ctx, p, ad, start, trigger)
		res.Runs = append(res.Runs, id)
		retry = max(retry, rt)
		switch {
		case st == "ok":
		case code == remnawave.CodeForbidden || code == remnawave.CodeNotFound:
			// A permission or version gap is a configuration state, not an outage: report it,
			// keep syncing nodes on schedule, do not trip the breaker.
			if res.Status == "ok" {
				res.Status = "partial"
			}
		default:
			if res.Status != "failed" {
				res.Status = "partial"
			}
			hardFail = true
		}
	}

	if hardFail {
		_ = s.St.RecordSyncOutcome(ctx, p.ID, false, res.Status, interval, s.Now().UTC(), retry, s.Cfg.BreakerAfter, s.Cfg.BreakerFor)
	} else {
		_ = s.St.RecordSyncOutcome(ctx, p.ID, true, res.Status, interval, s.Now().UTC(), 0, s.Cfg.BreakerAfter, s.Cfg.BreakerFor)
	}
	return res, nil
}

func usersSupported(p store.Panel) bool {
	if len(p.Capabilities) == 0 {
		return true
	}
	var c struct {
		Users *bool `json:"users"`
	}
	if json.Unmarshal(p.Capabilities, &c) != nil || c.Users == nil {
		return true
	}
	return *c.Users
}

func retryHint(err error) time.Duration {
	var ae *remnawave.APIError
	if errors.As(err, &ae) {
		return ae.RetryAfter
	}
	return 0
}

func (s *Syncer) syncNodes(ctx context.Context, p store.Panel, ad remnawave.PanelAdapter, start time.Time, trigger string) (runID, status, code string, retry time.Duration) {
	runID, err := s.St.StartSyncRun(ctx, p.ID, "nodes", trigger)
	if err != nil {
		return "", "failed", "internal", 0
	}
	nodes, err := ad.ListNodes(ctx)
	if err != nil {
		code = remnawave.ErrorCode(err)
		_ = s.St.FinishSyncRun(ctx, runID, "failed", code, "", map[string]any{})
		return runID, "failed", code, retryHint(err)
	}
	recs := make([]store.NodeRecord, 0, len(nodes))
	for _, n := range nodes {
		recs = append(recs, store.NodeRecord{RemoteUUID: n.RemoteUUID, Name: n.Name, CountryCode: n.CountryCode, XrayVersion: n.XrayVersion,
			IsConnected: n.IsConnected, IsDisabled: n.IsDisabled, UsersOnline: n.UsersOnline, LastStatusChange: n.LastStatusChange})
	}
	counts, err := s.St.UpsertNodes(ctx, p.ID, start, recs)
	if err != nil {
		_ = s.St.FinishSyncRun(ctx, runID, "failed", "internal", "", map[string]any{})
		return runID, "failed", "internal", 0
	}
	var cs []store.Counter
	for _, n := range nodes {
		if n.TrafficUsedBytes != nil {
			cs = append(cs, store.Counter{RemoteUUID: n.RemoteUUID, Bytes: *n.TrafficUsedBytes, Source: store.SrcNodeUsed})
		}
	}
	detail := ""
	if len(nodes) > 0 && len(cs) == 0 {
		detail = "the panel sent no node traffic counter (trafficUsedBytes); node traffic cannot be shown"
	}
	if _, err := s.St.RecordNodeCounters(ctx, p.ID, start, cs); err != nil {
		s.Log.Warn("recording node counters", "panel", p.ID)
	}
	_ = s.St.FinishSyncRun(ctx, runID, "ok", "", detail, counts)
	return runID, "ok", "", 0
}

func (s *Syncer) syncUsers(ctx context.Context, p store.Panel, ad remnawave.PanelAdapter, start time.Time, trigger string) (runID, status, code string, retry time.Duration) {
	runID, err := s.St.StartSyncRun(ctx, p.ID, "users", trigger)
	if err != nil {
		return "", "failed", "internal", 0
	}
	var total store.SyncCounts
	var skippedFields []string
	withCounter, seenUsers := 0, 0
	offset := 0
	complete := false
	for page := 0; page < s.Cfg.MaxPages; page++ {
		pg, err := ad.ListUsers(ctx, offset, s.Cfg.PageSize)
		if err != nil {
			code = remnawave.ErrorCode(err)
			st := "failed"
			if total.Added+total.Updated > 0 {
				st = "partial" // some pages landed; removals are skipped because the listing is incomplete
			}
			_ = s.St.FinishSyncRun(ctx, runID, st, code, "", total)
			return runID, st, code, retryHint(err)
		}
		recs := make([]store.UserRecord, 0, len(pg.Users))
		for _, u := range pg.Users {
			recs = append(recs, store.UserRecord{RemoteUUID: u.RemoteUUID, Username: u.Username, Status: u.Status})
		}
		c, err := s.St.UpsertUsers(ctx, p.ID, start, recs)
		if err != nil {
			_ = s.St.FinishSyncRun(ctx, runID, "failed", "internal", "", total)
			return runID, "failed", "internal", 0
		}
		var cs []store.Counter
		for _, u := range pg.Users {
			switch {
			case u.LifetimeBytes != nil:
				cs = append(cs, store.Counter{RemoteUUID: u.RemoteUUID, Bytes: *u.LifetimeBytes, Source: store.SrcUserLifetime})
			case u.UsedBytes != nil:
				cs = append(cs, store.Counter{RemoteUUID: u.RemoteUUID, Bytes: *u.UsedBytes, Source: store.SrcUserUsed})
			}
		}
		if _, err := s.St.RecordUserCounters(ctx, p.ID, start, cs); err != nil {
			s.Log.Warn("recording user counters", "panel", p.ID)
		}
		withCounter += pg.WithCounter
		seenUsers += len(pg.Users)
		total.Added += c.Added
		total.Updated += c.Updated
		total.Skipped += pg.Skipped
		if len(skippedFields) == 0 {
			skippedFields = pg.SkippedFields
		}
		if pg.Next < 0 {
			complete = true
			break
		}
		if pg.Next <= offset { // a panel that does not advance would loop forever
			break
		}
		offset = pg.Next
	}
	if !complete {
		_ = s.St.FinishSyncRun(ctx, runID, "partial", "listing_incomplete", "", total)
		return runID, "partial", "listing_incomplete", 0
	}
	removed, err := s.St.MarkUsersRemoved(ctx, p.ID, start)
	if err != nil {
		_ = s.St.FinishSyncRun(ctx, runID, "failed", "internal", "", total)
		return runID, "failed", "internal", 0
	}
	total.Removed = removed
	detail := ""
	if total.Skipped > 0 {
		detail = "some users have no uuid field and were skipped; fields seen on them: " + strings.Join(skippedFields, ", ")
	}
	if seenUsers > 0 && withCounter == 0 {
		if detail != "" {
			detail += "; "
		}
		detail += "the panel sent no user traffic counter (userTraffic); per-user traffic cannot be shown"
	}
	_ = s.St.FinishSyncRun(ctx, runID, "ok", "", detail, total)
	return runID, "ok", "", 0
}
