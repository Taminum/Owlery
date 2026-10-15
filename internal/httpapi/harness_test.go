package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/demo"
	"github.com/Taminum/RemnaScope/internal/ingest"
	"github.com/Taminum/RemnaScope/internal/remnawave"
	"github.com/Taminum/RemnaScope/internal/safehttp"
	"github.com/Taminum/RemnaScope/internal/secingest"
	"github.com/Taminum/RemnaScope/internal/secops"
	"github.com/Taminum/RemnaScope/internal/secrets"
	"github.com/Taminum/RemnaScope/internal/store"
	"github.com/Taminum/RemnaScope/internal/store/storetest"
	"github.com/Taminum/RemnaScope/internal/syncer"
)

var ctx = context.Background()

var fastHash = auth.Argon2Params{MemoryKiB: 8, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}

const testPassword = "correct horse battery staple"

// Tokens the fake panels understand.
const (
	tokGood    = "tok-SECRET-good-123"
	tokGood2   = "tok-SECRET-good-456"
	tokBad     = "tok-SECRET-bad-789"
	tokPartial = "tok-SECRET-partial-000"
	tokDown    = "tok-SECRET-down-111"
)

// fakePanel is what a "remote Remnawave" does for a given token.
type fakePanel struct {
	mu        sync.Mutex
	nodes     []remnawave.Node
	users     []remnawave.User
	block     chan struct{} // when set, ListNodes waits
	entered   chan struct{}
	enterOnce sync.Once
}

// adapterView is one connection to a fakePanel using one token.
type adapterView struct {
	*fakePanel
	token string
}

func (f adapterView) Probe(context.Context) remnawave.ProbeResult {
	ok := func(n string, req bool) remnawave.Check {
		return remnawave.Check{Name: n, Required: req, Status: remnawave.CheckOK}
	}
	switch f.token {
	case tokBad:
		return remnawave.ProbeResult{Reachable: true, TLSOK: true, Checks: []remnawave.Check{ok("connection", true),
			{Name: "auth", Required: true, Status: remnawave.CheckFailed, ErrorCode: remnawave.CodeUnauthorized},
			{Name: "nodes", Required: true, Status: remnawave.CheckSkipped}}}
	case tokDown:
		return remnawave.ProbeResult{Checks: []remnawave.Check{{Name: "connection", Required: true, Status: remnawave.CheckFailed, ErrorCode: safehttp.CodeConnect},
			{Name: "auth", Required: true, Status: remnawave.CheckSkipped}, {Name: "nodes", Required: true, Status: remnawave.CheckSkipped}}}
	}
	res := remnawave.ProbeResult{Reachable: true, TLSOK: true, Authenticated: true, APIVersion: "3.4.5", NodeCount: len(f.nodes),
		Capabilities: remnawave.Capabilities{Nodes: true, Users: true, SystemStats: true, Bandwidth: true, Metadata: true},
		Checks:       []remnawave.Check{ok("connection", true), ok("auth", true), ok("nodes", true), ok("users", false), ok("stats", false), ok("version", false)}}
	if f.token == tokPartial {
		res.Capabilities.Users = false
		res.Checks[3] = remnawave.Check{Name: "users", Status: remnawave.CheckFailed, ErrorCode: remnawave.CodeForbidden}
	}
	for _, n := range f.nodes {
		res.NodesPreview = append(res.NodesPreview, n.Name)
	}
	return res
}
func (f adapterView) GetCapabilities(context.Context) (remnawave.Capabilities, error) {
	return f.Probe(ctx).Capabilities, nil
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
	return f.nodes, nil
}
func (f *fakePanel) ListUsers(_ context.Context, offset, _ int) (remnawave.UsersPage, error) {
	if offset > 0 {
		return remnawave.UsersPage{Next: -1, Total: len(f.users)}, nil
	}
	return remnawave.UsersPage{Users: f.users, Total: len(f.users), Next: -1}, nil
}

type harness struct {
	t      *testing.T
	st     *store.Store
	ring   *secrets.Keyring
	srv    *Server
	ts     *httptest.Server
	logs   *bytes.Buffer
	remote map[string]*fakePanel // by host
	now    time.Time
	nowMu  sync.Mutex
}

type harnessOpt func(*Server)

func newHarness(t *testing.T, opts ...harnessOpt) *harness {
	t.Helper()
	st := storetest.New(t)
	ring, _ := secrets.NewKeyring(map[int][]byte{1: bytes32(1)}, 1)
	h := &harness{t: t, st: st, ring: ring, logs: &bytes.Buffer{}, remote: map[string]*fakePanel{}, now: time.Now()}
	if err := demo.Seed(ctx, st); err != nil {
		t.Fatal(err)
	}

	pol := safehttp.Policy{}
	factory := func(baseURL, token string, useCA bool) (remnawave.PanelAdapter, string, error) {
		u, err := safehttp.ParseBaseURL(baseURL, &pol)
		if err != nil {
			return nil, "", err
		}
		h.nowMu.Lock()
		defer h.nowMu.Unlock()
		fp, ok := h.remote[u.Host]
		if !ok {
			fp = &fakePanel{nodes: []remnawave.Node{{RemoteUUID: "n1", Name: "node-1"}, {RemoteUUID: "n2", Name: "node-2"}}}
			h.remote[u.Host] = fp
		}
		return adapterView{fakePanel: fp, token: token}, u.String(), nil
	}

	sy := syncer.New(st, ring,
		func(p store.Panel, token string, g remnawave.Getter) (remnawave.PanelAdapter, error) {
			a, _, err := factory(p.BaseURL, token, p.UseCustomCA)
			return a, err
		},
		func(store.Panel) remnawave.Getter { return nopGetter{} },
		func() syncer.Config { c := syncer.DefaultConfig(); c.RPS = 1000; return c }(), slog.New(slog.NewTextHandler(h.logs, nil)))

	h.srv = &Server{Store: st, Ring: ring, Probe: factory, Sync: sy, Hash: fastHash,
		Log: slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now: func() time.Time { h.nowMu.Lock(); defer h.nowMu.Unlock(); return h.now }}
	h.srv.Limits = DefaultLimits()
	h.srv.Limits.Writes = auth.NewLimiter(1000, 1000)
	h.srv.Limits.Probe = auth.NewLimiter(1000, 1000)
	h.srv.Limits.Test = auth.NewLimiter(1000, 1000)
	h.srv.Limits.Sync = auth.NewLimiter(1000, 1000)
	h.srv.Limits.Login = auth.NewLimiter(1000, 1000)
	for _, o := range opts {
		o(h.srv)
	}
	h.srv.Ingest = (&ingest.Server{Store: st}).Handler() // the agents' route, as in production
	hub := secops.New()
	h.srv.SecOps = hub
	h.srv.SecIngest = (&secingest.Server{Store: st, Ops: hub}).Handler()
	h.ts = httptest.NewServer(h.srv.Handler())
	t.Cleanup(h.ts.Close)
	return h
}

type nopGetter struct{}

func (nopGetter) Get(context.Context, string, http.Header) (*safehttp.Response, error) {
	return nil, io.EOF
}

func bytes32(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func (h *harness) advance(d time.Duration) {
	h.nowMu.Lock()
	h.now = h.now.Add(d)
	h.nowMu.Unlock()
}

func (h *harness) account(name string, owner bool, memberships ...store.Membership) store.Account {
	h.t.Helper()
	hash, _ := auth.HashPassword(testPassword, fastHash)
	a, err := h.st.CreateAccount(ctx, name, hash, owner)
	if err != nil {
		h.t.Fatal(err)
	}
	if len(memberships) > 0 {
		if err := h.st.SetMemberships(ctx, a.ID, memberships); err != nil {
			h.t.Fatal(err)
		}
	}
	return a
}

// client is a browser-like session: cookie jar plus the CSRF token from login.
type client struct {
	h    *harness
	http *http.Client
	csrf string
	me   meResponse
}

func (h *harness) anon() *client {
	jar, _ := cookiejar.New(nil)
	return &client{h: h, http: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (h *harness) login(name string) *client {
	h.t.Helper()
	c := h.anon()
	st, body := c.do("POST", "/api/v1/auth/login", map[string]string{"username": name, "password": testPassword})
	if st != 200 {
		h.t.Fatalf("login %s: %d %s", name, st, body)
	}
	if err := json.Unmarshal(body, &c.me); err != nil {
		h.t.Fatal(err)
	}
	c.csrf = c.me.CSRFToken
	return c
}

type reqOpt func(*http.Request)

func (c *client) do(method, path string, body any, opts ...reqOpt) (int, []byte) {
	c.h.t.Helper()
	var rdr io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			rdr = strings.NewReader(b)
		case []byte:
			rdr = bytes.NewReader(b)
		default:
			j, _ := json.Marshal(b)
			rdr = bytes.NewReader(j)
		}
	}
	req, err := http.NewRequest(method, c.h.ts.URL+path, rdr)
	if err != nil {
		c.h.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" && method != "GET" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for _, o := range opts {
		o(req)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (c *client) rawDo(req *http.Request) *http.Response {
	resp, err := c.http.Do(req)
	if err != nil {
		c.h.t.Fatal(err)
	}
	return resp
}

func (c *client) get(path string) (int, []byte) { return c.do("GET", path, nil) }

func parse[T any](t *testing.T, b []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("bad JSON %s: %v", b, err)
	}
	return v
}

func errCode(b []byte) string {
	var e apiError
	_ = json.Unmarshal(b, &e)
	return e.Code
}

// createPanel connects a real (non-demo) panel through the API as an owner.
func (h *harness) createPanel(c *client, name, host, token string) panelDTO {
	h.t.Helper()
	st, body := c.do("POST", "/api/v1/panels", map[string]any{"name": name, "base_url": "https://" + host, "api_token": token})
	if st != 201 {
		h.t.Fatalf("create %s: %d %s", name, st, body)
	}
	return parse[struct {
		Panel panelDTO `json:"panel"`
	}](h.t, body).Panel
}

func withNow(h *harness, f func(*Server)) harnessOpt { return func(s *Server) { f(s) } }

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
