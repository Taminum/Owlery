package remnawave

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/safehttp"
)

const token = "test-token-DO-NOT-LEAK"

// plainGetter lets tests hit httptest over loopback; production always goes through safehttp.
type plainGetter struct{}

func (plainGetter) Get(ctx context.Context, rawURL string, h http.Header) (*safehttp.Response, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	for k, vs := range h {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return &safehttp.Response{Status: resp.StatusCode, Body: b}, nil
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "v3.4", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type route struct {
	status int
	body   []byte
}

// panel serves fixtures for a path->route table and records what it was asked.
type panel struct {
	*httptest.Server
	mu   sync.Mutex
	seen []string
	auth []string
}

func newPanel(t *testing.T, routes map[string]route) *panel {
	t.Helper()
	p := &panel{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.seen = append(p.seen, r.URL.RequestURI())
		p.auth = append(p.auth, r.Header.Get("Authorization"))
		p.mu.Unlock()
		rt, ok := routes[r.URL.Path]
		if !ok {
			rt = route{status: 404, body: []byte(`{"message":"Cannot GET"}`)}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rt.status)
		_, _ = w.Write(rt.body)
	}))
	t.Cleanup(p.Close)
	return p
}

func fullRoutes(t *testing.T) map[string]route {
	return map[string]route{
		"/api/nodes":                 {200, fixture(t, "nodes.json")},
		"/api/users/":                {200, fixture(t, "users_page1.json")},
		"/api/system/stats":          {200, fixture(t, "system_stats.json")},
		"/api/bandwidth-stats/nodes": {200, fixture(t, "bandwidth_nodes.json")},
		"/api/system/metadata":       {200, fixture(t, "metadata.json")},
	}
}

func adapter(p *panel) *V3 { return NewV3(p.URL, token, plainGetter{}) }

func checkStatus(res ProbeResult, name string) CheckStatus {
	for _, c := range res.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	return "absent"
}

func TestProbeFullPanel(t *testing.T) {
	p := newPanel(t, fullRoutes(t))
	res := adapter(p).Probe(context.Background())

	if !res.Reachable || !res.TLSOK || !res.Authenticated || !res.RequiredOK() {
		t.Fatalf("expected a healthy panel: %+v", res)
	}
	want := Capabilities{Nodes: true, Users: true, SystemStats: true, Bandwidth: true, Metadata: true}
	if res.Capabilities != want {
		t.Fatalf("capabilities %+v", res.Capabilities)
	}
	if res.APIVersion != "3.4.5" || res.NodeCount != 3 {
		t.Fatalf("version %q nodes %d (row without uuid must not count)", res.APIVersion, res.NodeCount)
	}
	for _, a := range p.auth {
		if a != "Bearer "+token {
			t.Fatalf("every request must carry the bearer token, got %q", a)
		}
	}
	for _, c := range res.Checks {
		if c.Status != CheckOK {
			t.Errorf("check %s = %s", c.Name, c.Status)
		}
	}
}

func TestProbeRejectedTokenStopsEarly(t *testing.T) {
	for status, code := range map[int]string{401: CodeUnauthorized, 403: CodeForbidden} {
		p := newPanel(t, map[string]route{"/api/nodes": {status, []byte(`{}`)}})
		res := adapter(p).Probe(context.Background())
		if !res.Reachable || !res.TLSOK || res.Authenticated || res.RequiredOK() {
			t.Fatalf("%d: %+v", status, res)
		}
		var auth Check
		for _, c := range res.Checks {
			if c.Name == "auth" {
				auth = c
			}
		}
		if auth.ErrorCode != code || checkStatus(res, "nodes") != CheckSkipped {
			t.Fatalf("%d: auth=%+v nodes=%s", status, auth, checkStatus(res, "nodes"))
		}
		if len(p.seen) != 1 {
			t.Fatalf("a rejected token must not be used for further requests, saw %v", p.seen)
		}
	}
}

func TestProbeServerErrorsDoNotProveAuthentication(t *testing.T) {
	for _, status := range []int{404, 429, 500, 502, 503} {
		p := newPanel(t, map[string]route{"/api/nodes": {status, []byte(`oops`)}})
		res := adapter(p).Probe(context.Background())
		if res.Authenticated || res.RequiredOK() {
			t.Fatalf("%d must not count as authenticated: %+v", status, res)
		}
		if !res.Reachable {
			t.Fatalf("%d is still an HTTP answer", status)
		}
	}
}

func TestProbeUnreachable(t *testing.T) {
	p := newPanel(t, nil)
	url := p.URL
	p.Close()
	res := NewV3(url, token, plainGetter{}).Probe(context.Background())
	if res.Reachable || res.Authenticated || res.RequiredOK() {
		t.Fatalf("%+v", res)
	}
	if checkStatus(res, "connection") != CheckFailed || checkStatus(res, "nodes") != CheckSkipped {
		t.Fatalf("%+v", res.Checks)
	}
}

func TestProbePartialCapabilitiesAreReportedPerFeature(t *testing.T) {
	routes := fullRoutes(t)
	routes["/api/users/"] = route{403, []byte(`{}`)} // token lacks the users scope
	delete(routes, "/api/bandwidth-stats/nodes")     // older panel without bandwidth stats
	delete(routes, "/api/system/metadata")           // and without metadata
	p := newPanel(t, routes)
	res := adapter(p).Probe(context.Background())

	if !res.RequiredOK() {
		t.Fatal("optional gaps must not fail the required checks")
	}
	if res.Capabilities.Users || res.Capabilities.Bandwidth || res.Capabilities.Metadata || !res.Capabilities.Nodes || !res.Capabilities.SystemStats {
		t.Fatalf("capabilities %+v", res.Capabilities)
	}
	if checkStatus(res, "users") != CheckFailed || checkStatus(res, "stats") != CheckUnsupported || checkStatus(res, "version") != CheckUnsupported {
		t.Fatalf("checks %+v", res.Checks)
	}
	if res.APIVersion != "" {
		t.Fatal("no version means no version claim")
	}
}

func TestProbeIsReadOnly(t *testing.T) {
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		w.WriteHeader(404)
	}))
	defer srv.Close()
	NewV3(srv.URL, token, plainGetter{}).Probe(context.Background())
	for _, m := range methods {
		if m != http.MethodGet {
			t.Fatalf("adapter must only GET, saw %s", m)
		}
	}
}

func TestListNodesSkipsRowsWithoutIdentity(t *testing.T) {
	p := newPanel(t, fullRoutes(t))
	nodes, err := adapter(p).ListNodes(context.Background())
	if err != nil || len(nodes) != 3 {
		t.Fatalf("%v %d", err, len(nodes))
	}
	a := nodes[0]
	if a.RemoteUUID != "3f1c0a52-0000-4a00-8000-00000000a001" || a.Name != "node-alpha" || a.CountryCode != "NL" ||
		a.XrayVersion != "26.3.27" || a.IsConnected == nil || !*a.IsConnected || a.UsersOnline == nil || *a.UsersOnline != 4 || a.LastStatusChange == nil {
		t.Fatalf("alpha parsed wrong: %+v", a)
	}
	b := nodes[1]
	if b.XrayVersion != "" || b.LastStatusChange != nil || b.IsConnected == nil || *b.IsConnected {
		t.Fatalf("beta (nulls) parsed wrong: %+v", b)
	}
	g := nodes[2]
	if g.IsConnected != nil || g.UsersOnline != nil || g.IsDisabled == nil || !*g.IsDisabled {
		t.Fatalf("gamma (missing optional fields) must stay unknown, not false: %+v", g)
	}
}

func TestListNodesUnrecognisableShapeIsIncompatible(t *testing.T) {
	p := newPanel(t, map[string]route{"/api/nodes": {200, fixture(t, "nodes_unrecognisable.json")}})
	_, err := adapter(p).ListNodes(context.Background())
	if ErrorCode(err) != CodeIncompatible {
		t.Fatalf("got %v", err)
	}
	p = newPanel(t, map[string]route{"/api/nodes": {200, []byte(`<html>login</html>`)}})
	if _, err := adapter(p).ListNodes(context.Background()); ErrorCode(err) != CodeIncompatible {
		t.Fatalf("html login page must be incompatible, got %v", err)
	}
}

func TestListUsersPagination(t *testing.T) {
	var starts []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		starts = append(starts, r.URL.Query().Get("start")+"/"+r.URL.Query().Get("size"))
		if r.URL.Query().Get("start") == "0" {
			_, _ = w.Write(fixture(t, "users_page1.json"))
		} else {
			_, _ = w.Write(fixture(t, "users_page2.json"))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	a := NewV3(srv.URL, token, plainGetter{})

	p1, err := a.ListUsers(context.Background(), 0, 3)
	if err != nil || len(p1.Users) != 2 || p1.Skipped != 1 || p1.Total != 5 || p1.Next != 3 {
		t.Fatalf("page1 %+v %v", p1, err)
	}
	p2, err := a.ListUsers(context.Background(), p1.Next, 3)
	if err != nil || len(p2.Users) != 2 || p2.Next != -1 {
		t.Fatalf("page2 %+v %v", p2, err)
	}
	if strings.Join(starts, ",") != "0/3,3/3" {
		t.Fatalf("offset pagination params wrong: %v", starts)
	}
	if p1.Users[0].RemoteUUID == "" || p1.Users[0].Username != "alice" {
		t.Fatalf("%+v", p1.Users[0])
	}
}

func TestUserWithoutAnyIdentifierGetsNoInventedIdentity(t *testing.T) {
	p := newPanel(t, fullRoutes(t))
	page, _ := adapter(p).ListUsers(context.Background(), 0, 3)
	for _, u := range page.Users {
		if u.Username == "no-identity-user" {
			t.Fatal("a user without a UUID must be skipped, never given an identity")
		}
	}
	if page.Skipped != 1 {
		t.Fatal("the skip must be counted so the sync can report partial data")
	}
}

func TestListUsersCapsPageSize(t *testing.T) {
	var size string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		size = r.URL.Query().Get("size")
		_, _ = w.Write([]byte(`{"response":{"total":0,"users":[]}}`))
	}))
	defer srv.Close()
	_, _ = NewV3(srv.URL, token, plainGetter{}).ListUsers(context.Background(), 0, 100000)
	if size != "500" {
		t.Fatalf("size must be capped, sent %s", size)
	}
}

func TestStatusMapping(t *testing.T) {
	for status, code := range map[int]string{401: CodeUnauthorized, 403: CodeForbidden, 404: CodeNotFound, 429: CodeRateLimited, 500: CodeUpstream, 503: CodeUpstream, 418: CodeUnexpected} {
		p := newPanel(t, map[string]route{"/api/nodes": {status, []byte(`{}`)}})
		_, err := adapter(p).ListNodes(context.Background())
		if ErrorCode(err) != code {
			t.Errorf("%d: got %s want %s", status, ErrorCode(err), code)
		}
	}
	p := newPanel(t, map[string]route{"/api/nodes": {429, []byte(`{}`)}})
	_, err := adapter(p).ListNodes(context.Background())
	if ae, ok := err.(*APIError); !ok || ae.RetryAfter <= 0 {
		t.Fatalf("429 must carry a retry hint: %v", err)
	}
}

func TestTrafficCountersArriveInM3(t *testing.T) {
	if _, err := NewV3("https://x.example.com", token, plainGetter{}).GetTrafficCounters(context.Background(), timeZero, timeZero); ErrorCode(err) != CodeNotImplemented {
		t.Fatalf("got %v", err)
	}
}

func TestNoErrorOrCheckEverContainsTheToken(t *testing.T) {
	for _, status := range []int{401, 403, 404, 429, 500} {
		p := newPanel(t, map[string]route{"/api/nodes": {status, []byte(token)}}) // hostile server echoes it
		res := adapter(p).Probe(context.Background())
		if strings.Contains(strings.Join(checkStrings(res), " "), token) {
			t.Fatalf("%d: token leaked into probe result", status)
		}
		_, err := adapter(p).ListNodes(context.Background())
		if err != nil && strings.Contains(err.Error(), token) {
			t.Fatalf("%d: token leaked into error", status)
		}
	}
}

func checkStrings(r ProbeResult) []string {
	var out []string
	for _, c := range r.Checks {
		out = append(out, c.Name, string(c.Status), c.ErrorCode)
	}
	return append(out, r.APIVersion)
}

// timeZero keeps the M3 stub test free of time imports noise.
var timeZero = time.Time{}

// urlCheckingGetter is the production URL rules (safehttp) in front of canned answers, so a
// URL shape the hardened client would refuse is caught here and not only against a live panel.
type urlCheckingGetter struct {
	t    *testing.T
	pol  *safehttp.Policy
	seen []string
}

func (g *urlCheckingGetter) Get(_ context.Context, rawURL string, _ http.Header) (*safehttp.Response, error) {
	if err := safehttp.ValidateRequestURL(rawURL, g.pol); err != nil {
		g.t.Errorf("the hardened client would refuse %s: %v", rawURL, err)
		return nil, err
	}
	g.seen = append(g.seen, rawURL)
	switch {
	case strings.Contains(rawURL, "/api/nodes"):
		return &safehttp.Response{Status: 200, Body: fixture(g.t, "nodes.json")}, nil
	case strings.Contains(rawURL, "/api/users/"):
		return &safehttp.Response{Status: 200, Body: fixture(g.t, "users_page1.json")}, nil
	case strings.Contains(rawURL, "/api/system/stats"):
		return &safehttp.Response{Status: 200, Body: fixture(g.t, "system_stats.json")}, nil
	case strings.Contains(rawURL, "/api/bandwidth-stats/nodes"):
		return &safehttp.Response{Status: 200, Body: fixture(g.t, "bandwidth_nodes.json")}, nil
	case strings.Contains(rawURL, "/api/system/metadata"):
		return &safehttp.Response{Status: 200, Body: fixture(g.t, "metadata.json")}, nil
	}
	return &safehttp.Response{Status: 404, Body: []byte(`{}`)}, nil
}

func TestEveryURLTheAdapterBuildsPassesTheHardenedClientRules(t *testing.T) {
	g := &urlCheckingGetter{t: t, pol: &safehttp.Policy{}}
	a := NewV3("https://panel.example.com", token, g)
	res := a.Probe(context.Background())
	if !res.RequiredOK() || res.Capabilities != (Capabilities{Nodes: true, Users: true, SystemStats: true, Bandwidth: true, Metadata: true}) {
		t.Fatalf("%+v", res)
	}
	if _, err := a.ListUsers(context.Background(), 200, 200); err != nil {
		t.Fatal(err)
	}
	if len(g.seen) < 6 {
		t.Fatalf("expected the probe and a page to be exercised, saw %v", g.seen)
	}
	// A panel served from a sub-path keeps working.
	g2 := &urlCheckingGetter{t: t, pol: &safehttp.Policy{}}
	if _, err := NewV3("https://panel.example.com/secret-prefix", token, g2).ListNodes(context.Background()); err != nil || !strings.HasPrefix(g2.seen[0], "https://panel.example.com/secret-prefix/api/nodes") {
		t.Fatalf("%v %v", err, g2.seen)
	}
}

func TestSkippedRowsReportFieldNamesButNeverValues(t *testing.T) {
	p := newPanel(t, fullRoutes(t))
	page, err := adapter(p).ListUsers(context.Background(), 0, 3)
	if err != nil || page.Skipped != 1 {
		t.Fatalf("%+v %v", page, err)
	}
	got := strings.Join(page.SkippedFields, ",")
	for _, want := range []string{"id", "shortUuid", "username", "status"} {
		if !strings.Contains(got, want) {
			t.Errorf("field %q should be reported: %s", want, got)
		}
	}
	if strings.Contains(got, "no-identity-user") || strings.Contains(got, "cccc3333") {
		t.Fatalf("a value leaked into the diagnostics: %s", got)
	}
}

func TestUserIdentityIsTheNumericIDWhenThereIsNoUUID(t *testing.T) {
	p := newPanel(t, fullRoutes(t))
	page, err := adapter(p).ListUsers(context.Background(), 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Users) != 2 || page.Users[0].RemoteUUID != "1" || page.Users[1].RemoteUUID != "2" {
		t.Fatalf("identity must be the stable numeric id, got %+v", page.Users)
	}
	row := func(js string) map[string]json.RawMessage {
		var m map[string]json.RawMessage
		_ = json.Unmarshal([]byte(js), &m)
		return m
	}
	for js, want := range map[string]string{
		`{"uuid":"u-1","id":7}`: "u-1", `{"id":7}`: "7", `{"id":0}`: "", `{"id":-3}`: "", `{"id":"7"}`: "", `{"id":1.5}`: "",
		`{"shortUuid":"abc"}`: "", `{"vlessUuid":"abc"}`: "", `{}`: "",
	} {
		if got := userIdentity(row(js)); got != want {
			t.Errorf("%s -> %q, want %q", js, got, want)
		}
	}
}

func TestTrafficCountersAreReadStrictly(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"response":{"total":6,"users":[
 {"id":1,"username":"both","userTraffic":{"usedTrafficBytes":10,"lifetimeUsedTrafficBytes":9007199254740993}},
 {"id":2,"username":"used-only","userTraffic":{"usedTrafficBytes":5}},
 {"id":3,"username":"none"},
 {"id":4,"username":"quoted","userTraffic":{"usedTrafficBytes":"77"}},
 {"id":5,"username":"negative","userTraffic":{"usedTrafficBytes":-1,"lifetimeUsedTrafficBytes":1.5}},
 {"id":6,"username":"null","userTraffic":null}
]}}`))
	})
	mux.HandleFunc("/api/nodes", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"response":[{"uuid":"n1","name":"a","trafficUsedBytes":123456789012},{"uuid":"n2","name":"b"},{"uuid":"n3","name":"c","trafficUsedBytes":"5"}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	a := NewV3(srv.URL, token, plainGetter{})

	pg, err := a.ListUsers(context.Background(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]User{}
	for _, u := range pg.Users {
		by[u.Username] = u
	}
	if u := by["both"]; u.LifetimeBytes == nil || *u.LifetimeBytes != 9007199254740993 || *u.UsedBytes != 10 {
		t.Fatalf("a large counter must keep every digit: %+v", u)
	}
	if u := by["used-only"]; u.LifetimeBytes != nil || u.UsedBytes == nil || *u.UsedBytes != 5 {
		t.Fatalf("%+v", u)
	}
	for _, n := range []string{"none", "quoted", "negative", "null"} {
		if u := by[n]; u.LifetimeBytes != nil || u.UsedBytes != nil {
			t.Errorf("%s: an unusable counter must read as absent, got %+v", n, u)
		}
	}
	if pg.WithCounter != 2 {
		t.Fatalf("with counter: %d", pg.WithCounter)
	}

	nodes, err := a.ListNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if nodes[0].TrafficUsedBytes == nil || *nodes[0].TrafficUsedBytes != 123456789012 || nodes[1].TrafficUsedBytes != nil || nodes[2].TrafficUsedBytes != nil {
		t.Fatalf("%+v", nodes)
	}
}
