package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/demo"
	"github.com/Taminum/Owlery/internal/remnawave"
	"github.com/Taminum/Owlery/internal/store"
)

// --- authentication, sessions, CSRF ------------------------------------------------

func TestLoginLogoutFlow(t *testing.T) {
	h := newHarness(t)
	h.account("alice", true)

	anon := h.anon()
	if st, _ := anon.get("/api/v1/auth/me"); st != 401 {
		t.Fatalf("unauthenticated /me = %d", st)
	}
	c := h.login("alice")
	if c.me.Account.Username != "alice" || !c.me.Account.IsOwner || c.csrf == "" {
		t.Fatalf("%+v", c.me)
	}
	if st, _ := c.get("/api/v1/auth/me"); st != 200 {
		t.Fatalf("me after login = %d", st)
	}
	if st, _ := c.do("POST", "/api/v1/auth/logout", nil); st != 204 {
		t.Fatalf("logout = %d", st)
	}
	if st, _ := c.get("/api/v1/auth/me"); st != 401 {
		t.Fatal("the session must be dead after logout")
	}
}

func TestSessionCookieFlags(t *testing.T) {
	h := newHarness(t, func(s *Server) { s.CookieSecure = true })
	h.account("alice", false)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"alice","password":"`+testPassword+`"}`))
	req.Header.Set("Content-Type", "application/json")
	h.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var ck *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == CookieSession {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" || ck.MaxAge <= 0 {
		t.Fatalf("cookie must be HttpOnly, Secure, SameSite=Strict: %+v", ck)
	}
	var count int
	_ = h.st.Pool().QueryRow(ctx, `SELECT count(*) FROM sessions WHERE token_hash = $1`, []byte(ck.Value)).Scan(&count)
	if count != 0 {
		t.Fatal("the raw token must never be what is stored")
	}
}

func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	h := newHarness(t)
	h.account("real", false)
	disabled := h.account("gone", false)
	_ = h.st.SetAccountDisabled(ctx, disabled.ID, true)

	attempt := func(user, pass string) (int, string, string) {
		st, body := h.anon().do("POST", "/api/v1/auth/login", map[string]string{"username": user, "password": pass})
		var e apiError
		_ = json.Unmarshal(body, &e)
		return st, e.Code, e.Message
	}
	s1, c1, m1 := attempt("real", "wrong password here")
	s2, c2, m2 := attempt("nobody", "wrong password here")
	s3, c3, m3 := attempt("gone", testPassword)
	s4, c4, m4 := attempt("", "x")
	for _, r := range [][3]any{{s1, c1, m1}, {s2, c2, m2}, {s3, c3, m3}, {s4, c4, m4}} {
		if r[0] != 401 || r[1] != "invalid_credentials" || r[2] != m1 {
			t.Fatalf("answers differ: %v vs %v %v %v", r, s1, c1, m1)
		}
	}
}

func TestLockoutAfterRepeatedFailuresRefusesEvenTheRightPassword(t *testing.T) {
	h := newHarness(t)
	a := h.account("alice", false)
	for i := 0; i < 6; i++ {
		h.anon().do("POST", "/api/v1/auth/login", map[string]string{"username": "alice", "password": "nope-nope-nope-nope"})
	}
	st, body := h.anon().do("POST", "/api/v1/auth/login", map[string]string{"username": "alice", "password": testPassword})
	if st != 401 || errCode(body) != "invalid_credentials" {
		t.Fatalf("locked account must refuse the right password too: %d %s", st, body)
	}
	_, _ = h.st.Pool().Exec(ctx, `UPDATE accounts SET locked_until=NULL, failed_logins=0 WHERE id=$1`, a.ID)
	if st, _ := h.anon().do("POST", "/api/v1/auth/login", map[string]string{"username": "alice", "password": testPassword}); st != 200 {
		t.Fatalf("after the lock expires login works: %d", st)
	}
}

func TestLoginIsRateLimitedPerIP(t *testing.T) {
	h := newHarness(t, func(s *Server) { s.Limits.Login = DefaultLimits().Login })
	h.account("alice", false)
	var last int
	for i := 0; i < 15; i++ {
		last, _ = h.anon().do("POST", "/api/v1/auth/login", map[string]string{"username": "alice", "password": "wrong-wrong-wrong"})
	}
	if last != 429 {
		t.Fatalf("the 15th rapid attempt must be rate limited, got %d", last)
	}
}

func TestCSRFAndOriginChecks(t *testing.T) {
	h := newHarness(t)
	h.account("alice", true)
	c := h.login("alice")
	body := map[string]any{"base_url": "https://csrf.example.com", "api_token": tokGood}

	good := c.csrf
	c.csrf = ""
	if st, b := c.do("POST", "/api/v1/panels/probe", body); st != 403 || errCode(b) != "csrf" {
		t.Fatalf("missing token: %d %s", st, b)
	}
	c.csrf = "not-the-token"
	if st, b := c.do("POST", "/api/v1/panels/probe", body); st != 403 || errCode(b) != "csrf" {
		t.Fatalf("wrong token: %d %s", st, b)
	}
	c.csrf = good
	if st, b := c.do("POST", "/api/v1/panels/probe", body, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }); st != 403 || errCode(b) != "cross_origin" {
		t.Fatalf("foreign origin: %d %s", st, b)
	}
	if st, b := c.do("POST", "/api/v1/panels/probe", body, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }); st != 403 || errCode(b) != "cross_origin" {
		t.Fatalf("cross-site fetch: %d %s", st, b)
	}
	if st, b := c.do("POST", "/api/v1/panels/probe", body, func(r *http.Request) { r.Header.Set("Origin", h.ts.URL) }); st != 200 {
		t.Fatalf("same origin must pass: %d %s", st, b)
	}
	// A token from one session is useless in another.
	other := h.login("alice")
	c.csrf = other.csrf
	if st, _ := c.do("POST", "/api/v1/panels/probe", body); st != 403 {
		t.Fatal("a CSRF token from another session was accepted")
	}
	// Reads never need it.
	c.csrf = ""
	if st, _ := c.get("/api/v1/panels"); st != 200 {
		t.Fatal("GET must not require CSRF")
	}
	// Login itself checks the origin.
	st, b := h.anon().do("POST", "/api/v1/auth/login", map[string]string{"username": "alice", "password": testPassword},
		func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") })
	if st != 403 {
		t.Fatalf("cross-origin login: %d %s", st, b)
	}
}

func TestIdleAndDisabledSessions(t *testing.T) {
	h := newHarness(t)
	a := h.account("alice", true)
	c := h.login("alice")
	h.advance(3 * time.Hour) // idle limit is 2h
	if st, b := c.get("/api/v1/panels"); st != 401 || errCode(b) != "session_expired" {
		t.Fatalf("idle session: %d %s", st, b)
	}

	h2 := newHarness(t)
	a2 := h2.account("bob", true)
	c2 := h2.login("bob")
	_ = h2.st.SetAccountDisabled(ctx, a2.ID, true)
	if st, _ := c2.get("/api/v1/panels"); st != 401 {
		t.Fatal("disabling an account must end its session at once")
	}
	_ = a
}

func TestChangeOwnPasswordEndsAllSessions(t *testing.T) {
	h := newHarness(t)
	h.account("alice", false)
	c1, c2 := h.login("alice"), h.login("alice")
	if st, _ := c1.do("POST", "/api/v1/auth/password", map[string]string{"current_password": "wrong", "new_password": "another long passphrase"}); st != 403 {
		t.Fatalf("wrong current password: %d", st)
	}
	if st, _ := c1.do("POST", "/api/v1/auth/password", map[string]string{"current_password": testPassword, "new_password": "short"}); st != 422 {
		t.Fatalf("weak new password: %d", st)
	}
	if st, _ := c1.do("POST", "/api/v1/auth/password", map[string]string{"current_password": testPassword, "new_password": "another long passphrase"}); st != 204 {
		t.Fatalf("change: %d", st)
	}
	for i, c := range []*client{c1, c2} {
		if st, _ := c.get("/api/v1/auth/me"); st != 401 {
			t.Fatalf("session %d survived a password change", i)
		}
	}
}

// --- RBAC: the Work-only viewer ----------------------------------------------------

type world struct {
	h               *harness
	owner           *client
	home, work      panelDTO
	viewer, op, adm *client
}

func newWorld(t *testing.T) *world {
	h := newHarness(t)
	h.account("owner", true)
	owner := h.login("owner")
	w := &world{h: h, owner: owner}
	w.home = h.createPanel(owner, "Home", "home.example.com", tokGood)
	w.work = h.createPanel(owner, "Work", "work.example.com", tokGood2)
	h.account("viewer", false, store.Membership{PanelID: w.work.ID, Role: "viewer"})
	h.account("operator", false, store.Membership{PanelID: w.work.ID, Role: "operator"})
	h.account("padmin", false, store.Membership{PanelID: w.work.ID, Role: "admin"})
	w.viewer, w.op, w.adm = h.login("viewer"), h.login("operator"), h.login("padmin")
	return w
}

func TestWorkOnlyViewerCannotSeeHomeAnywhere(t *testing.T) {
	w := newWorld(t)
	v := w.viewer

	st, body := v.get("/api/v1/panels")
	if st != 200 {
		t.Fatal(st)
	}
	list := parse[struct {
		Panels    []panelDTO `json:"panels"`
		CanCreate bool       `json:"can_create"`
	}](t, body)
	if len(list.Panels) != 1 || list.Panels[0].ID != w.work.ID || list.CanCreate {
		t.Fatalf("viewer sees %+v", list)
	}
	if strings.Contains(string(body), w.home.ID) || strings.Contains(string(body), "home.example.com") {
		t.Fatal("Home leaked into the panel list")
	}

	homeID := w.home.ID
	random := "ffffffff-ffff-4fff-8fff-ffffffffffff"
	for _, path := range []string{"", "/nodes", "/users", "/sync-runs"} {
		a, ab := v.get("/api/v1/panels/" + homeID + path)
		b, bb := v.get("/api/v1/panels/" + random + path)
		if a != 404 || b != 404 || errCode(ab) != errCode(bb) {
			t.Fatalf("%q: Home=%d random=%d (must be indistinguishable 404s)", path, a, b)
		}
	}

	// Scope selector, overview, aggregates.
	_, sb := v.get("/api/v1/scope")
	sc := parse[struct {
		Panels []scopePanel `json:"panels"`
	}](t, sb)
	for _, p := range sc.Panels {
		if p.ID == w.home.ID || p.Name == "Home" {
			t.Fatal("Home is in the viewer's filter scope")
		}
	}
	a, ab := v.get("/api/v1/overview?range=24h&panel_ids=" + homeID)
	b, bb := v.get("/api/v1/overview?range=24h&panel_ids=" + random)
	if a != 403 || b != 403 || errCode(ab) != "panel_forbidden" || errCode(bb) != "panel_forbidden" {
		t.Fatalf("overview probing: %d/%d %s %s", a, b, ab, bb)
	}
	if st, ob := v.get("/api/v1/overview?range=24h"); st != 200 || strings.Contains(string(ob), homeID) {
		t.Fatalf("default overview must be limited to the viewer's panels: %d", st)
	}
	// The viewer cannot name Home through a node filter either.
	if st, _ := v.get("/api/v1/overview?range=24h&panel_ids=" + w.work.ID + "&node_ids=" + demo.Panels[0].Nodes[0].ID); st == 200 {
		t.Fatal("a node id from another panel must be refused")
	}

	// Audit and accounts.
	if st, b := v.get("/api/v1/audit?panel_id=" + homeID); st != 404 {
		t.Fatalf("audit of Home: %d %s", st, b)
	}
	if st, b := v.get("/api/v1/audit"); st != 200 || strings.Contains(string(b), homeID) {
		t.Fatalf("audit: %d", st)
	}
	if st, _ := v.get("/api/v1/accounts"); st != 403 {
		t.Fatal("viewer listing accounts")
	}
}

func TestRoleLadderOnTheAssignedPanel(t *testing.T) {
	w := newWorld(t)
	work := "/api/v1/panels/" + w.work.ID
	check := func(who string, c *client, method, path string, body any, want int) {
		t.Helper()
		if st, b := c.do(method, path, body); st != want {
			t.Errorf("%s %s %s: got %d want %d (%s)", who, method, path, st, want, b)
		}
	}
	rename := map[string]any{"name": "Work2"}
	tok := map[string]any{"api_token": tokGood2}

	// viewer: read only
	check("viewer", w.viewer, "GET", work, nil, 200)
	check("viewer", w.viewer, "GET", work+"/nodes", nil, 200)
	check("viewer", w.viewer, "GET", work+"/sync-runs", nil, 403)
	check("viewer", w.viewer, "POST", work+"/test", nil, 403)
	check("viewer", w.viewer, "POST", work+"/sync", nil, 403)
	check("viewer", w.viewer, "PATCH", work, rename, 403)
	check("viewer", w.viewer, "PUT", work+"/token", tok, 403)
	check("viewer", w.viewer, "POST", work+"/disable", nil, 403)
	check("viewer", w.viewer, "DELETE", work, map[string]any{"confirm": "Work", "retention": "purge"}, 403)

	// operator: test, sync, run history
	check("operator", w.op, "GET", work+"/sync-runs", nil, 200)
	check("operator", w.op, "POST", work+"/test", nil, 200)
	check("operator", w.op, "POST", work+"/sync", nil, 202)
	check("operator", w.op, "PATCH", work, rename, 403)
	check("operator", w.op, "PUT", work+"/token", tok, 403)
	check("operator", w.op, "POST", work+"/disable", nil, 403)

	// panel admin: manage this panel, but not create or delete panels, nor manage accounts
	check("admin", w.adm, "PATCH", work, rename, 200)
	check("admin", w.adm, "PUT", work+"/token", tok, 200)
	check("admin", w.adm, "POST", work+"/disable", nil, 200)
	check("admin", w.adm, "POST", work+"/enable", nil, 200)
	check("admin", w.adm, "DELETE", work, map[string]any{"confirm": "Work2", "retention": "purge"}, 403)
	check("admin", w.adm, "POST", "/api/v1/panels", map[string]any{"name": "N", "base_url": "https://n.example.com", "api_token": tokGood}, 403)
	check("admin", w.adm, "POST", "/api/v1/panels/probe", map[string]any{"base_url": "https://n.example.com", "api_token": tokGood}, 403)
	check("admin", w.adm, "GET", "/api/v1/accounts", nil, 403)
	check("admin", w.adm, "POST", "/api/v1/accounts", map[string]any{"username": "mallory", "password": testPassword, "is_owner": true}, 403)
	// ...and Home stays out of reach for all of them.
	home := "/api/v1/panels/" + w.home.ID
	check("admin", w.adm, "PATCH", home, rename, 404)
	check("admin", w.adm, "PUT", home+"/token", tok, 404)
	check("operator", w.op, "POST", home+"/sync", nil, 404)
}

// --- secrets never leave ------------------------------------------------------------

func TestTokenNeverAppearsAnywhere(t *testing.T) {
	h := newHarness(t)
	h.account("owner", true)
	c := h.login("owner")
	secret := tokGood
	secret2 := tokGood2

	var seen [][]byte
	record := func(st int, b []byte) { seen = append(seen, b); _ = st }

	st, b := c.do("POST", "/api/v1/panels/probe", map[string]any{"base_url": "https://leak.example.com", "api_token": secret})
	record(st, b)
	st, b = c.do("POST", "/api/v1/panels", map[string]any{"name": "Leak", "base_url": "https://leak.example.com", "api_token": secret})
	record(st, b)
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	p := parse[struct {
		Panel panelDTO `json:"panel"`
	}](t, b).Panel
	if p.Token != "configured" {
		t.Fatalf("token field must only say configured: %q", p.Token)
	}
	base := "/api/v1/panels/" + p.ID
	for _, call := range [][3]string{{"GET", "/api/v1/panels", ""}, {"GET", base, ""}, {"POST", base + "/test", ""}, {"GET", base + "/nodes", ""},
		{"GET", base + "/users", ""}, {"GET", base + "/sync-runs", ""}, {"GET", "/api/v1/audit", ""}, {"GET", "/api/v1/scope", ""}, {"GET", "/api/v1/auth/me", ""}} {
		st, b := c.do(call[0], call[1], nil)
		record(st, b)
	}
	st, b = c.do("PATCH", base, map[string]any{"name": "Leak2"})
	record(st, b)
	st, b = c.do("PUT", base+"/token", map[string]any{"api_token": secret2})
	record(st, b)
	st, b = c.do("PUT", base+"/token", map[string]any{"api_token": tokBad}) // rejected rotation
	record(st, b)
	st, b = c.do("POST", base+"/sync", nil)
	record(st, b)
	time.Sleep(400 * time.Millisecond)
	st, b = c.get(base + "/sync-runs")
	record(st, b)

	for i, body := range seen {
		for _, s := range []string{secret, secret2, tokBad} {
			if bytes.Contains(body, []byte(s)) {
				t.Errorf("response %d contains a token: %s", i, body)
			}
		}
	}
	if strings.Contains(h.logs.String(), "tok-SECRET") {
		t.Fatalf("a token reached the logs:\n%s", h.logs.String())
	}

	var dump string
	rows, _ := h.st.Pool().Query(ctx, `SELECT row_to_json(t)::text FROM audit_log t`)
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		dump += s
	}
	rows.Close()
	if dump == "" || strings.Contains(dump, "tok-SECRET") {
		t.Fatalf("audit log must exist and hold no token: %.300s", dump)
	}
	var n int
	_ = h.st.Pool().QueryRow(ctx, `SELECT count(*) FROM panels WHERE to_jsonb(panels)::text LIKE '%tok-SECRET%'`).Scan(&n)
	if n != 0 {
		t.Fatal("token in the panels table")
	}
	var plain bool
	_ = h.st.Pool().QueryRow(ctx, `SELECT position('tok-SECRET'::bytea in ciphertext) > 0 FROM panel_credentials WHERE panel_id=$1`, p.ID).Scan(&plain)
	if plain {
		t.Fatal("plaintext token in the credential column")
	}
}

func TestPanelAPIHasNoTokenField(t *testing.T) {
	// Guard against someone adding one later: the DTO's JSON keys are pinned.
	b, _ := json.Marshal(panelDTO{})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for k := range m {
		if strings.Contains(strings.ToLower(k), "secret") || strings.Contains(strings.ToLower(k), "password") || k == "api_token" || k == "ciphertext" {
			t.Fatalf("panel DTO exposes %q", k)
		}
	}
}

// --- the connection wizard ----------------------------------------------------------

func TestProbeIsStatelessAndSSRFSafe(t *testing.T) {
	h := newHarness(t)
	h.account("owner", true)
	c := h.login("owner")
	count := func() int {
		var n int
		_ = h.st.Pool().QueryRow(ctx, `SELECT count(*) FROM panels WHERE NOT demo`).Scan(&n)
		return n
	}

	st, b := c.do("POST", "/api/v1/panels/probe", map[string]any{"base_url": "https://probe.example.com", "api_token": tokGood})
	sum := parse[probeSummary](t, b)
	if st != 200 || !sum.RequiredOK || sum.NodeCount != 2 || sum.APIVersion != "3.4.5" || len(sum.NodesPreview) != 2 {
		t.Fatalf("%d %+v", st, sum)
	}
	if count() != 0 {
		t.Fatal("a probe must not persist anything")
	}

	for _, u := range []string{"http://probe.example.com", "https://127.0.0.1", "https://10.0.0.5", "https://169.254.169.254", "https://[::1]",
		"https://user:pw@probe.example.com", "https://probe.example.com?x=1", "https://probe.example.com:22", "https://localhost", "ftp://x.example.com"} {
		st, b := c.do("POST", "/api/v1/panels/probe", map[string]any{"base_url": u, "api_token": tokGood})
		s := parse[probeSummary](t, b)
		if st != 200 || s.RequiredOK || s.Checks[0].Name != "url" || s.Checks[0].Status != remnawave.CheckFailed {
			t.Errorf("%s: %d %+v", u, st, s.Checks)
		}
		if bytes.Contains(b, []byte(u)) && strings.Contains(u, "pw@") {
			t.Errorf("credentials from the URL echoed back: %s", b)
		}
	}
	if count() != 0 {
		t.Fatal("probing unsafe URLs created panels")
	}
	for _, bad := range []map[string]any{{"base_url": "https://a.example.com", "api_token": ""}, {"base_url": "https://a.example.com", "api_token": "has space"},
		{"base_url": "https://a.example.com", "api_token": strings.Repeat("x", 3000)}} {
		if st, _ := c.do("POST", "/api/v1/panels/probe", bad); st != 422 {
			t.Errorf("bad token shape accepted: %d", st)
		}
	}
	if st, b := c.do("POST", "/api/v1/panels/probe", map[string]any{"base_url": "https://a.example.com", "api_token": tokGood, "use_custom_ca": true}); st != 422 || errCode(b) != "custom_ca_unavailable" {
		t.Fatalf("custom CA without a configured bundle: %d %s", st, b)
	}
}

func TestProbeIsRateLimited(t *testing.T) {
	h := newHarness(t, func(s *Server) { s.Limits.Probe = DefaultLimits().Probe })
	h.account("owner", true)
	c := h.login("owner")
	var codes []int
	for i := 0; i < 8; i++ {
		st, _ := c.do("POST", "/api/v1/panels/probe", map[string]any{"base_url": "https://rl.example.com", "api_token": tokGood})
		codes = append(codes, st)
	}
	if codes[0] != 200 || codes[7] != 429 {
		t.Fatalf("codes %v", codes)
	}
}

func TestCreateRequiresTheRequiredChecks(t *testing.T) {
	h := newHarness(t)
	h.account("owner", true)
	c := h.login("owner")
	for name, tc := range map[string]struct {
		url, token string
		want       string
	}{
		"bad token":    {"https://a.example.com", tokBad, "auth"},
		"unreachable":  {"https://b.example.com", tokDown, "connection"},
		"unsafe url":   {"https://127.0.0.1", tokGood, "url"},
		"private host": {"https://192.168.1.10", tokGood, "url"},
	} {
		st, b := c.do("POST", "/api/v1/panels", map[string]any{"name": name, "base_url": tc.url, "api_token": tc.token})
		e := parse[apiError](t, b)
		if st != 422 || e.Code != "probe_failed" {
			t.Errorf("%s: %d %s", name, st, b)
			continue
		}
		raw, _ := json.Marshal(e.Details)
		var d probeSummary
		_ = json.Unmarshal(raw, &d)
		var failed string
		for _, ch := range d.Checks {
			if ch.Status == remnawave.CheckFailed && failed == "" {
				failed = ch.Name
			}
		}
		if failed != tc.want {
			t.Errorf("%s: first failed check %q, want %q", name, failed, tc.want)
		}
	}
	var n int
	_ = h.st.Pool().QueryRow(ctx, `SELECT count(*) FROM panels WHERE NOT demo`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d panels were saved although a required check failed", n)
	}
}

func TestPartialCapabilitiesNeedExplicitOverride(t *testing.T) {
	h := newHarness(t)
	h.account("owner", true)
	c := h.login("owner")
	body := map[string]any{"name": "Partial", "base_url": "https://partial.example.com", "api_token": tokPartial}

	st, b := c.do("POST", "/api/v1/panels", body)
	e := parse[apiError](t, b)
	if st != 422 || e.Code != "partial_capabilities" || !strings.Contains(string(b), `"users"`) {
		t.Fatalf("%d %s", st, b)
	}
	body["allow_partial"] = true
	st, b = c.do("POST", "/api/v1/panels", body)
	out := parse[struct {
		Panel panelDTO `json:"panel"`
		Gaps  []string `json:"partial_gaps"`
	}](t, b)
	if st != 201 || out.Panel.SyncOptions.Users || !out.Panel.SyncOptions.Nodes || len(out.Gaps) != 1 || out.Gaps[0] != "users" {
		t.Fatalf("%d %+v", st, out)
	}
}

func TestCreateValidation(t *testing.T) {
	h := newHarness(t)
	h.account("owner", true)
	c := h.login("owner")
	h.createPanel(c, "Taken", "taken.example.com", tokGood)
	for name, tc := range map[string]struct {
		body map[string]any
		want int
		code string
	}{
		"empty name":     {map[string]any{"name": "  ", "base_url": "https://v.example.com", "api_token": tokGood}, 422, "invalid_name"},
		"long name":      {map[string]any{"name": strings.Repeat("я", 65), "base_url": "https://v.example.com", "api_token": tokGood}, 422, "invalid_name"},
		"control chars":  {map[string]any{"name": "a\x00b", "base_url": "https://v.example.com", "api_token": tokGood}, 422, "invalid_name"},
		"duplicate name": {map[string]any{"name": "taken", "base_url": "https://v.example.com", "api_token": tokGood}, 409, "name_taken"},
		"tiny interval":  {map[string]any{"name": "Z1", "base_url": "https://v.example.com", "api_token": tokGood, "sync_interval_seconds": 5}, 422, "invalid_settings"},
		"huge retention": {map[string]any{"name": "Z2", "base_url": "https://v.example.com", "api_token": tokGood, "retention_days": 99999}, 422, "invalid_settings"},
		"unknown field":  {map[string]any{"name": "Z3", "base_url": "https://v.example.com", "api_token": tokGood, "is_owner": true}, 400, "invalid_body"},
	} {
		st, b := c.do("POST", "/api/v1/panels", tc.body)
		if st != tc.want || errCode(b) != tc.code {
			t.Errorf("%s: %d %s", name, st, b)
		}
	}
}

func TestRotateTokenKeepsTheOldOneOnFailure(t *testing.T) {
	h := newHarness(t)
	h.account("owner", true)
	c := h.login("owner")
	p := h.createPanel(c, "Rot", "rot.example.com", tokGood)
	before, _ := h.st.Credential(ctx, p.ID)

	st, b := c.do("PUT", "/api/v1/panels/"+p.ID+"/token", map[string]any{"api_token": tokBad})
	if st != 422 || errCode(b) != "probe_failed" {
		t.Fatalf("%d %s", st, b)
	}
	after, _ := h.st.Credential(ctx, p.ID)
	if !bytes.Equal(before.Ciphertext, after.Ciphertext) || !bytes.Equal(before.Nonce, after.Nonce) {
		t.Fatal("a rejected token replaced the working one")
	}

	// Mark the panel as failing, then rotate to a good token: it recovers.
	_ = h.st.RecordSyncOutcome(ctx, p.ID, false, "failed", time.Minute, time.Now(), 0, 1, time.Hour)
	if st, b := c.do("PUT", "/api/v1/panels/"+p.ID+"/token", map[string]any{"api_token": tokGood2}); st != 200 {
		t.Fatalf("%d %s", st, b)
	}
	after, _ = h.st.Credential(ctx, p.ID)
	if bytes.Equal(before.Ciphertext, after.Ciphertext) {
		t.Fatal("token was not replaced")
	}
	pt, err := h.ring.Open(p.ID, after)
	if err != nil || string(pt) != tokGood2 {
		t.Fatalf("stored token wrong: %q %v", pt, err)
	}
	got, _ := h.st.GetPanel(ctx, store.Scope{All: true}, p.ID)
	if got.Status != "active" || got.CircuitOpenUntil != nil {
		t.Fatalf("rotation should clear the failure state: %+v", got)
	}
	if st, b := c.do("PUT", "/api/v1/panels/"+p.ID+"/token", map[string]any{"api_token": "has space"}); st != 422 {
		t.Fatalf("%d %s", st, b)
	}
}

func TestDeleteNeedsConfirmationAndARetentionChoice(t *testing.T) {
	h := newHarness(t)
	h.account("owner", true)
	c := h.login("owner")
	a := h.createPanel(c, "Alpha", "alpha.example.com", tokGood)
	b2 := h.createPanel(c, "Beta", "beta.example.com", tokGood)

	del := func(id string, body any) (int, string) {
		st, b := c.do("DELETE", "/api/v1/panels/"+id, body)
		return st, errCode(b)
	}
	if st, code := del(a.ID, map[string]any{"confirm": "Alpha"}); st != 422 || code != "retention_required" {
		t.Fatalf("no retention choice: %d %s", st, code)
	}
	if st, code := del(a.ID, map[string]any{"confirm": "alpha", "retention": "purge"}); st != 422 || code != "confirmation_mismatch" {
		t.Fatalf("wrong confirmation: %d %s", st, code)
	}
	if st, code := del(a.ID, map[string]any{"confirm": "Alpha", "retention": "shred"}); st != 422 || code != "retention_required" {
		t.Fatalf("bad retention: %d %s", st, code)
	}
	if st, _ := del(a.ID, map[string]any{"confirm": "Alpha", "retention": "purge"}); st != 204 {
		t.Fatalf("purge: %d", st)
	}
	if st, _ := c.get("/api/v1/panels/" + a.ID); st != 404 {
		t.Fatal("purged panel still visible")
	}
	if st, _ := del(b2.ID, map[string]any{"confirm": "Beta", "retention": "archive"}); st != 204 {
		t.Fatalf("archive: %d", st)
	}
	if h.createPanel(c, "Beta", "beta2.example.com", tokGood).ID == b2.ID {
		t.Fatal("an archived panel's name must be reusable")
	}
	demoID := demo.Panels[0].ID
	if st, code := del(demoID, map[string]any{"confirm": demo.Panels[0].Name, "retention": "purge"}); st != 409 || code != "demo_panel" {
		t.Fatalf("demo panel removal: %d %s", st, code)
	}
	var n int
	_ = h.st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='panel.delete'`).Scan(&n)
	if n < 2 {
		t.Fatalf("deletions must be audited, found %d", n)
	}
}

func TestDemoPanelsRefuseConnectionActions(t *testing.T) {
	h := newHarness(t)
	h.account("owner", true)
	c := h.login("owner")
	d := "/api/v1/panels/" + demo.Panels[0].ID
	for _, call := range [][2]string{{"POST", d + "/test"}, {"POST", d + "/sync"}, {"PUT", d + "/token"}, {"POST", d + "/disable"}} {
		var body any
		if call[0] == "PUT" {
			body = map[string]any{"api_token": tokGood}
		}
		if st, b := c.do(call[0], call[1], body); st != 409 || errCode(b) != "demo_panel" {
			t.Errorf("%s %s: %d %s", call[0], call[1], st, b)
		}
	}
}

// --- sync from the API --------------------------------------------------------------

func TestManualSyncRunsAndRefusesOverlap(t *testing.T) {
	w := newWorld(t)
	c := w.owner
	waitFor := func(cond func() bool) {
		t.Helper()
		for i := 0; i < 100; i++ {
			if cond() {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("condition not reached")
	}
	// The harness fakes serve two nodes by default.
	if st, b := c.do("POST", "/api/v1/panels/"+w.home.ID+"/sync", nil); st != 202 {
		t.Fatalf("%d %s", st, b)
	}
	waitFor(func() bool {
		_, b := c.get("/api/v1/panels/" + w.home.ID)
		return parse[panelDTO](t, b).NodeCount == 2
	})
	_, b := c.get("/api/v1/panels/" + w.home.ID + "/sync-runs")
	runs := parse[struct {
		Runs []store.SyncRun `json:"runs"`
	}](t, b).Runs
	if len(runs) == 0 || runs[0].Trigger != "manual" {
		t.Fatalf("%+v", runs)
	}
	// The other panel was not touched.
	_, b = c.get("/api/v1/panels/" + w.work.ID)
	if n := parse[panelDTO](t, b).NodeCount; n != 0 {
		t.Fatalf("syncing Home changed Work: %d nodes", n)
	}

	// Overlap: hold Work's sync open and ask again.
	fp := w.h.remote["work.example.com"]
	fp.block, fp.entered = make(chan struct{}), make(chan struct{})
	if st, _ := c.do("POST", "/api/v1/panels/"+w.work.ID+"/sync", nil); st != 202 {
		t.Fatal("first sync should start")
	}
	select {
	case <-fp.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("sync never started")
	}
	if st, b := c.do("POST", "/api/v1/panels/"+w.work.ID+"/sync", nil); st != 409 || errCode(b) != "sync_in_progress" {
		t.Fatalf("%d %s", st, b)
	}
	close(fp.block)

	// Disabled panels refuse manual syncs.
	_, _ = c.do("POST", "/api/v1/panels/"+w.home.ID+"/disable", nil)
	if st, b := c.do("POST", "/api/v1/panels/"+w.home.ID+"/sync", nil); st != 409 || errCode(b) != "panel_disabled" {
		t.Fatalf("%d %s", st, b)
	}
}

func TestViewerSeesMaskedUsernames(t *testing.T) {
	w := newWorld(t)
	w.h.remote["work.example.com"].users = []remnawave.User{{RemoteUUID: "u-1", Username: "alexandra", Status: "ACTIVE"}}
	_, _ = w.owner.do("POST", "/api/v1/panels/"+w.work.ID+"/sync", nil)
	time.Sleep(600 * time.Millisecond)

	read := func(c *client) string {
		_, b := c.get("/api/v1/panels/" + w.work.ID + "/users")
		us := parse[struct {
			Users []store.User `json:"users"`
		}](t, b).Users
		if len(us) != 1 || us[0].Username == nil {
			t.Fatalf("%s", b)
		}
		return *us[0].Username
	}
	if got := read(w.viewer); got == "alexandra" || !strings.HasPrefix(got, "al") {
		t.Fatalf("viewer must see a masked name, got %q", got)
	}
	if got := read(w.op); got != "alexandra" {
		t.Fatalf("operator sees the real name, got %q", got)
	}
}

// --- accounts --------------------------------------------------------------------------

func TestAccountManagement(t *testing.T) {
	w := newWorld(t)
	o := w.owner

	cases := []struct {
		name string
		body map[string]any
		want int
		code string
	}{
		{"weak password", map[string]any{"username": "carol", "password": "short"}, 422, "weak_password"},
		{"password contains username", map[string]any{"username": "carol", "password": "carol-carol-carol-1"}, 422, "weak_password"},
		{"bad username", map[string]any{"username": "a b", "password": testPassword}, 422, "invalid_username"},
		{"duplicate (case-insensitive)", map[string]any{"username": "VIEWER", "password": testPassword}, 409, "username_taken"},
		{"unknown role", map[string]any{"username": "dave", "password": testPassword, "memberships": []map[string]string{{"panel_id": w.work.ID, "role": "boss"}}}, 422, "invalid_memberships"},
		{"unknown panel", map[string]any{"username": "dave", "password": testPassword, "memberships": []map[string]string{{"panel_id": "ffffffff-ffff-4fff-8fff-ffffffffffff", "role": "viewer"}}}, 422, "invalid_memberships"},
		{"ok", map[string]any{"username": "carol", "password": testPassword, "memberships": []map[string]string{{"panel_id": w.home.ID, "role": "viewer"}}}, 201, ""},
	}
	for _, tc := range cases {
		st, b := o.do("POST", "/api/v1/accounts", tc.body)
		if st != tc.want || (tc.code != "" && errCode(b) != tc.code) {
			t.Errorf("%s: %d %s", tc.name, st, b)
		}
		if bytes.Contains(b, []byte(testPassword)) {
			t.Errorf("%s: the password was echoed", tc.name)
		}
	}
	carol := h2(t, w, "carol")
	if st, _ := carol.get("/api/v1/panels/" + w.home.ID); st != 200 {
		t.Fatal("carol should see Home")
	}
	if st, _ := carol.get("/api/v1/panels/" + w.work.ID); st != 404 {
		t.Fatal("carol must not see Work")
	}

	// Change carol's panels: Home -> Work.
	_, lb := o.get("/api/v1/accounts")
	var carolID string
	for _, a := range parse[struct {
		Accounts []accountFullDTO `json:"accounts"`
	}](t, lb).Accounts {
		if a.Username == "carol" {
			carolID = a.ID
		}
	}
	if st, b := o.do("PUT", "/api/v1/accounts/"+carolID+"/memberships", map[string]any{"memberships": []map[string]string{{"panel_id": w.work.ID, "role": "operator"}}}); st != 204 {
		t.Fatalf("%d %s", st, b)
	}
	if st, _ := carol.get("/api/v1/panels/" + w.home.ID); st != 404 {
		t.Fatal("membership change must take effect immediately")
	}
	if st, _ := carol.get("/api/v1/panels/" + w.work.ID); st != 200 {
		t.Fatal("carol should now see Work")
	}

	// Disable and reset password end sessions; you cannot disable yourself.
	if st, b := o.do("PATCH", "/api/v1/accounts/"+w.owner.me.Account.ID, map[string]any{"disabled": true}); st != 422 || errCode(b) != "cannot_disable_self" {
		t.Fatalf("%d %s", st, b)
	}
	if st, _ := o.do("PATCH", "/api/v1/accounts/"+carolID, map[string]any{"password": "a brand new long passphrase"}); st != 204 {
		t.Fatal("password reset failed")
	}
	if st, _ := carol.get("/api/v1/auth/me"); st != 401 {
		t.Fatal("a password reset must sign the account out")
	}
	carol2 := w.h.anon()
	if st, _ := carol2.do("POST", "/api/v1/auth/login", map[string]string{"username": "carol", "password": "a brand new long passphrase"}); st != 200 {
		t.Fatal("new password should work")
	}
	if st, _ := o.do("PATCH", "/api/v1/accounts/"+carolID, map[string]any{"disabled": true}); st != 204 {
		t.Fatal("disable failed")
	}
	if st, _ := w.h.anon().do("POST", "/api/v1/auth/login", map[string]string{"username": "carol", "password": "a brand new long passphrase"}); st != 401 {
		t.Fatal("disabled account logged in")
	}
	if st, _ := o.do("PATCH", "/api/v1/accounts/"+carolID, map[string]any{}); st != 422 {
		t.Fatal("empty patch")
	}
	if st, _ := o.do("PATCH", "/api/v1/accounts/not-a-uuid", map[string]any{"disabled": false}); st != 404 {
		t.Fatal("bad id")
	}

	var dump string
	rows, _ := w.h.st.Pool().Query(ctx, `SELECT row_to_json(t)::text FROM audit_log t WHERE action LIKE 'account.%'`)
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		dump += s
	}
	rows.Close()
	if !strings.Contains(dump, "account.create") || !strings.Contains(dump, "account.password_reset") || strings.Contains(dump, "passphrase") || strings.Contains(dump, testPassword) {
		t.Fatalf("account audit wrong or leaking: %.400s", dump)
	}
}

func h2(t *testing.T, w *world, name string) *client {
	t.Helper()
	return w.h.login(name)
}

// --- overview -----------------------------------------------------------------------

func TestOverviewHonestyAndScope(t *testing.T) {
	w := newWorld(t)
	homeDemo, workDemo := demo.Panels[0].ID, demo.Panels[1].ID
	_, _ = w.owner.do("PUT", "/api/v1/accounts/"+w.viewer.me.Account.ID+"/memberships", nil) // owner endpoint exists; viewer unaffected below

	// Owner, demo panel only: synthetic data, labelled demo.
	st, b := w.owner.get("/api/v1/overview?range=24h&panel_ids=" + homeDemo)
	ov := parse[demo.Overview](t, b)
	if st != 200 || !ov.Meta.Demo || ov.Meta.State != "ok" || ov.Connections.Total == 0 {
		t.Fatalf("%d %+v", st, ov.Meta)
	}
	// A real panel has no events yet and says so; it never gets invented numbers.
	st, b = w.owner.get("/api/v1/overview?range=24h&panel_ids=" + w.home.ID)
	ov = parse[demo.Overview](t, b)
	if st != 200 || ov.Meta.Demo || ov.Meta.State != "no_data" || ov.Meta.Reason != "agents_not_connected" || ov.Connections.Total != 0 || len(ov.Timeline) != 0 {
		t.Fatalf("%d %+v", st, ov.Meta)
	}
	// Mixing real and demo panels must not blend fixtures into real scope.
	st, b = w.owner.get("/api/v1/overview?range=24h&panel_ids=" + w.home.ID + "," + homeDemo)
	ov = parse[demo.Overview](t, b)
	if st != 200 || ov.Meta.Demo || ov.Connections.Total != 0 {
		t.Fatalf("mixed scope leaked demo numbers: %+v", ov.Meta)
	}
	// Scoped viewer on a demo panel: only the assigned demo panel.
	w.h.account("demoviewer", false, store.Membership{PanelID: workDemo, Role: "viewer"})
	dv := w.h.login("demoviewer")
	if st, _ := dv.get("/api/v1/overview?range=24h&panel_ids=" + workDemo); st != 200 {
		t.Fatal("assigned demo panel")
	}
	if st, b := dv.get("/api/v1/overview?range=24h&panel_ids=" + homeDemo); st != 403 || errCode(b) != "panel_forbidden" {
		t.Fatalf("%d %s", st, b)
	}
	st, b = dv.get("/api/v1/overview?range=24h")
	ov = parse[demo.Overview](t, b)
	if st != 200 || len(ov.Meta.PanelIDs) != 1 || ov.Meta.PanelIDs[0] != workDemo {
		t.Fatalf("default scope: %+v", ov.Meta.PanelIDs)
	}
	for _, u := range ov.Users {
		if u.PanelID != workDemo {
			t.Fatal("users from another panel in the aggregate")
		}
	}
	// Bad input.
	for url, want := range map[string]int{"/api/v1/overview": 400, "/api/v1/overview?range=2y": 400, "/api/v1/overview?from=x&to=y": 400} {
		if st, _ := w.owner.get(url); st != want {
			t.Errorf("%s: %d", url, st)
		}
	}
	if st, b := w.owner.get("/api/v1/overview?range=1h&panel_ids=" + homeDemo + "&demo_state=error"); st != 503 || errCode(b) != "api_unavailable" {
		t.Fatalf("%d %s", st, b)
	}
	// demo_state must not let anyone fake outages for real panels.
	if st, _ := w.owner.get("/api/v1/overview?range=1h&panel_ids=" + w.home.ID + "&demo_state=error"); st != 200 {
		t.Fatal("demo_state applied to a real panel")
	}
}

// --- request hardening --------------------------------------------------------------

func TestRequestHardening(t *testing.T) {
	h := newHarness(t)
	h.account("owner", true)
	c := h.login("owner")

	huge := `{"name":"` + strings.Repeat("a", 70000) + `"}`
	if st, b := c.do("POST", "/api/v1/panels", huge); st != 413 || errCode(b) != "body_too_large" {
		t.Fatalf("%d %s", st, b)
	}
	if st, b := c.do("POST", "/api/v1/panels", `{"name":"x"} {"name":"y"}`); st != 400 {
		t.Fatalf("two JSON values: %d %s", st, b)
	}
	if st, b := c.do("POST", "/api/v1/panels", `not json`); st != 400 || errCode(b) != "invalid_body" {
		t.Fatalf("%d %s", st, b)
	}
	if st, b := c.do("POST", "/api/v1/panels", `{"name":"x"}`, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }); st != 415 {
		t.Fatalf("%d %s", st, b)
	}
}

func TestEveryResponseCarriesSecurityHeadersAndRequestID(t *testing.T) {
	h := newHarness(t)
	h.account("owner", true)
	c := h.login("owner")
	for _, path := range []string{"/healthz", "/api/v1/panels", "/api/v1/nope", "/api/v1/panels/not-a-uuid"} {
		req, _ := http.NewRequest("GET", h.ts.URL+path, nil)
		resp := c.rawDo(req)
		resp.Body.Close()
		for _, hd := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Cache-Control", "X-Request-Id"} {
			if resp.Header.Get(hd) == "" {
				t.Errorf("%s missing %s", path, hd)
			}
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s must not be cacheable", path)
		}
	}
	_, b := h.anon().get("/api/v1/panels")
	if e := parse[apiError](t, b); e.RequestID == "" || e.Code != "unauthenticated" {
		t.Fatalf("%+v", e)
	}
}

func TestHealthAndReadiness(t *testing.T) {
	h := newHarness(t)
	if st, _ := h.anon().get("/healthz"); st != 200 {
		t.Fatal("healthz")
	}
	st, b := h.anon().get("/readyz")
	if st != 200 || !strings.Contains(string(b), `"database":"ok"`) {
		t.Fatalf("%d %s", st, b)
	}
}

func TestClientIPOnlyTrustsConfiguredProxies(t *testing.T) {
	h := newHarness(t)
	s := h.srv
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("X-Real-IP", "198.51.100.1")
	if got := s.clientIP(req).String(); got != "203.0.113.9" {
		t.Fatalf("an untrusted peer must not set its own IP: %s", got)
	}
	s.Trusted = append(s.Trusted, mustPrefix("203.0.113.0/24"))
	if got := s.clientIP(req).String(); got != "198.51.100.1" {
		t.Fatalf("a trusted proxy's X-Real-IP should be used: %s", got)
	}
	req.Header.Set("X-Real-IP", "not-an-ip")
	if got := s.clientIP(req).String(); got != "203.0.113.9" {
		t.Fatalf("garbage header: %s", got)
	}
}
