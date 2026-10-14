package netintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
)

// allowLoopback lets a test reach a server on 127.0.0.1 while everything else stays refused.
func allowLoopback(t *testing.T) {
	t.Helper()
	old, oldPort := publicCheck, httpPortOK
	publicCheck = func(a netip.Addr) error {
		if a.Unmap().IsLoopback() {
			return nil
		}
		return PublicOnly(a)
	}
	httpPortOK = func(string) bool { return true }
	t.Cleanup(func() { publicCheck, httpPortOK = old, oldPort })
}

func portOf(t *testing.T, raw string) int {
	t.Helper()
	u, _ := url.Parse(raw)
	p := 0
	for _, c := range u.Port() {
		p = p*10 + int(c-'0')
	}
	return p
}

func TestTLSDescribesTheChainAndJudgesTrustSeparately(t *testing.T) {
	allowLoopback(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	env := (&Tool{}).TLS(context.Background(), mustTarget(t, "127.0.0.1"), portOf(t, srv.URL))
	res, ok := env.Data.(TLSResult)
	if !ok || !env.Sources[0].OK {
		t.Fatalf("%+v", env)
	}
	if res.Verified || res.VerifyError == "" {
		t.Fatalf("a self-signed certificate was trusted: %+v", res)
	}
	if len(res.Chain) == 0 || res.Chain[0].NotAfter.IsZero() || res.Version == "" || res.Cipher == "" {
		t.Fatalf("%+v", res)
	}
}

func TestTLSRefusesInsideTargetsWithoutConnecting(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254"} {
		if env := (&Tool{}).TLS(context.Background(), mustTarget(t, s), 443); env.Data != nil || env.Sources[0].Error != "not_public" {
			t.Errorf("%s: %+v", s, env)
		}
	}
}

func TestHTTPFollowsRedirectsByHandAndHidesCookies(t *testing.T) {
	allowLoopback(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/a", http.StatusMovedPermanently) })
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/b", http.StatusFound) })
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=1")
		w.Header().Add("Set-Cookie", "session=SECRETVALUE; Path=/")
		w.Header().Set("Server", "test")
		_, _ = w.Write([]byte("hello"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	env := inspectURL(t, srv.URL)
	res := env.Data.(HTTPResult)
	if len(res.Hops) != 3 || res.Hops[0].Status != 301 || res.Hops[1].Status != 302 || res.Final != 200 {
		t.Fatalf("%+v", res)
	}
	if res.Hops[2].Headers["Set-Cookie"] == "" || contains(res.Hops[2].Headers["Set-Cookie"], "SECRETVALUE") {
		t.Fatalf("cookie value leaked or missing: %q", res.Hops[2].Headers["Set-Cookie"])
	}
	if !res.Security["Strict-Transport-Security"] || res.Security["Content-Security-Policy"] {
		t.Fatalf("%+v", res.Security)
	}
}

func contains(s, sub string) bool { return len(sub) > 0 && len(s) >= len(sub) && indexOf(s, sub) >= 0 }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// inspectURL runs the inspector against a full http URL by treating its host:port as the start.
func inspectURL(t *testing.T, raw string) Envelope {
	t.Helper()
	u, _ := url.Parse(raw)
	tool := &Tool{}
	return tool.httpFrom(context.Background(), Target{Kind: KindIP, Value: "127.0.0.1", Display: "127.0.0.1", Addr: netip.MustParseAddr("127.0.0.1")}, "http://"+u.Host+"/")
}

func TestHTTPStopsAtRedirectsToInsideHostsAndLoops(t *testing.T) {
	allowLoopback(t)
	inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://10.0.0.1/admin", http.StatusFound)
	}))
	defer inside.Close()
	env := inspectURL(t, inside.URL)
	res, ok := env.Data.(HTTPResult)
	if !ok || len(res.Hops) != 1 || env.Sources[0].Error != "not_public" {
		t.Fatalf("a redirect to an internal host was followed: %+v %+v", env.Sources, env.Data)
	}
	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/", http.StatusFound) }))
	defer loop.Close()
	res = inspectURL(t, loop.URL).Data.(HTTPResult)
	if len(res.Hops) != maxRedirects+1 {
		t.Fatalf("%d hops in a loop", len(res.Hops))
	}
}

func TestHTTPRefusesInsideTargets(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "192.168.1.1", "169.254.169.254"} {
		if env := (&Tool{}).HTTP(context.Background(), mustTarget(t, s), "http", "/"); env.Data != nil || env.Sources[0].Error != "not_public" {
			t.Errorf("%s: %+v", s, env)
		}
	}
	tool := &Tool{Resolver: &fakeDNS{ips: map[string][]string{"in.example.com": {"10.0.0.1"}}}}
	if env := tool.HTTP(context.Background(), mustTarget(t, "in.example.com"), "https", "/"); env.Data != nil {
		t.Errorf("%+v", env)
	}
}
