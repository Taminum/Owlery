package safehttp

import (
	"context"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseBaseURL(t *testing.T) {
	pol := &Policy{AllowedPorts: []int{443, 8443}}
	good := map[string]string{
		"https://panel.example.com":          "https://panel.example.com",
		"https://Panel.Example.com/":         "https://panel.example.com",
		"https://panel.example.com:8443":     "https://panel.example.com:8443",
		"https://panel.example.com/secret-1": "https://panel.example.com/secret-1",
		"https://xn--80ak6aa92e.com":         "https://xn--80ak6aa92e.com",
	}
	for in, want := range good {
		u, err := ParseBaseURL(in, pol)
		if err != nil || u.String() != want {
			t.Errorf("%q: got %v %v, want %s", in, u, err, want)
		}
	}
	bad := map[string]string{
		"http://panel.example.com":             CodeInvalidURL,
		"ftp://panel.example.com":              CodeInvalidURL,
		"https://user:pw@panel.example.com":    CodeInvalidURL,
		"https://panel.example.com#frag":       CodeInvalidURL,
		"https://panel.example.com?token=abc":  CodeInvalidURL,
		"https://panel.example.com/a/../b":     CodeInvalidURL,
		"https://panel.example.com//x":         CodeInvalidURL,
		"https://panel.example.com/a b":        CodeInvalidURL,
		"https://localhost":                    CodeInvalidURL,
		"https://panel_underscore.example.com": CodeInvalidURL,
		"https://панель.рф":                    CodeInvalidURL,
		"https://":                             CodeInvalidURL,
		"":                                     CodeInvalidURL,
		"https://panel.example.com:22":         CodeUnsafeTarget,
		"https://panel.example.com:80":         CodeUnsafeTarget,
		"https://panel.example.com:99999":      CodeInvalidURL,
		"https://127.0.0.1":                    CodeUnsafeTarget,
		"https://10.0.0.5":                     CodeUnsafeTarget,
		"https://169.254.169.254":              CodeUnsafeTarget,
		"https://[::1]":                        CodeUnsafeTarget,
		"https://[fd00:ec2::254]":              CodeUnsafeTarget,
		"https://[::ffff:127.0.0.1]":           CodeUnsafeTarget,
		"https://2130706433":                   CodeInvalidURL, // decimal-encoded 127.0.0.1 is not a valid FQDN
		"https://0x7f.0.0.1":                   CodeInvalidURL,
		"https://127.1":                        CodeInvalidURL,
		"https://example.123":                  CodeInvalidURL,
	}
	for in, code := range bad {
		if _, err := ParseBaseURL(in, pol); err == nil || CodeOf(err) != code {
			t.Errorf("%q: want %s, got %v", in, code, err)
		}
	}
}

func TestClassify(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.8.9.10", "0.0.0.0", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"100.64.0.1", "169.254.169.254", "169.254.170.2", "224.0.0.1", "255.255.255.255", "198.18.0.1",
		"::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
		"64:ff9b::7f00:1", "2002:7f00:1::1", "2001:db8::1",
	}
	for _, s := range blocked {
		if classify(netip.MustParseAddr(s), false) == "" {
			t.Errorf("%s must be blocked", s)
		}
	}
	allowed := []string{"93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2a00:1450:4001::200e"}
	for _, s := range allowed {
		if r := classify(netip.MustParseAddr(s), false); r != "" {
			t.Errorf("%s must be allowed, got %q", s, r)
		}
	}
}

func TestAllowListOnlyOpensPrivateSpace(t *testing.T) {
	for _, s := range []string{"10.0.0.5", "172.20.1.1", "192.168.88.2", "100.64.0.9", "fd00::5"} {
		if classify(netip.MustParseAddr(s), true) != "" {
			t.Errorf("%s should be reachable for an approved host", s)
		}
	}
	for _, s := range []string{"127.0.0.1", "::1", "169.254.169.254", "fe80::1", "224.0.0.1", "0.0.0.0", "::ffff:127.0.0.1"} {
		if classify(netip.MustParseAddr(s), true) == "" {
			t.Errorf("%s must stay blocked even for an approved host", s)
		}
	}
}

type fakeResolver struct {
	calls   atomic.Int32
	answers func(call int) ([]netip.Addr, error)
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return f.answers(int(f.calls.Add(1)))
}

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, v := range s {
		out[i] = netip.MustParseAddr(v)
	}
	return out
}

func fixedResolver(s ...string) *fakeResolver {
	return &fakeResolver{answers: func(int) ([]netip.Addr, error) { return addrs(s...), nil }}
}

// harness returns a client whose "network" is the given TLS test server.
func harness(t *testing.T, h http.HandlerFunc, res Resolver, tune func(*Policy)) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	pol := Policy{
		Resolver:   res,
		ExtraCAPEM: caPEM,
		dialFn: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}
	if tune != nil {
		tune(&pol)
	}
	return New(pol, true), srv
}

// httptest certificates are valid for example.com.
const host = "https://example.com"

func TestGetSendsBearerAndReadsBody(t *testing.T) {
	var gotAuth, gotUA string
	c, _ := harness(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotUA = r.Header.Get("Authorization"), r.Header.Get("User-Agent")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}, fixedResolver("93.184.216.34"), nil)

	resp, err := c.Get(context.Background(), host+"/api/nodes", http.Header{"Authorization": {"Bearer secret-token"}})
	if err != nil || resp.Status != 200 || string(resp.Body) != `{"ok":true}` {
		t.Fatalf("got %+v %v", resp, err)
	}
	if gotAuth != "Bearer secret-token" || gotUA == "" {
		t.Fatalf("headers not delivered: %q %q", gotAuth, gotUA)
	}
}

func TestErrorsNeverContainTheToken(t *testing.T) {
	c, _ := harness(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/x", http.StatusFound) }, fixedResolver("93.184.216.34"), nil)
	_, err := c.Get(context.Background(), host, http.Header{"Authorization": {"Bearer super-secret-value"}})
	if err == nil || strings.Contains(err.Error(), "super-secret-value") {
		t.Fatalf("error must exist and not leak the token: %v", err)
	}
}

func TestRedirectsAreNeverFollowed(t *testing.T) {
	var hits atomic.Int32
	c, _ := harness(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "https://169.254.169.254/latest/meta-data", http.StatusFound)
	}, fixedResolver("93.184.216.34"), nil)
	_, err := c.Get(context.Background(), host, nil)
	if CodeOf(err) != CodeRedirect || hits.Load() != 1 {
		t.Fatalf("want redirect_blocked after exactly one request, got %v hits=%d", err, hits.Load())
	}
}

func TestOversizedResponseIsRejected(t *testing.T) {
	c, _ := harness(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 5000)))
	}, fixedResolver("93.184.216.34"), func(p *Policy) { p.MaxBody = 1024 })
	if _, err := c.Get(context.Background(), host, nil); CodeOf(err) != CodeTooLarge {
		t.Fatalf("got %v", err)
	}
}

func TestOversizedChunkedResponseIsRejected(t *testing.T) {
	c, _ := harness(t, func(w http.ResponseWriter, r *http.Request) {
		f := w.(http.Flusher)
		for i := 0; i < 20; i++ {
			_, _ = w.Write([]byte(strings.Repeat("b", 500)))
			f.Flush()
		}
	}, fixedResolver("93.184.216.34"), func(p *Policy) { p.MaxBody = 1024 })
	if _, err := c.Get(context.Background(), host, nil); CodeOf(err) != CodeTooLarge {
		t.Fatalf("a response with no Content-Length must still be capped, got %v", err)
	}
}

func TestSlowServerTimesOut(t *testing.T) {
	c, _ := harness(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(600 * time.Millisecond) },
		fixedResolver("93.184.216.34"), func(p *Policy) { p.Timeout = 150 * time.Millisecond })
	if _, err := c.Get(context.Background(), host, nil); CodeOf(err) != CodeTimeout {
		t.Fatalf("got %v", err)
	}
}

func TestUntrustedCertificateFails(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := New(Policy{
		Resolver: fixedResolver("93.184.216.34"),
		dialFn: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}, false)
	if _, err := c.Get(context.Background(), host, nil); CodeOf(err) != CodeTLS {
		t.Fatalf("a certificate nobody trusts must fail, got %v", err)
	}
}

func TestExtraCAOnlyAppliesWhenRequested(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	pol := Policy{Resolver: fixedResolver("93.184.216.34"), ExtraCAPEM: caPEM,
		dialFn: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Listener.Addr().String())
		}}
	if _, err := New(pol, true).Get(context.Background(), host, nil); err != nil {
		t.Fatalf("with the custom CA enabled: %v", err)
	}
	if _, err := New(pol, false).Get(context.Background(), host, nil); CodeOf(err) != CodeTLS {
		t.Fatalf("a panel without the flag must not trust the custom CA, got %v", err)
	}
}

func TestResolutionToInternalAddressIsBlocked(t *testing.T) {
	for name, answers := range map[string][]string{
		"loopback":        {"127.0.0.1"},
		"rfc1918":         {"10.0.0.5"},
		"metadata":        {"169.254.169.254"},
		"ipv6 loopback":   {"::1"},
		"ula":             {"fd00::5"},
		"v4-mapped":       {"::ffff:127.0.0.1"},
		"mixed (any bad)": {"93.184.216.34", "10.0.0.5"},
		"mixed reversed":  {"192.168.1.1", "93.184.216.34"},
	} {
		c, _ := harness(t, func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("%s: request reached the server", name)
		}, fixedResolver(answers...), nil)
		if _, err := c.Get(context.Background(), host, nil); CodeOf(err) != CodeUnsafeTarget {
			t.Errorf("%s: want unsafe_target, got %v", name, err)
		}
	}
}

func TestDNSRebindingIsRevalidatedOnEveryConnection(t *testing.T) {
	res := &fakeResolver{answers: func(call int) ([]netip.Addr, error) {
		if call == 1 {
			return addrs("93.184.216.34"), nil // looks fine the first time
		}
		return addrs("127.0.0.1"), nil // then flips to loopback
	}}
	c, _ := harness(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }, res, nil)
	c.http.Transport.(*http.Transport).DisableKeepAlives = true // force a new connection per request

	if _, err := c.Get(context.Background(), host, nil); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if _, err := c.Get(context.Background(), host, nil); CodeOf(err) != CodeUnsafeTarget {
		t.Fatalf("after the answer changed, the next connection must be refused, got %v", err)
	}
}

func TestPrivateHostAllowList(t *testing.T) {
	ok := func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }

	c, _ := harness(t, ok, fixedResolver("10.0.0.5"), func(p *Policy) { p.AllowedPrivateHosts = []string{"EXAMPLE.com"} })
	if _, err := c.Get(context.Background(), host, nil); err != nil {
		t.Fatalf("approved host resolving to private space: %v", err)
	}

	c, _ = harness(t, ok, fixedResolver("10.0.0.5"), nil)
	if _, err := c.Get(context.Background(), host, nil); CodeOf(err) != CodeUnsafeTarget {
		t.Fatalf("not approved: %v", err)
	}

	c, _ = harness(t, ok, fixedResolver("127.0.0.1"), func(p *Policy) { p.AllowedPrivateHosts = []string{"example.com"} })
	if _, err := c.Get(context.Background(), host, nil); CodeOf(err) != CodeUnsafeTarget {
		t.Fatalf("loopback stays blocked even when approved: %v", err)
	}
}

func TestDNSFailure(t *testing.T) {
	res := &fakeResolver{answers: func(int) ([]netip.Addr, error) { return nil, errors.New("no such host") }}
	c, _ := harness(t, func(w http.ResponseWriter, r *http.Request) {}, res, nil)
	if _, err := c.Get(context.Background(), host, nil); CodeOf(err) != CodeDNS {
		t.Fatalf("got %v", err)
	}
}

func TestAmbientProxySettingsAreIgnored(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:9")
	c, _ := harness(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("direct")) }, fixedResolver("93.184.216.34"), nil)
	resp, err := c.Get(context.Background(), host, nil)
	if err != nil || string(resp.Body) != "direct" {
		t.Fatalf("proxy env must not be honoured: %v", err)
	}
}

func TestDisallowedPortInURLIsRefusedBeforeAnyNetworkAccess(t *testing.T) {
	res := &fakeResolver{answers: func(int) ([]netip.Addr, error) {
		t.Error("DNS must not be queried for a URL that fails validation")
		return nil, nil
	}}
	c, _ := harness(t, func(w http.ResponseWriter, r *http.Request) {}, res, nil)
	if _, err := c.Get(context.Background(), "https://example.com:6379", nil); CodeOf(err) != CodeUnsafeTarget {
		t.Fatalf("got %v", err)
	}
}

func TestValidateCAPEM(t *testing.T) {
	if ValidateCAPEM([]byte("not a cert")) == nil {
		t.Fatal("garbage must be rejected")
	}
}

func TestRequestURLsMayCarryAQueryButNothingElseRisky(t *testing.T) {
	pol := &Policy{}
	for _, ok := range []string{
		"https://panel.example.com/api/nodes",
		"https://panel.example.com/api/users/?start=0&size=200",
		"https://panel.example.com/api/bandwidth-stats/nodes?start=2026-10-12&end=2026-10-12",
	} {
		if err := ValidateRequestURL(ok, pol); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://panel.example.com/api/nodes?a=1", "https://u:p@panel.example.com/api?a=1", "https://panel.example.com/api?a=1#frag",
		"https://127.0.0.1/api?a=1", "https://panel.example.com:22/api?a=1", "https://panel.example.com/a/../b?x=1",
		"https://panel.example.com/api?" + strings.Repeat("a", 2000),
	} {
		if ValidateRequestURL(bad, pol) == nil {
			t.Errorf("%s must be rejected", bad)
		}
	}
	// The strict base-URL parser still forbids a query: a panel's base URL has none.
	if _, err := ParseBaseURL("https://panel.example.com/?x=1", pol); err == nil {
		t.Fatal("base URLs must not carry a query")
	}
}

func TestGetKeepsTrailingSlashAndQuery(t *testing.T) {
	var got string
	c, _ := harness(t, func(w http.ResponseWriter, r *http.Request) { got = r.URL.RequestURI() }, fixedResolver("93.184.216.34"), nil)
	if _, err := c.Get(context.Background(), host+"/api/users/?start=0&size=200", nil); err != nil {
		t.Fatal(err)
	}
	if got != "/api/users/?start=0&size=200" {
		t.Fatalf("the panel received %q", got)
	}
}
