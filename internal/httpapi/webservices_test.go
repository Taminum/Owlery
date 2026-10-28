package httpapi

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Taminum/Owlery/internal/store"
)

func TestWebServicesPublishSignInAndProxy(t *testing.T) {
	w := newAgentWorld(t)
	w.h.srv.ServicesDomain = "owlery.test"
	host := func(h string) reqOpt { return func(r *http.Request) { r.Host = h } }

	st, b := w.owner.do("POST", "/api/v1/security/vps", map[string]any{"name": "owlnet"})
	if st != 201 {
		t.Fatalf("create server: %d %s", st, b)
	}
	v := parse[vpsResp](t, b)
	base := "/api/v1/servers/" + v.ID + "/services"

	// Publishing: the address is checked and is unique for good.
	for name, in := range map[string]map[string]any{
		"slug": {"title": "Komodo", "slug": "Komodo Panel", "port": 9120},
		"port": {"title": "Komodo", "slug": "komodo", "port": 70000},
	} {
		if st, _ := w.owner.do("POST", base, in); st != 422 {
			t.Errorf("%s: %d", name, st)
		}
	}
	st, b = w.owner.do("POST", base, map[string]any{"title": "Komodo", "slug": "komodo-owlnet", "port": 9120})
	if st != 201 {
		t.Fatalf("publish: %d %s", st, b)
	}
	svc := parse[store.WebService](t, b)
	if st, _ := w.owner.do("POST", base, map[string]any{"title": "Again", "slug": "komodo-owlnet", "port": 1}); st != 409 {
		t.Errorf("a slug in use: %d", st)
	}
	if st, _ := w.adm.get(base); st != 404 {
		t.Errorf("another admin sees the services: %d", st)
	}

	// Caddy gets a certificate only for a published name.
	if st, _ := w.owner.get("/internal/tls-ask?domain=komodo-owlnet.owlery.test"); st != 200 {
		t.Errorf("tls ask, published: %d", st)
	}
	if st, _ := w.owner.get("/internal/tls-ask?domain=nope.owlery.test"); st != 404 {
		t.Errorf("tls ask, unknown: %d", st)
	}

	// A visit without the service's cookie goes to Owlery to sign in; Owlery sends it back with a ticket.
	resp := w.owner.rawDo(mustReq(t, "GET", w.h.ts.URL+"/dashboard?x=1", "komodo-owlnet.owlery.test"))
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != 302 || !strings.HasPrefix(loc, "https://owlery.test/api/v1/services/komodo-owlnet/enter?next=") {
		t.Fatalf("sign-in redirect: %d %s", resp.StatusCode, loc)
	}
	enter, _ := url.Parse(loc)
	resp = w.owner.rawDo(mustReq(t, "GET", w.h.ts.URL+enter.RequestURI(), ""))
	resp.Body.Close()
	back, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || back.Host != "komodo-owlnet.owlery.test" || back.Path != svcAuthPath || back.Query().Get("next") != "/dashboard?x=1" {
		t.Fatalf("ticket redirect: %d %s", resp.StatusCode, back)
	}
	// Someone without rights to the server gets no ticket.
	resp = w.adm.rawDo(mustReq(t, "GET", w.h.ts.URL+enter.RequestURI(), ""))
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("ticket for an admin of another panel: %d", resp.StatusCode)
	}

	// The ticket becomes the service's own cookie; a ticket for another service is refused.
	resp = w.owner.rawDo(mustReq(t, "GET", w.h.ts.URL+back.RequestURI(), "komodo-owlnet.owlery.test"))
	resp.Body.Close()
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == svcCookie {
			cookie = c
		}
	}
	if resp.StatusCode != 302 || cookie == nil || !cookie.HttpOnly || !cookie.Secure || resp.Header.Get("Location") != "/dashboard?x=1" {
		t.Fatalf("auth: %d %v %s", resp.StatusCode, cookie, resp.Header.Get("Location"))
	}
	resp = w.owner.rawDo(mustReq(t, "GET", w.h.ts.URL+back.RequestURI(), "other.owlery.test"))
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("a ticket used on another service: %d", resp.StatusCode)
	}

	// With the cookie the request goes to the machine; this one has no agent, which the page says plainly.
	req := mustReq(t, "GET", w.h.ts.URL+"/dashboard", "komodo-owlnet.owlery.test")
	req.AddCookie(cookie)
	resp = w.owner.rawDo(req)
	resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Fatalf("no agent: %d", resp.StatusCode)
	}

	// Removed: the address answers nothing and gets no certificate.
	if st, _ := w.owner.do("DELETE", base+"/"+svc.ID, nil); st != 204 {
		t.Fatalf("delete: %d", st)
	}
	if st, _ := w.owner.get("/internal/tls-ask?domain=komodo-owlnet.owlery.test"); st != 404 {
		t.Errorf("tls ask after removal: %d", st)
	}
	_ = host
}

func mustReq(t *testing.T, method, u, host string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		r.Host = host
	}
	return r
}

func TestSafeNextStaysOnTheHost(t *testing.T) {
	for in, want := range map[string]string{"/a?b=1": "/a?b=1", "//evil.example/x": "/", "https://evil.example": "/", "/\\evil": "/", "": "/"} {
		if got := safeNext(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}
