package main

import (
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func call(t *testing.T, h http.Handler, path, token string) (int, map[string]any) {
	req := httptest.NewRequest("GET", path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	b, _ := io.ReadAll(rec.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return rec.Code, m
}

func TestMockPanelsRequireTheirOwnToken(t *testing.T) {
	home, work := specs("home-token", "work-token")
	h, w := newHandler(home), newHandler(work)
	for _, path := range []string{"/api/nodes", "/api/users/", "/api/system/stats", "/api/system/metadata"} {
		if st, _ := call(t, h, path, ""); st != 401 {
			t.Errorf("%s without a token: %d", path, st)
		}
		if st, _ := call(t, h, path, "work-token"); st != 401 {
			t.Errorf("%s with the other panel's token: %d", path, st)
		}
	}
	if st, _ := call(t, h, "/api/nodes", "home-token"); st != 200 {
		t.Fatal("home token must work on home")
	}
	if st, _ := call(t, w, "/api/nodes", "home-token"); st != 401 {
		t.Fatal("home token must not work on work")
	}
}

func TestMockUserPagination(t *testing.T) {
	home, _ := specs("t", "u")
	h := newHandler(home)
	st, m := call(t, h, "/api/users/?start=0&size=2", "t")
	r := m["response"].(map[string]any)
	if st != 200 || len(r["users"].([]any)) != 2 || r["total"].(float64) != 5 {
		t.Fatalf("%d %v", st, m)
	}
	_, m = call(t, h, "/api/users/?start=4&size=2", "t")
	if got := len(m["response"].(map[string]any)["users"].([]any)); got != 1 {
		t.Fatalf("last page has %d", got)
	}
	_, m = call(t, h, "/api/users/?start=999&size=2", "t")
	if got := len(m["response"].(map[string]any)["users"].([]any)); got != 0 {
		t.Fatalf("past the end has %d", got)
	}
}

func TestWorkPanelIsPartialByDesign(t *testing.T) {
	_, work := specs("t", "u")
	w := newHandler(work)
	if st, _ := call(t, w, "/api/users/", "u"); st != 403 {
		t.Fatal("work must deny users")
	}
	if st, _ := call(t, w, "/api/bandwidth-stats/nodes", "u"); st != 404 {
		t.Fatal("work must lack bandwidth stats")
	}
	if st, _ := call(t, w, "/api/system/stats", "u"); st != 200 {
		t.Fatal("work has system stats")
	}
}

func TestPanelsShareRemoteIdentifiersOnPurpose(t *testing.T) {
	home, work := specs("t", "u")
	if home.Nodes[0]["uuid"] != work.Nodes[0]["uuid"] || home.Users[0]["username"] != work.Users[0]["username"] {
		t.Fatal("the demo panels must overlap so isolation is exercised")
	}
}

func TestCAIsStableAcrossRestartsAndSignsTheLeaf(t *testing.T) {
	dir := t.TempDir()
	first, err := loadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.certPEM) != string(second.certPEM) {
		t.Fatal("a restarted mock must present the same CA, or everything that trusted it breaks")
	}
	leaf, err := second.issue([]string{"a.demo.test", "b.demo.test"})
	if err != nil || len(leaf.Certificate) != 1 {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(leaf.Certificate[0])
	pool := x509.NewCertPool()
	pool.AddCert(first.cert)
	for _, host := range []string{"a.demo.test", "b.demo.test"} {
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: host}); err != nil {
			t.Fatalf("leaf must verify for %s against the stored CA: %v", host, err)
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "other.demo.test"}); err == nil {
		t.Fatal("leaf must not verify for a name it was not issued for")
	}
}
