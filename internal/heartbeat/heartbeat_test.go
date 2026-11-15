package heartbeat

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTheAddressMustBePlainHTTPS(t *testing.T) {
	for _, bad := range []string{"", "http://hc-ping.com/x", "https://user:pw@hc-ping.com/x", "https:///x", "ftp://x/y", "nonsense"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	if u, err := Parse(" https://hc-ping.com/abc "); err != nil || u != "https://hc-ping.com/abc" {
		t.Fatalf("%q %v", u, err)
	}
}

func TestItAsksOnlyWhileThePanelIsWell(t *testing.T) {
	hits := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Method != http.MethodGet || r.ContentLength > 0 {
			t.Errorf("nothing but the ask: %s %d", r.Method, r.ContentLength)
		}
	}))
	defer srv.Close()
	well := true
	b := &Beater{URL: srv.URL, Client: srv.Client(), Alive: func(context.Context) error {
		if well {
			return nil
		}
		return errors.New("database is down")
	}}
	b.once(context.Background())
	b.once(context.Background())
	if hits != 2 {
		t.Fatalf("while well: %d", hits)
	}
	well = false
	b.once(context.Background())
	if hits != 2 {
		t.Fatalf("a panel that is not well must stay silent: %d", hits)
	}
}
