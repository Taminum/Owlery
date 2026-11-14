package keenetic

import (
	"context"
	"crypto/md5" //nolint:gosec // the router's own login scheme
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// writableRouter is a router that keeps a list of static forwards and takes the two changes Owlery makes.
type writableRouter struct {
	statics []map[string]any
	saves   int
	deny    bool
	bodies  []string
}

func (wr *writableRouter) serve(t *testing.T, mayWrite bool) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth" {
			if r.Method == http.MethodGet {
				w.Header().Set("X-NDM-Challenge", "ch")
				w.Header().Set("X-NDM-Realm", "rl")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var in struct{ Login, Password string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			m := md5.Sum([]byte("Test:rl:pw")) //nolint:gosec
			s := sha256.Sum256([]byte("ch" + hex.EncodeToString(m[:])))
			if in.Login != "Test" || in.Password != hex.EncodeToString(s[:]) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "ok", Value: "1", Path: "/", Secure: true})
			return
		}
		if c, err := r.Cookie("ok"); err != nil || c.Value != "1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			raw, _ := json.Marshal(body)
			wr.bodies = append(wr.bodies, string(raw))
			if !mayWrite {
				_, _ = w.Write([]byte(`{"status":[{"status":"error","message":"access denied"}]}`))
				return
			}
			if sys, ok := body["system"].(map[string]any); ok && sys["configuration"] != nil {
				wr.saves++
				_, _ = w.Write([]byte(`{"status":[{"status":"message","message":"saving (http/rci)."}]}`))
				return
			}
			rule, _ := body["ip"].(map[string]any)["static"].(map[string]any)
			if rule["no"] == true {
				kept := wr.statics[:0]
				for _, e := range wr.statics {
					if e["index"] != rule["index"] {
						kept = append(kept, e)
					}
				}
				wr.statics = kept
			} else {
				delete(rule, "disable") // the router lists a rule that is on without the key
				rule["index"] = "new" + rule["port"].(string)
				wr.statics = append(wr.statics, rule)
			}
			_, _ = w.Write([]byte(`{"status":[{"status":"message","message":"ok"}]}`))
			return
		}
		switch r.URL.Path {
		case "/rci/show/sc/ip/static":
			_ = json.NewEncoder(w).Encode(wr.statics)
		case "/rci/show/ip/hotspot":
			_, _ = w.Write([]byte(`{"host":[{"mac":"AA:BB:CC:DD:EE:01","ip":"192.168.1.5","hostname":"pc","active":true}]}`))
		case "/rci/show/ip/route":
			_, _ = w.Write([]byte(`[{"destination":"10.0.0.0/8","interface":"Bridge0"},{"destination":"0.0.0.0/0","interface":"PPPoE0"}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestAForwardIsAddedSavedAndTakenAwayAgain(t *testing.T) {
	wr := &writableRouter{statics: []map[string]any{{"interface": "PPPoE0", "protocol": "tcp", "port": "8001", "to-host": "aa:bb:cc:dd:ee:09", "index": "old1", "comment": "NVR", "disable": true}}}
	srv := wr.serve(t, true)
	defer srv.Close()
	c, _ := New(srv.URL, "Test", "pw")
	c.HTTP = srv.Client()
	ctx := context.Background()

	if err := c.AddForward(ctx, ForwardSpec{Protocol: "tcp", Port: 8080, ToPort: 80, ToIP: "192.168.1.5", Comment: "web"}); err != nil {
		t.Fatal(err)
	}
	if wr.saves != 1 || len(wr.statics) != 2 {
		t.Fatalf("saved %d times, %d forwards", wr.saves, len(wr.statics))
	}
	n := wr.statics[1]
	if n["interface"] != "PPPoE0" || n["protocol"] != "tcp" || n["port"] != "8080" || n["to-port"] != "80" || n["to-host"] != "aa:bb:cc:dd:ee:01" || n["comment"] != "web" {
		t.Fatalf("what the router was given: %v", n)
	}
	if err := c.AddForward(ctx, ForwardSpec{Protocol: "tcp", Port: 8080, ToIP: "192.168.1.5"}); !errors.Is(err, ErrPortTaken) {
		t.Fatalf("the same port again: %v", err)
	}
	if err := c.AddForward(ctx, ForwardSpec{Protocol: "tcp", Port: 9000, ToIP: "192.168.1.77"}); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("a device the router does not know: %v", err)
	}
	if err := c.AddForward(ctx, ForwardSpec{Protocol: "icmp", Port: 9000, ToIP: "192.168.1.5"}); err == nil {
		t.Fatal("a protocol that is not tcp or udp")
	}
	// a switched-off forward on the same port does not block a new one
	if err := c.AddForward(ctx, ForwardSpec{Protocol: "tcp", Port: 8001, ToIP: "192.168.1.5"}); err != nil {
		t.Fatalf("a switched-off forward on the same port: %v", err)
	}
	if err := c.DeleteForward(ctx, "new8080"); err != nil {
		t.Fatal(err)
	}
	if len(wr.statics) != 2 || wr.saves != 3 {
		t.Fatalf("after the removal: %d forwards, saved %d times", len(wr.statics), wr.saves)
	}
	last := wr.bodies[len(wr.bodies)-2]
	if !strings.Contains(last, `"no":true`) || !strings.Contains(last, `"index":"new8080"`) || strings.Contains(last, "disable") {
		t.Fatalf("the removal as sent: %s", last)
	}
	if err := c.DeleteForward(ctx, "nothing"); !errors.Is(err, ErrMissing) {
		t.Fatalf("a forward that is not there: %v", err)
	}
}

func TestAUserWithoutTheRightToChangeIsToldSo(t *testing.T) {
	wr := &writableRouter{}
	srv := wr.serve(t, false)
	defer srv.Close()
	c, _ := New(srv.URL, "Test", "pw")
	c.HTTP = srv.Client()
	err := c.AddForward(context.Background(), ForwardSpec{Protocol: "udp", Port: 5000, ToIP: "192.168.1.5"})
	if !errors.Is(err, ErrForbidden) || Code(err) != "forbidden" {
		t.Fatalf("%v", err)
	}
	if len(wr.statics) != 0 || wr.saves != 0 {
		t.Fatalf("nothing changed: %d forwards, %d saves", len(wr.statics), wr.saves)
	}
}
