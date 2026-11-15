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
	access   map[string]string // MAC -> permit or deny
	reserved map[string]string // MAC -> address kept
	reboots  int
	statics  []map[string]any
	saves    int
	deny     bool
	bodies   []string
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
			if sys, ok := body["system"].(map[string]any); ok && sys["reboot"] != nil {
				wr.reboots++
				_, _ = w.Write([]byte(`{"status":[{"status":"message","message":"rebooting"}]}`))
				return
			}
			if hs, ok := body["ip"].(map[string]any)["hotspot"].(map[string]any); ok {
				host := hs["host"].(map[string]any)
				if host["deny"] == true {
					wr.access[host["mac"].(string)] = "deny"
				} else {
					wr.access[host["mac"].(string)] = "permit"
				}
				_, _ = w.Write([]byte(`{}`))
				return
			}
			if dh, ok := body["ip"].(map[string]any)["dhcp"].(map[string]any); ok {
				host := dh["host"].(map[string]any)
				if host["no"] == true {
					delete(wr.reserved, host["mac"].(string))
				} else {
					wr.reserved[host["mac"].(string)] = host["ip"].(string)
				}
				_, _ = w.Write([]byte(`{}`))
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
			} else if rule["index"] != nil {
				for i, e := range wr.statics {
					if e["index"] == rule["index"] {
						if m, isMap := rule["disable"].(map[string]any); isMap && m["no"] == true {
							delete(rule, "disable")
						}
						wr.statics[i] = rule
					}
				}
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
		case "/rci/show/sc/ip/hotspot/host":
			var out []map[string]any
			for m, a := range wr.access {
				out = append(out, map[string]any{"mac": m, "access": a})
			}
			_ = json.NewEncoder(w).Encode(out)
		case "/rci/show/sc/ip/dhcp/host":
			var out []map[string]any
			for m, ip := range wr.reserved {
				out = append(out, map[string]any{"mac": m, "ip": ip})
			}
			_ = json.NewEncoder(w).Encode(out)
		case "/rci/show/ip/route":
			_, _ = w.Write([]byte(`[{"destination":"10.0.0.0/8","interface":"Bridge0"},{"destination":"0.0.0.0/0","interface":"PPPoE0"}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestAForwardIsAddedSavedAndTakenAwayAgain(t *testing.T) {
	wr := &writableRouter{access: map[string]string{}, reserved: map[string]string{}, statics: []map[string]any{{"interface": "PPPoE0", "protocol": "tcp", "port": "8001", "to-host": "aa:bb:cc:dd:ee:09", "index": "old1", "comment": "NVR", "disable": true}}}
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
	wr := &writableRouter{access: map[string]string{}, reserved: map[string]string{}}
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

func TestADeviceIsBlockedAFormerForwardSwitchedOffAnAddressKeptAndTheRouterRestarted(t *testing.T) {
	wr := &writableRouter{access: map[string]string{}, reserved: map[string]string{}, statics: []map[string]any{{"interface": "PPPoE0", "protocol": "tcp", "port": "8001", "to-host": "aa:bb:cc:dd:ee:09", "index": "ab1", "comment": "NVR"}}}
	srv := wr.serve(t, true)
	defer srv.Close()
	c, _ := New(srv.URL, "Test", "pw")
	c.HTTP = srv.Client()
	ctx := context.Background()

	if err := c.SetBlocked(ctx, "AA:BB:CC:DD:EE:01", true); err != nil {
		t.Fatal(err)
	}
	if wr.access["aa:bb:cc:dd:ee:01"] != "deny" {
		t.Fatalf("blocked: %v", wr.access)
	}
	if err := c.SetBlocked(ctx, "AA:BB:CC:DD:EE:01", false); err != nil || wr.access["aa:bb:cc:dd:ee:01"] != "permit" {
		t.Fatalf("let back: %v %v", err, wr.access)
	}
	if err := c.SetBlocked(ctx, "AA:BB:CC:DD:EE:77", true); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("a device the router does not know: %v", err)
	}
	if err := c.SetBlocked(ctx, "nonsense", true); err == nil {
		t.Fatal("not an address")
	}

	if err := c.SetForwardOff(ctx, "ab1", true); err != nil || wr.statics[0]["disable"] != true || len(wr.statics) != 1 {
		t.Fatalf("switched off: %v %v", err, wr.statics)
	}
	if err := c.SetForwardOff(ctx, "ab1", false); err != nil || wr.statics[0]["disable"] != nil || wr.statics[0]["comment"] != "NVR" {
		t.Fatalf("switched on again, nothing else changed: %v %v", err, wr.statics)
	}
	if err := c.SetForwardOff(ctx, "nope", true); !errors.Is(err, ErrMissing) {
		t.Fatalf("%v", err)
	}

	if err := c.SetReserved(ctx, "AA:BB:CC:DD:EE:01", true); err != nil || wr.reserved["aa:bb:cc:dd:ee:01"] != "192.168.1.5" {
		t.Fatalf("kept: %v %v", err, wr.reserved)
	}
	wr.reserved["aa:bb:cc:dd:ee:02"] = "192.168.1.5"
	delete(wr.reserved, "aa:bb:cc:dd:ee:01")
	if err := c.SetReserved(ctx, "AA:BB:CC:DD:EE:01", true); !errors.Is(err, ErrPortTaken) {
		t.Fatalf("an address kept for another device: %v", err)
	}
	delete(wr.reserved, "aa:bb:cc:dd:ee:02")
	_ = c.SetReserved(ctx, "AA:BB:CC:DD:EE:01", true)
	if err := c.SetReserved(ctx, "AA:BB:CC:DD:EE:01", false); err != nil || len(wr.reserved) != 0 {
		t.Fatalf("let go: %v %v", err, wr.reserved)
	}

	if err := c.Reboot(ctx); err != nil || wr.reboots != 1 {
		t.Fatalf("restart: %v %d", err, wr.reboots)
	}
}
