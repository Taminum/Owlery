package keenetic

import (
	"context"
	"crypto/md5" //nolint:gosec
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const realm, challenge = "Keenetic Sprinter", "CHALLENGE"

// fakeRouter answers like a Keenetic: a challenge on /auth, the login checked the way the router does, and fixed answers.
func fakeRouter(t *testing.T, login, password string, paths *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth" {
			if r.Method == http.MethodGet {
				w.Header().Set("X-NDM-Challenge", challenge)
				w.Header().Set("X-NDM-Realm", realm)
				w.Header().Set("Set-Cookie", "sid=abc; Path=/; Secure")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var in struct{ Login, Password string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			m := md5.Sum([]byte(login + ":" + realm + ":" + password)) //nolint:gosec
			s := sha256.Sum256([]byte(challenge + hex.EncodeToString(m[:])))
			if in.Login != login || in.Password != hex.EncodeToString(s[:]) {
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
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/rci/show/") {
			t.Errorf("only read-only show paths may be asked, got %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		*paths = append(*paths, r.URL.RequestURI())
		switch r.URL.RequestURI() {
		case "/rci/show/version":
			_, _ = w.Write([]byte(`{"title":"4.3.6.3","model":"Sprinter (KN-3710)"}`))
		case "/rci/show/system":
			_, _ = w.Write([]byte(`{"cpuload":34,"memtotal":262144,"memfree":10000,"membuffers":5000,"memcache":20000,"uptime":"3162337","conntotal":16384,"connfree":15906}`))
		case "/rci/show/ip/hotspot":
			_, _ = w.Write([]byte(`{"host":[
				{"mac":"e8:6a:64:7e:0a:b8","ip":"192.168.0.90","hostname":"Desk","name":"Desk - Home","active":true},
				{"mac":"ac:c5:1b:24:2b:4d","ip":"192.168.0.71","hostname":"","name":"Printer - Home","active":true,"access":"deny"},
				{"mac":"00:25:ab:20:34:7c","ip":"192.168.0.95","hostname":"Gone","active":false},
				{"mac":"zz","ip":"192.168.0.99","hostname":"Broken","active":true}]}`))
		case "/rci/show/sc/ip/static":
			_, _ = w.Write([]byte(`[{"interface":"PPPoE0","protocol":"tcp","port":"8001","to-host":"AA:BB:CC:DD:EE:01","comment":"NVR"},{"interface":"PPPoE0","protocol":"tcp","port":"84","to-host":"AA:BB:CC:DD:EE:01","comment":"off","disable":true},{"interface":"PPPoE0","protocol":"tcpudp","port":"9025","to-port":"3389","to-address":"192.168.1.9","comment":"RDP"}]`))
		case "/rci/show/sc/ip/hotspot/host":
			_, _ = w.Write([]byte(`[{"mac":"e8:6a:64:7e:0a:b8","access":"permit","permit":true},{"mac":"ac:c5:1b:24:2b:4d","access":"deny","deny":true}]`))
		case "/rci/show/sc/ip/dhcp/host":
			_, _ = w.Write([]byte(`[{"mac":"e8:6a:64:7e:0a:b8","ip":"192.168.0.90"},{"mac":"zz","ip":"1.2.3.4"}]`))
		case "/rci/show/upnp/redirect":
			_, _ = w.Write([]byte(`{"entry":[{"protocol":"udp","port":58849,"to-address":"192.168.1.5","to-port":"58849","description":"ZeroTier","packets":3,"bytes":120}]}`))
		case "/rci/show/internet/status":
			_, _ = w.Write([]byte(`{"internet":false}`))
		case "/rci/show/interface":
			_, _ = w.Write([]byte(`{"GigabitEthernet0":{"type":"GigabitEthernet","state":"up","link":"up"},"0":{"type":"Port","link":"up"},
				"GigabitEthernet0/Vlan1":{"type":"Vlan","state":"up","link":"up"},
				"Bridge0":{"type":"Bridge","state":"up","link":"up","address":"192.168.0.1"},
				"PPPoE0":{"type":"PPPoE","state":"up","link":"up","address":"31.28.108.191"},
				"WifiMaster0/AccessPoint0":{"type":"AccessPoint","state":"up","link":"up"},
				"Bridge1":{"type":"Bridge","state":"down","link":"down"}}`))
		case "/rci/show/interface/stat?name=PPPoE0":
			_, _ = w.Write([]byte(`{"rxbytes":409890362492,"txbytes":153820558386}`))
		case "/rci/show/interface/stat?name=Bridge0":
			_, _ = w.Write([]byte(`{"rxbytes":7,"txbytes":9}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestPollReadsTheRouterWithOnlyShowCommands(t *testing.T) {
	var paths []string
	srv := fakeRouter(t, "Test", "pw", &paths)
	defer srv.Close()
	c, err := New(srv.URL, "Test", "pw")
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP = srv.Client()
	r, err := c.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Board != "Sprinter (KN-3710)" || r.Version != "4.3.6.3" || r.UptimeSec != 3162337 || r.CPU != 34 || !r.HasStats {
		t.Fatalf("device: %+v", r)
	}
	if r.MemTotal != 262144*1024 || r.MemFree != 35000*1024 {
		t.Fatalf("memory (caches count as free): %d free of %d", r.MemFree, r.MemTotal)
	}
	if !r.HasConn || r.Conn != 16384-15906 || r.ConnMax != 16384 {
		t.Fatalf("connections: %+v", r)
	}
	if !r.ResetClients || len(r.Clients) != 1 {
		t.Fatalf("only active clients with a real address and MAC: %+v", r.Clients)
	}
	if r.Clients[0].MAC != "E8:6A:64:7E:0A:B8" || r.Clients[0].Host != "Desk" {
		t.Fatalf("clients: %+v", r.Clients)
	}
	if len(r.Ifaces) != 2 || r.Ifaces[0].Name != "Bridge0" || r.Ifaces[1].Name != "PPPoE0" || r.Ifaces[1].RX != 409890362492 || !r.Ifaces[1].Up || !r.Ifaces[1].Wan || r.Ifaces[0].Wan {
		t.Fatalf("interfaces (the lines and the cable ports are left out): %+v", r.Ifaces)
	}
	if !r.ResetNat || len(r.Nat) != 4 || !r.Nat[1].Off || r.Nat[0].Off || r.Nat[2].Off {
		t.Fatalf("three forwards (one of them switched off) and one UPnP entry: %+v", r.Nat)
	}
	if n := r.Nat[0]; n.Action != "forward tcp" || n.DstPort != "8001" || n.ToAddr != "AA:BB:CC:DD:EE:01" || n.ToPorts != "8001" || n.Comment != "NVR" || n.Packets != -1 {
		t.Fatalf("a forward to a machine known only by its MAC: %+v", n)
	}
	if n := r.Nat[2]; n.DstPort != "9025" || n.ToAddr != "192.168.1.9" || n.ToPorts != "3389" {
		t.Fatalf("a forward to another port: %+v", n)
	}
	if n := r.Nat[3]; n.Action != "upnp udp" || n.Comment != "ZeroTier" || n.Packets != 3 || n.Bytes != 120 {
		t.Fatalf("upnp: %+v", n)
	}
	if !r.HasAccess || len(r.Blocked) != 1 || r.Blocked[0].MAC != "AC:C5:1B:24:2B:4D" || r.Blocked[0].Host != "Printer - Home" || r.Blocked[0].IP != "192.168.0.71" {
		t.Fatalf("the device the router refuses: %+v", r.Blocked)
	}
	if len(r.Reserved) != 1 || r.Reserved[0].MAC != "E8:6A:64:7E:0A:B8" || r.Reserved[0].IP != "192.168.0.90" {
		t.Fatalf("the address the router keeps (a broken row is left out): %+v", r.Reserved)
	}
	if r.Internet == nil || *r.Internet {
		t.Fatalf("the router says there is no way out: %v", r.Internet)
	}
}

func TestPollTellsAWrongPasswordFromAnAddressThatIsNotARouter(t *testing.T) {
	var paths []string
	srv := fakeRouter(t, "Test", "pw", &paths)
	defer srv.Close()
	c, _ := New(srv.URL, "Test", "wrong")
	c.HTTP = srv.Client()
	if _, err := c.Poll(context.Background()); !errors.Is(err, ErrAuth) || Code(err) != "auth" {
		t.Fatalf("a wrong password: %v", err)
	}
	other := httptest.NewTLSServer(http.NotFoundHandler())
	defer other.Close()
	c, _ = New(other.URL, "Test", "pw")
	c.HTTP = other.Client()
	if _, err := c.Poll(context.Background()); !errors.Is(err, ErrUnexpected) || Code(err) != "unexpected" {
		t.Fatalf("not a Keenetic: %v", err)
	}
	if len(paths) != 0 {
		t.Fatalf("nothing is read before the login works: %v", paths)
	}
}

func TestTheClientDoesNotReachTheServerItself(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler()) // listens on loopback
	defer srv.Close()
	c, _ := New(srv.URL, "Test", "pw")
	if _, err := c.Poll(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("loopback must be refused: %v", err)
	}
}

func TestParseBaseTakesOnlyPlainHTTPSAddresses(t *testing.T) {
	for in, want := range map[string]string{"profite.keenetic.pro": "https://profite.keenetic.pro", "HTTPS://Name.Keenetic.Link:8443/": "https://name.keenetic.link:8443"} {
		if got, err := ParseBase(in); err != nil || got != want {
			t.Errorf("%q → %q %v", in, got, err)
		}
	}
	for _, in := range []string{"", "http://x.example", "https://u:p@x.example", "https://x.example/rci/show", "https://x.example?a=1", "https://x.example:99999", "ftp://x.example"} {
		if _, err := ParseBase(in); err == nil {
			t.Errorf("%q must be refused", in)
		}
	}
}
