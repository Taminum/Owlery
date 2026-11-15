package httpapi

import (
	"bytes"
	"crypto/md5" //nolint:gosec
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Taminum/Owlery/internal/keenetic"
	"github.com/Taminum/Owlery/internal/store"
)

func TestRouterReportsThroughItsTokenAndTheOwnerSeesPortsClientsAndSpeeds(t *testing.T) {
	w := newWorld(t)
	if st, _ := w.viewer.get("/api/v1/net-devices"); st != 403 {
		t.Fatalf("a viewer must not see devices: %d", st)
	}
	if st, _ := w.viewer.do("POST", "/api/v1/net-devices", map[string]any{"name": "x"}); st != 403 {
		t.Fatalf("a viewer must not add one: %d", st)
	}
	st, b := w.owner.do("POST", "/api/v1/net-devices", map[string]any{"name": "Дом"})
	if st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	var made struct {
		Token  string `json:"token"`
		Script string `json:"script"`
		Device struct {
			ID string `json:"id"`
		} `json:"device"`
	}
	if err := json.Unmarshal(b, &made); err != nil || made.Token == "" || !strings.Contains(made.Script, "Bearer "+made.Token) || !strings.Contains(made.Script, NetIngestPath) {
		t.Fatalf("%v %s", err, b)
	}
	if st, _ := w.owner.do("POST", "/api/v1/net-devices", map[string]any{"name": "дом"}); st != 409 {
		t.Errorf("the same name twice: %d", st)
	}
	post := func(token, body string) int {
		req, _ := http.NewRequest("POST", w.h.ts.URL+NetIngestPath, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := post(made.Device.ID+".wrongwrongwrongwrongwrong", "cpu=1"); c != 401 {
		t.Errorf("a wrong token: %d", c)
	}
	if c := post(made.Token, "just text"); c != 422 {
		t.Errorf("nothing usable: %d", c)
	}
	if c := post(made.Token, "board=hAP\nuptime=1d00:00:00\ncpu=7\nmem_free=1\nmem_total=2\nif=ether1,1000,2000,true\n"); c != 204 {
		t.Fatalf("a report: %d", c)
	}
	if c := post(made.Token, "reset_clients=1\nclient=192.168.88.20,aa:bb:cc:dd:ee:01,home-pc\n"); c != 204 {
		t.Fatalf("clients: %d", c)
	}
	if c := post(made.Token, "client=192.168.88.21,aa:bb:cc:dd:ee:02,nas\nclient=192.168.88.20,aa:bb:cc:dd:ee:01,home-pc\n"); c != 204 {
		t.Fatalf("more clients: %d", c)
	}
	_, b = w.owner.get("/api/v1/net-devices")
	for _, want := range []string{`"name":"Дом"`, `"online":true`, `"board":"hAP"`, `"name":"ether1"`, `"host":"home-pc"`, `"host":"nas"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("%s is missing: %s", want, b)
		}
	}
	if strings.Count(string(b), `"mac":"AA:BB:CC:DD:EE:01"`) != 1 {
		t.Errorf("a client listed twice: %s", b)
	}
	if st, _ := w.owner.do("DELETE", "/api/v1/net-devices/"+made.Device.ID, nil); st != 204 {
		t.Errorf("delete: %d", st)
	}
	if c := post(made.Token, "cpu=1"); c != 401 {
		t.Errorf("a removed device must not report: %d", c)
	}
}

func TestOpenWrtRouterGetsItsOwnInstallerAndItsReportIsTaken(t *testing.T) {
	w := newWorld(t)
	if st, _ := w.owner.do("POST", "/api/v1/net-devices", map[string]any{"name": "Кривой", "kind": "cisco"}); st != 422 {
		t.Fatalf("an unknown kind: %d", st)
	}
	st, b := w.owner.do("POST", "/api/v1/net-devices", map[string]any{"name": "RouteRich", "kind": "openwrt"})
	if st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	var made struct {
		Token  string `json:"token"`
		Script string `json:"script"`
		Device struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
		} `json:"device"`
	}
	if err := json.Unmarshal(b, &made); err != nil || made.Device.Kind != "openwrt" {
		t.Fatalf("%v %s", err, b)
	}
	if !strings.Contains(made.Script, "owlery-report.sh") || !strings.Contains(made.Script, `TOKEN="`+made.Token+`"`) || strings.Contains(made.Script, "@TOKEN@") || strings.Contains(made.Script, "@HOST@") {
		t.Fatalf("the installer: %s", made.Script)
	}
	req, _ := http.NewRequest("POST", w.h.ts.URL+NetIngestPath, strings.NewReader("board=RouteRich\nversion=OpenWrt 23.05.3\nuptime=3d04:05:06\ncpu=9\nmem_total=268435456\nmem_free=100000000\nif=eth0,100,200,true\nconn=40\nconn_max=16384\nreset_nat=1\nnat=dstnat,dst-nat,-,-,8080,192.168.1.20,80,web\nreset_clients=1\nclient=192.168.1.20,aa:bb:cc:dd:ee:01,pc\n"))
	req.Header.Set("Authorization", "Bearer "+made.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 204 {
		t.Fatalf("%v %v", err, resp)
	}
	_, b = w.owner.get("/api/v1/net-devices")
	if !strings.Contains(string(b), `"kind":"openwrt"`) || !strings.Contains(string(b), `"packets":-1`) || !strings.Contains(string(b), `"conn":40`) {
		t.Fatalf("%s", b)
	}
}

func TestAClientThatAppearsLaterIsNewUntilTheOwnerNamesIt(t *testing.T) {
	w := newWorld(t)
	_, b := w.owner.do("POST", "/api/v1/net-devices", map[string]any{"name": "Дом"})
	var made struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(b, &made)
	send := func(body string) {
		req, _ := http.NewRequest("POST", w.h.ts.URL+NetIngestPath, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+made.Token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 204 {
			t.Fatalf("%v %v", err, resp)
		}
	}
	type dev struct {
		MAC       string `json:"mac"`
		Name      string `json:"name"`
		Source    string `json:"source"`
		Confirmed bool   `json:"confirmed"`
		Seen      bool   `json:"seen"`
	}
	list := func() map[string]dev {
		_, b := w.owner.get("/api/v1/lan-devices")
		var out struct {
			Devices []dev `json:"devices"`
		}
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		m := map[string]dev{}
		for _, d := range out.Devices {
			m[d.MAC] = d
		}
		return m
	}
	if st, _ := w.viewer.get("/api/v1/lan-devices"); st != 403 {
		t.Fatalf("a viewer: %d", st)
	}
	// The first list a router sends is the baseline: known.
	send("reset_clients=1\nclient=192.168.88.20,aa:bb:cc:dd:ee:01,pc\n")
	if d := list()["AA:BB:CC:DD:EE:01"]; !d.Confirmed || !d.Seen || d.Source != "Дом" {
		t.Fatalf("baseline: %+v", d)
	}
	// A later arrival is new.
	send("reset_clients=1\nclient=192.168.88.20,aa:bb:cc:dd:ee:01,pc\nclient=192.168.88.141,3c:22:fb:11:90:ab,\n")
	if d := list()["3C:22:FB:11:90:AB"]; d.Confirmed || !d.Seen {
		t.Fatalf("a new device: %+v", d)
	}
	if st, _ := w.owner.do("PATCH", "/api/v1/lan-devices/3c:22:fb:11:90:ab", map[string]any{"name": "Телефон"}); st != 204 {
		t.Fatalf("name: %d", st)
	}
	if d := list()["3C:22:FB:11:90:AB"]; !d.Confirmed || d.Name != "Телефон" {
		t.Fatalf("named: %+v", d)
	}
	if st, _ := w.owner.do("PATCH", "/api/v1/lan-devices/00:00:00:00:00:99", map[string]any{"name": "x"}); st != 404 {
		t.Fatalf("unknown: %d", st)
	}
}

func TestARouterCanStandBehindAnotherButNotInALoop(t *testing.T) {
	w := newWorld(t)
	mk := func(name string) string {
		_, b := w.owner.do("POST", "/api/v1/net-devices", map[string]any{"name": name})
		var m struct {
			Device struct {
				ID string `json:"id"`
			} `json:"device"`
		}
		_ = json.Unmarshal(b, &m)
		return m.Device.ID
	}
	a, b := mk("Дом"), mk("RouteRich")
	set := func(id, parent string) int {
		st, _ := w.owner.do("PATCH", "/api/v1/net-devices/"+id, map[string]any{"parent_id": parent})
		return st
	}
	if set(b, a) != 204 {
		t.Fatal("b behind a")
	}
	if set(a, b) != 409 || set(a, a) != 409 {
		t.Fatal("a loop must be refused")
	}
	if set(b, "00000000-0000-0000-0000-000000000000") != 409 && set(b, "00000000-0000-0000-0000-000000000000") != 404 {
		t.Fatal("an unknown parent must be refused")
	}
	_, body := w.owner.get("/api/v1/net-devices")
	var out struct {
		Devices []struct {
			ID       string  `json:"id"`
			ParentID *string `json:"parent_id"`
		} `json:"devices"`
	}
	_ = json.Unmarshal(body, &out)
	got := map[string]*string{}
	for _, d := range out.Devices {
		got[d.ID] = d.ParentID
	}
	if got[b] == nil || *got[b] != a || got[a] != nil {
		t.Fatalf("%v", got)
	}
	if set(b, "") != 204 {
		t.Fatal("clear")
	}
}

// fakeKeenetic answers like a Keenetic router whose "Test" user has the password "pw".
func fakeKeenetic(t *testing.T) *httptest.Server {
	t.Helper()
	const realm, challenge = "Keenetic Sprinter", "CH"
	var statics []map[string]any
	access, reserved := map[string]string{}, map[string]string{}
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth" {
			if r.Method == http.MethodGet {
				w.Header().Set("X-NDM-Challenge", challenge)
				w.Header().Set("X-NDM-Realm", realm)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			var in struct{ Login, Password string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			m := md5.Sum([]byte("Test:" + realm + ":pw")) //nolint:gosec
			s := sha256.Sum256([]byte(challenge + hex.EncodeToString(m[:])))
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
			if sys, ok := body["system"].(map[string]any); ok && sys["reboot"] != nil {
				w.Header().Set("X-Rebooted", "1")
			}
			if ip, ok := body["ip"].(map[string]any); ok {
				if hs, ok := ip["hotspot"].(map[string]any); ok {
					host := hs["host"].(map[string]any)
					access[host["mac"].(string)] = map[bool]string{true: "deny", false: "permit"}[host["deny"] == true]
				}
				if dh, ok := ip["dhcp"].(map[string]any); ok {
					host := dh["host"].(map[string]any)
					if host["no"] == true {
						delete(reserved, host["mac"].(string))
					} else {
						reserved[host["mac"].(string)] = host["ip"].(string)
					}
				}
				rule, _ := ip["static"].(map[string]any)
				if rule == nil {
					rule = map[string]any{}
				}
				if len(rule) == 0 {
					// not a forward
				} else if rule["no"] == true {
					kept := statics[:0]
					for _, e := range statics {
						if e["index"] != rule["index"] {
							kept = append(kept, e)
						}
					}
					statics = kept
				} else if rule["index"] != nil {
					for i, e := range statics {
						if e["index"] == rule["index"] {
							if m, isMap := rule["disable"].(map[string]any); isMap && m["no"] == true {
								delete(rule, "disable")
							}
							statics[i] = rule
						}
					}
				} else {
					delete(rule, "disable") // the router lists a rule that is on without the key
					rule["index"] = "f" + rule["port"].(string)
					statics = append(statics, rule)
				}
			}
			_, _ = w.Write([]byte(`{"status":[{"status":"message","message":"ok"}]}`))
			return
		}
		switch r.URL.RequestURI() {
		case "/rci/show/sc/ip/static":
			_ = json.NewEncoder(w).Encode(statics)
		case "/rci/show/ip/route":
			_, _ = w.Write([]byte(`[{"destination":"0.0.0.0/0","interface":"PPPoE0"}]`))
		case "/rci/show/sc/ip/hotspot/host":
			out := []map[string]any{}
			for m, a := range access {
				out = append(out, map[string]any{"mac": m, "access": a})
			}
			_ = json.NewEncoder(w).Encode(out)
		case "/rci/show/sc/ip/dhcp/host":
			out := []map[string]any{}
			for m, ip := range reserved {
				out = append(out, map[string]any{"mac": m, "ip": ip})
			}
			_ = json.NewEncoder(w).Encode(out)
		case "/rci/show/version":
			_, _ = w.Write([]byte(`{"title":"4.3.6.3","model":"Sprinter (KN-3710)"}`))
		case "/rci/show/system":
			_, _ = w.Write([]byte(`{"cpuload":12,"memtotal":1000,"memfree":100,"uptime":"500","conntotal":100,"connfree":90}`))
		case "/rci/show/ip/hotspot":
			_, _ = w.Write([]byte(`{"host":[{"mac":"e8:6a:64:7e:0a:b8","ip":"192.168.0.90","hostname":"Desk","active":true}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestAKeeneticIsCheckedStoredSealedAndAskedByTheOwnersWord(t *testing.T) {
	w := newWorld(t)
	router := fakeKeenetic(t)
	defer router.Close()
	w.h.srv.KeeneticClient = func(base, login, password string) (*keenetic.Client, error) {
		c, err := keenetic.New(base, login, password)
		if c != nil {
			c.HTTP = router.Client()
		}
		return c, err
	}
	add := func(c *client, body map[string]any) (int, []byte) { return c.do("POST", "/api/v1/net-devices", body) }
	good := map[string]any{"name": "Рабочий", "kind": "keenetic", "url": router.URL, "login": "Test", "password": "pw"}
	if st, _ := add(w.viewer, good); st != 403 {
		t.Fatalf("a viewer must not add a router: %d", st)
	}
	bad := map[string]any{"name": "Рабочий", "kind": "keenetic", "url": router.URL, "login": "Test", "password": "nope"}
	if st, b := add(w.owner, bad); st != 422 || !strings.Contains(string(b), "router_auth") {
		t.Fatalf("a wrong password is told apart: %d %s", st, b)
	}
	for _, in := range []map[string]any{
		{"name": "x", "kind": "keenetic", "url": "http://plain.example", "login": "Test", "password": "pw"},
		{"name": "x", "kind": "keenetic", "url": router.URL, "login": "", "password": "pw"},
	} {
		if st, _ := add(w.owner, in); st != 422 {
			t.Errorf("%v: %d", in, st)
		}
	}
	_, b := w.owner.get("/api/v1/net-devices")
	if strings.Contains(string(b), "Рабочий") {
		t.Fatalf("a router that failed the check must not be kept: %s", b)
	}
	st, b := add(w.owner, good)
	if st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	if strings.Contains(string(b), `"pw"`) || strings.Contains(string(b), "token") || strings.Contains(string(b), "password") {
		t.Fatalf("the password must never come back: %s", b)
	}
	var made struct {
		Device struct {
			ID string `json:"id"`
		} `json:"device"`
	}
	_ = json.Unmarshal(b, &made)
	_, b = w.owner.get("/api/v1/net-devices")
	for _, want := range []string{`"name":"Рабочий"`, `"kind":"keenetic"`, `"board":"Sprinter (KN-3710)"`, `"host":"Desk"`, `"online":true`, `"url":"` + router.URL + `"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("%s is missing: %s", want, b)
		}
	}
	if st, _ := add(w.owner, good); st != 409 {
		t.Errorf("the same name twice: %d", st)
	}
	pulls, err := w.h.st.PullDevices(ctx)
	if err != nil || len(pulls) != 1 {
		t.Fatalf("%v %v", err, pulls)
	}
	if bytes.Contains(pulls[0].Sealed.Ciphertext, []byte("pw")) || pulls[0].Login != "Test" {
		t.Fatalf("the password is kept sealed: %+v", pulls[0])
	}
	if pw, err := w.h.ring.Open(store.NetPullAAD(made.Device.ID), pulls[0].Sealed); err != nil || string(pw) != "pw" {
		t.Fatalf("the sealed password must open for this router only: %v", err)
	}
	if _, err := w.h.ring.Open(store.NetPullAAD("another"), pulls[0].Sealed); err == nil {
		t.Fatal("a password sealed for one router must not open for another")
	}
	// A new password is checked before it replaces the old one.
	if st, b := w.owner.do("PATCH", "/api/v1/net-devices/"+made.Device.ID, map[string]any{"password": "wrong"}); st != 422 {
		t.Fatalf("a wrong new password: %d %s", st, b)
	}
	if pw, _ := w.h.ring.Open(store.NetPullAAD(made.Device.ID), mustPull(t, w.h.st).Sealed); string(pw) != "pw" {
		t.Fatal("the old password must stay when the new one is refused")
	}
	if st, b := w.owner.do("PATCH", "/api/v1/net-devices/"+made.Device.ID, map[string]any{"password": "pw"}); st != 204 {
		t.Fatalf("the right password: %d %s", st, b)
	}
	// The poller cannot reach a router on this machine: that is told on the page, and nothing else changes.
	(&keenetic.Runner{St: w.h.st, Ring: w.h.ring}).Once(ctx)
	_, b = w.owner.get("/api/v1/net-devices")
	if !strings.Contains(string(b), `"pull_error":"unreachable"`) {
		t.Errorf("the failure is not shown: %s", b)
	}
}

func mustPull(t *testing.T, st *store.Store) store.PullDevice {
	t.Helper()
	p, err := st.PullDevices(ctx)
	if err != nil || len(p) != 1 {
		t.Fatalf("%v %v", err, p)
	}
	return p[0]
}

func TestForwardsAreOpenedAndRemovedFromThePanelByTheOwnerOnly(t *testing.T) {
	w := newWorld(t)
	router := fakeKeenetic(t)
	defer router.Close()
	w.h.srv.KeeneticClient = func(base, login, password string) (*keenetic.Client, error) {
		c, err := keenetic.New(base, login, password)
		if c != nil {
			c.HTTP = router.Client()
		}
		return c, err
	}
	st, b := w.owner.do("POST", "/api/v1/net-devices", map[string]any{"name": "Рабочий", "kind": "keenetic", "url": router.URL, "login": "Test", "password": "pw"})
	if st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	var made struct {
		Device struct {
			ID string `json:"id"`
		} `json:"device"`
	}
	_ = json.Unmarshal(b, &made)
	path := "/api/v1/net-devices/" + made.Device.ID + "/forwards"
	open := map[string]any{"protocol": "tcp", "port": 8080, "to_addr": "192.168.0.90", "to_port": 80, "comment": "web"}
	if st, _ := w.viewer.do("POST", path, open); st != 403 {
		t.Fatalf("a viewer must not open a port: %d", st)
	}
	for _, in := range []map[string]any{
		{"protocol": "icmp", "port": 80, "to_addr": "192.168.0.90"},
		{"protocol": "tcp", "port": 0, "to_addr": "192.168.0.90"},
		{"protocol": "tcp", "port": 80, "to_addr": "8.8.8.8"},
		{"protocol": "tcp", "port": 80, "to_addr": "nonsense"},
	} {
		if st, _ := w.owner.do("POST", path, in); st != 422 {
			t.Errorf("%v: %d", in, st)
		}
	}
	if st, b := w.owner.do("POST", path, map[string]any{"protocol": "tcp", "port": 8080, "to_addr": "192.168.0.77"}); st != 422 || !strings.Contains(string(b), "unknown_host") {
		t.Fatalf("a device the router does not know: %d %s", st, b)
	}
	if st, b := w.owner.do("POST", path, open); st != 204 {
		t.Fatalf("%d %s", st, b)
	}
	if st, b := w.owner.do("POST", path, open); st != 422 || !strings.Contains(string(b), "port_taken") {
		t.Fatalf("the same port twice: %d %s", st, b)
	}
	_, b = w.owner.get("/api/v1/net-devices")
	if !strings.Contains(string(b), `"dst_port":"8080"`) || !strings.Contains(string(b), `"ref":"f8080"`) {
		t.Fatalf("the new forward shows at once: %s", b)
	}
	if strings.Contains(string(b), "new_forwards") {
		t.Fatalf("a forward the owner made is no news: %s", b)
	}
	if st, _ := w.viewer.do("DELETE", path+"/f8080", nil); st != 403 {
		t.Fatalf("a viewer must not remove a port: %d", st)
	}
	if st, _ := w.owner.do("DELETE", path+"/not-hex!", nil); st != 404 {
		t.Fatalf("a reference that is not one: %d", st)
	}
	if st, b := w.owner.do("DELETE", path+"/f8080", nil); st != 204 {
		t.Fatalf("%d %s", st, b)
	}
	if st, _ := w.owner.do("DELETE", path+"/f8080", nil); st != 404 {
		t.Fatalf("gone already: %d", st)
	}
	_, b = w.owner.get("/api/v1/net-devices")
	if strings.Contains(string(b), `"dst_port":"8080"`) {
		t.Fatalf("the removed forward still shows: %s", b)
	}
}

func TestADeviceIsBlockedAnAddressKeptAForwardSwitchedAndTheRouterRestartedByTheOwnerOnly(t *testing.T) {
	w := newWorld(t)
	router := fakeKeenetic(t)
	defer router.Close()
	w.h.srv.KeeneticClient = func(base, login, password string) (*keenetic.Client, error) {
		c, err := keenetic.New(base, login, password)
		if c != nil {
			c.HTTP = router.Client()
		}
		return c, err
	}
	st, b := w.owner.do("POST", "/api/v1/net-devices", map[string]any{"name": "Рабочий", "kind": "keenetic", "url": router.URL, "login": "Test", "password": "pw"})
	if st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	var made struct {
		Device struct {
			ID string `json:"id"`
		} `json:"device"`
	}
	_ = json.Unmarshal(b, &made)
	base := "/api/v1/net-devices/" + made.Device.ID
	mac := "/clients/E8:6A:64:7E:0A:B8"
	for _, c := range []struct{ m, p string }{{"POST", "/reboot"}, {"POST", mac + "/block"}, {"DELETE", mac + "/block"}, {"PUT", mac + "/reserve"}, {"DELETE", mac + "/reserve"}, {"POST", "/forwards/f1/switch"}} {
		if st, _ := w.viewer.do(c.m, base+c.p, map[string]any{}); st != 403 {
			t.Errorf("a viewer must not %s %s: %d", c.m, c.p, st)
		}
	}
	if st, _ := w.owner.do("POST", base+"/clients/nonsense/block", nil); st != 422 {
		t.Fatalf("not a device address: %d", st)
	}
	if st, b := w.owner.do("POST", base+mac+"/block", nil); st != 204 {
		t.Fatalf("%d %s", st, b)
	}
	_, b = w.owner.get("/api/v1/net-devices")
	if !strings.Contains(string(b), `"blocked":[{"mac":"E8:6A:64:7E:0A:B8"`) {
		t.Fatalf("the blocked device shows at once: %s", b)
	}
	if st, _ := w.owner.do("DELETE", base+mac+"/block", nil); st != 204 {
		t.Fatalf("unblock: %d", st)
	}
	if st, b := w.owner.do("PUT", base+mac+"/reserve", nil); st != 204 {
		t.Fatalf("%d %s", st, b)
	}
	_, b = w.owner.get("/api/v1/net-devices")
	if !strings.Contains(string(b), `"reserved":[{"mac":"E8:6A:64:7E:0A:B8","ip":"192.168.0.90"}]`) || strings.Contains(string(b), `"blocked"`) {
		t.Fatalf("the kept address shows and the block is gone: %s", b)
	}
	if st, _ := w.owner.do("DELETE", base+mac+"/reserve", nil); st != 204 {
		t.Fatalf("let go: %d", st)
	}
	if st, b := w.owner.do("POST", base+"/forwards", map[string]any{"protocol": "tcp", "port": 8080, "to_addr": "192.168.0.90"}); st != 204 {
		t.Fatalf("%d %s", st, b)
	}
	if st, b := w.owner.do("POST", base+"/forwards/f8080/switch", map[string]any{"off": true}); st != 204 {
		t.Fatalf("%d %s", st, b)
	}
	_, b = w.owner.get("/api/v1/net-devices")
	if !strings.Contains(string(b), `"off":true`) || strings.Contains(string(b), "new_forwards") {
		t.Fatalf("a forward that is off stays in the list and is no news: %s", b)
	}
	if st, b := w.owner.do("POST", base+"/forwards/f8080/switch", map[string]any{"off": false}); st != 204 {
		t.Fatalf("%d %s", st, b)
	}
	_, b = w.owner.get("/api/v1/net-devices")
	if strings.Contains(string(b), `"off":true`) || strings.Contains(string(b), "new_forwards") {
		t.Fatalf("on again, and the owner's own, so no alert: %s", b)
	}
	if st, _ := w.owner.do("POST", base+"/forwards/zz/switch", map[string]any{"off": true}); st != 404 {
		t.Fatalf("a reference that is not one: %d", st)
	}
	if st, _ := w.owner.do("POST", base+"/reboot", nil); st != 204 {
		t.Fatalf("restart: %d", st)
	}
}

func TestARouterIsPutInAGroupByTheOwnerOnly(t *testing.T) {
	w := newWorld(t)
	st, b := w.owner.do("POST", "/api/v1/net-devices", map[string]any{"name": "Дом", "kind": "mikrotik"})
	if st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	var made struct {
		Device struct {
			ID string `json:"id"`
		} `json:"device"`
	}
	_ = json.Unmarshal(b, &made)
	path := "/api/v1/net-devices/" + made.Device.ID
	if st, _ := w.viewer.do("PATCH", path, map[string]any{"group": "Работа"}); st != 403 {
		t.Fatalf("a viewer must not group a router: %d", st)
	}
	if st, _ := w.owner.do("PATCH", path, map[string]any{"group": strings.Repeat("я", 41)}); st != 422 {
		t.Fatalf("a long name: %d", st)
	}
	if st, _ := w.owner.do("PATCH", path, map[string]any{"group": " Работа "}); st != 204 {
		t.Fatalf("%d", st)
	}
	if _, b := w.owner.get("/api/v1/net-devices"); !strings.Contains(string(b), `"group":"Работа"`) {
		t.Fatalf("%s", b)
	}
	if st, _ := w.owner.do("PATCH", path, map[string]any{"group": ""}); st != 204 {
		t.Fatalf("%d", st)
	}
	if _, b := w.owner.get("/api/v1/net-devices"); strings.Contains(string(b), `"group"`) {
		t.Fatalf("taken out: %s", b)
	}
}

func TestARouterThatReportsByAScriptIsAskedThroughAQueueItAsksFor(t *testing.T) {
	w := newWorld(t)
	st, b := w.owner.do("POST", "/api/v1/net-devices", map[string]any{"name": "Дом", "kind": "mikrotik"})
	if st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	var made struct {
		Token  string `json:"token"`
		Device struct {
			ID string `json:"id"`
		} `json:"device"`
	}
	_ = json.Unmarshal(b, &made)
	call := func(method, token, body string) (int, string) {
		req, _ := http.NewRequest(method, w.h.ts.URL+NetCommandsPath, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(out)
	}
	if c, _ := call("GET", made.Device.ID+".wrongwrongwrongwrongwrong", ""); c != 401 {
		t.Fatalf("a wrong token: %d", c)
	}
	if c, _ := call("GET", made.Token, ""); c != 204 {
		t.Fatalf("nothing is asked yet: %d", c)
	}
	// the router lists a client, so that an address can be kept for it
	rep := "cpu=1\nreset_clients=1\nclient=192.168.88.20,aa:bb:cc:dd:ee:01,pc\n"
	req, _ := http.NewRequest("POST", w.h.ts.URL+NetIngestPath, strings.NewReader(rep))
	req.Header.Set("Authorization", "Bearer "+made.Token)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	path := "/api/v1/net-devices/" + made.Device.ID + "/commands"
	if st, _ := w.viewer.do("POST", path, map[string]any{"kind": "reboot"}); st != 403 {
		t.Fatalf("a viewer must not ask: %d", st)
	}
	for _, in := range []map[string]any{{"kind": "format"}, {"kind": "block", "mac": "nonsense"}, {"kind": "reserve", "mac": "AA:BB:CC:DD:EE:99"}} {
		if st, _ := w.owner.do("POST", path, in); st != 422 {
			t.Errorf("%v: %d", in, st)
		}
	}
	for _, in := range []map[string]any{{"kind": "block", "mac": "aa:bb:cc:dd:ee:01"}, {"kind": "block", "mac": "AA:BB:CC:DD:EE:01"}, {"kind": "reserve", "mac": "AA:BB:CC:DD:EE:01"}, {"kind": "reboot"}} {
		if st, b := w.owner.do("POST", path, in); st != 202 {
			t.Fatalf("%v: %d %s", in, st, b)
		}
	}
	c, line := call("GET", made.Token, "")
	if c != 200 || !strings.HasSuffix(line, "|block|AA:BB:CC:DD:EE:01|") {
		t.Fatalf("the oldest first, the same ask only once: %d %q", c, line)
	}
	id := strings.SplitN(line, "|", 2)[0]
	if c, _ := call("POST", made.Token, "ack="+id+",ok\n"); c != 204 {
		t.Fatalf("ack: %d", c)
	}
	c, line = call("GET", made.Token, "")
	if c != 200 || !strings.Contains(line, "|reserve|AA:BB:CC:DD:EE:01|192.168.88.20") {
		t.Fatalf("the next: %d %q", c, line)
	}
	id = strings.SplitN(line, "|", 2)[0]
	call("POST", made.Token, "ack="+id+",fail,no such lease\n")
	c, line = call("GET", made.Token, "")
	if c != 200 || !strings.Contains(line, "|reboot||") {
		t.Fatalf("%d %q", c, line)
	}
	if c, _ := call("GET", made.Token, ""); c != 204 {
		t.Fatalf("a reboot is handed out once, and nothing else is left: %d", c)
	}
	_, b = w.owner.get("/api/v1/net-devices")
	for _, want := range []string{`"state":"done"`, `"state":"failed"`, `no such lease`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("%s is missing from the list: %s", want, b)
		}
	}

	// a new token: the old script stops at once
	st, b = w.owner.do("POST", "/api/v1/net-devices/"+made.Device.ID+"/rotate", nil)
	var again struct {
		Token  string `json:"token"`
		Script string `json:"script"`
	}
	_ = json.Unmarshal(b, &again)
	if st != 200 || again.Token == "" || again.Token == made.Token || !strings.Contains(again.Script, NetCommandsPath) {
		t.Fatalf("%d %s", st, b)
	}
	if c, _ := call("GET", made.Token, ""); c != 401 {
		t.Fatalf("the old token must stop: %d", c)
	}
	if c, _ := call("GET", again.Token, ""); c != 204 {
		t.Fatalf("the new one works: %d", c)
	}
	if st, _ := w.viewer.do("POST", "/api/v1/net-devices/"+made.Device.ID+"/rotate", nil); st != 403 {
		t.Fatalf("a viewer must not rotate: %d", st)
	}
}
