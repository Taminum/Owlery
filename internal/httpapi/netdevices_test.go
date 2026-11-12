package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
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
