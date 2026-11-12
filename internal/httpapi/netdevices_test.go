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
