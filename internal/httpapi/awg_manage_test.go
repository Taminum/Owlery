package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/awgops"
	"github.com/Taminum/RemnaScope/internal/ingestproto"
	"github.com/Taminum/RemnaScope/internal/store"
)

const newKey = "NEWK111111111111111111111111111111111111111="

// fakeHost plays an AmneziaWG agent connected to the hub: it answers commands the way the helper would.
type fakeHost struct {
	mu   sync.Mutex
	ops  []ingestproto.AWGOp
	hub  *awgops.Hub
	id   string
	fail string // when set, every command is answered with this error code
}

func (f *fakeHost) connect() {
	f.hub.Register(f.id, func(_ context.Context, v any) error {
		op := v.(ingestproto.AWGOp)
		f.mu.Lock()
		f.ops = append(f.ops, op)
		fail := f.fail
		f.mu.Unlock()
		go func() {
			res := ingestproto.AWGOpResult{ID: op.ID, Status: "ok", Key: newKey, IP: "10.8.1.9"}
			switch {
			case fail != "":
				res = ingestproto.AWGOpResult{ID: op.ID, Status: "error", Code: fail}
			case op.Op == "add":
				res.Config = "[Interface]\nPrivateKey = CLIENTSECRET\nAddress = 10.8.1.9/32\n"
			case op.Op == "revoke":
				res.Key, res.IP = op.Key, ""
			}
			f.hub.Deliver(f.id, res)
		}()
		return nil
	})
}

func managedWorld(t *testing.T) (*world, *fakeHost, string) {
	t.Helper()
	w := awgWorld(t, time.Second)
	hub := awgops.New()
	w.h.srv.AWGOps = hub
	var agentID, instID string
	if err := w.h.st.Pool().QueryRow(context.Background(), `SELECT agent_id::text, id::text FROM awg_instances LIMIT 1`).Scan(&agentID, &instID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.h.st.Pool().Exec(context.Background(), `UPDATE awg_instances SET mode='managed'`); err != nil {
		t.Fatal(err)
	}
	f := &fakeHost{hub: hub, id: agentID}
	f.connect()
	return w, f, instID
}

func TestAWGAddReturnsTheConfigOnceAndStoresNoSecret(t *testing.T) {
	w, host, inst := managedWorld(t)
	st, b := w.owner.do("POST", "/api/v1/awg/instances/"+inst+"/peers", map[string]string{"name": "Pixel 8 (Mish)"})
	if st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	var out struct {
		Name, KeyShort, TunnelIP, Config, Filename string
	}
	_ = json.Unmarshal(b, &struct {
		Name     *string `json:"name"`
		KeyShort *string `json:"key_short"`
		TunnelIP *string `json:"tunnel_ip"`
		Config   *string `json:"config"`
		Filename *string `json:"filename"`
	}{&out.Name, &out.KeyShort, &out.TunnelIP, &out.Config, &out.Filename})
	if out.TunnelIP != "10.8.1.9" || !strings.Contains(out.Config, "CLIENTSECRET") || out.Filename != "Pixel_8_Mish.conf" || strings.Contains(string(b), newKey) {
		t.Fatalf("%+v (the full public key must not be shown either): %s", out, b)
	}
	if len(host.ops) != 1 || host.ops[0].Op != "add" || host.ops[0].Name != "Pixel 8 (Mish)" || host.ops[0].Container != "amnezia-awg2" {
		t.Fatalf("%+v", host.ops)
	}
	// the device is listed at once under its name; the secret is nowhere in the database or the audit
	_, lb := w.owner.get("/api/v1/awg")
	if !strings.Contains(string(lb), "Pixel 8 (Mish)") || strings.Contains(string(lb), "CLIENTSECRET") {
		t.Fatalf("%s", lb)
	}
	for _, q := range []string{`SELECT coalesce(string_agg(metadata::text,' '),'') FROM audit_log`, `SELECT coalesce(string_agg(label,' '),'') FROM awg_operations`, `SELECT coalesce(string_agg(label || tunnel_ip,' '),'') FROM awg_peers`} {
		var text string
		if err := w.h.st.Pool().QueryRow(context.Background(), q).Scan(&text); err != nil {
			t.Fatal(err, q)
		}
		if strings.Contains(text, "CLIENTSECRET") || strings.Contains(text, "PrivateKey") {
			t.Fatalf("a private key reached the database: %s", q)
		}
	}
	var n int
	_ = w.h.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM awg_operations WHERE kind='add' AND status='ok' AND requested_by IS NOT NULL`).Scan(&n)
	if n != 1 {
		t.Fatalf("%d operation rows", n)
	}
	// a second add, looked at on the wire: the answer carrying a private key must not be cacheable
	req, _ := http.NewRequest("POST", w.h.ts.URL+"/api/v1/awg/instances/"+inst+"/peers", strings.NewReader(`{"name":"Second"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", w.owner.csrf)
	resp := w.owner.rawDo(req)
	resp.Body.Close()
	if resp.StatusCode != 201 || !strings.Contains(resp.Header.Get("Cache-Control"), "no-store") {
		t.Fatalf("%d %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
}

func TestAWGManagementIsOwnerOnlyAndNeedsAManagedOnlineHost(t *testing.T) {
	w, host, inst := managedWorld(t)
	body := map[string]string{"name": "Phone"}
	for _, c := range []*client{w.viewer, w.op, w.adm} {
		if st, _ := c.do("POST", "/api/v1/awg/instances/"+inst+"/peers", body); st != 403 {
			t.Fatalf("non-owner add: %d", st)
		}
	}
	if st, _ := w.h.anon().do("POST", "/api/v1/awg/instances/"+inst+"/peers", body); st != 401 && st != 403 {
		t.Fatalf("anonymous: %d", st)
	}
	if len(host.ops) != 0 {
		t.Fatal("a command reached the host without permission")
	}
	// invalid names never reach the host
	for _, bad := range []string{"", "x; rm -rf /", "$(id)", "-lead", strings.Repeat("x", 41), "тест"} {
		if st, _ := w.owner.do("POST", "/api/v1/awg/instances/"+inst+"/peers", map[string]string{"name": bad}); st != 422 {
			t.Fatalf("name %q: %d", bad, st)
		}
	}
	if len(host.ops) != 0 {
		t.Fatalf("an invalid name was forwarded: %+v", host.ops)
	}
	// not managed
	_, _ = w.h.st.Pool().Exec(context.Background(), `UPDATE awg_instances SET mode='read_only'`)
	if st, b := w.owner.do("POST", "/api/v1/awg/instances/"+inst+"/peers", body); st != 409 || errCode(b) != "not_managed" {
		t.Fatalf("read-only server: %d %s", st, b)
	}
	_, _ = w.h.st.Pool().Exec(context.Background(), `UPDATE awg_instances SET mode='managed'`)
	// unknown server
	if st, _ := w.owner.do("POST", "/api/v1/awg/instances/00000000-0000-4000-8000-000000000001/peers", body); st != 404 {
		t.Fatalf("unknown server: %d", st)
	}
	// agent offline
	w.h.srv.AWGOps = awgops.New()
	if st, b := w.owner.do("POST", "/api/v1/awg/instances/"+inst+"/peers", body); st != 503 || errCode(b) != "agent_offline" {
		t.Fatalf("offline: %d %s", st, b)
	}
}

func TestAWGHostRefusalsAreReportedWithFixedWordsAndRecorded(t *testing.T) {
	w, host, inst := managedWorld(t)
	host.fail = "no_free_address"
	st, b := w.owner.do("POST", "/api/v1/awg/instances/"+inst+"/peers", map[string]string{"name": "Phone"})
	if st != 502 || errCode(b) != "awg_no_free_address" {
		t.Fatalf("%d %s", st, b)
	}
	host.fail = "busy"
	if st, b := w.owner.do("POST", "/api/v1/awg/instances/"+inst+"/peers", map[string]string{"name": "Phone"}); st != 409 || errCode(b) != "awg_busy" {
		t.Fatalf("%d %s", st, b)
	}
	host.fail = "weird <script>"
	if st, b := w.owner.do("POST", "/api/v1/awg/instances/"+inst+"/peers", map[string]string{"name": "Phone"}); st != 502 || errCode(b) != "awg_failed" || strings.Contains(string(b), "script") {
		t.Fatalf("an unknown word must not be passed on: %d %s", st, b)
	}
	var n int
	_ = w.h.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM awg_operations WHERE kind='add' AND status='error'`).Scan(&n)
	if n != 3 {
		t.Fatalf("%d failed operations recorded", n)
	}
	_, lb := w.owner.get("/api/v1/awg")
	if strings.Contains(string(lb), `"Phone"`) {
		t.Fatal("a device that was never created is listed")
	}
}

func TestAWGRevokeAndRename(t *testing.T) {
	w, host, _ := managedWorld(t)
	_, b := w.owner.get("/api/v1/awg")
	var out awgResp
	_ = json.Unmarshal(b, &out)
	var target string
	for _, p := range out.Instances[0].Peers {
		if p.Label == "RouterOne" {
			target = p.ID
		}
	}
	if st, _ := w.viewer.do("POST", "/api/v1/awg/peers/"+target+"/revoke", nil); st != 403 {
		t.Fatalf("non-owner revoke: %d", st)
	}
	if st, _ := w.owner.do("PATCH", "/api/v1/awg/peers/"+target, map[string]string{"label": "Router home"}); st != 204 {
		t.Fatalf("rename: %d", st)
	}
	if st, _ := w.owner.do("PATCH", "/api/v1/awg/peers/"+target, map[string]string{"label": "bad;name"}); st != 422 {
		t.Fatalf("rename with a bad name: %d", st)
	}
	if len(host.ops) != 0 {
		t.Fatal("renaming must not touch the host")
	}
	if st, b := w.owner.do("POST", "/api/v1/awg/peers/"+target+"/revoke", nil); st != 204 {
		t.Fatalf("revoke: %d %s", st, b)
	}
	if len(host.ops) != 1 || host.ops[0].Op != "revoke" || host.ops[0].Key != awgKeyA {
		t.Fatalf("%+v", host.ops)
	}
	_, lb := w.owner.get("/api/v1/awg")
	var after awgResp
	_ = json.Unmarshal(lb, &after)
	for _, p := range after.Instances[0].Peers {
		if p.ID == target && p.Label != "Router home" {
			t.Fatalf("%+v", p)
		}
	}
	if !strings.Contains(string(lb), `"gone":true`) {
		t.Fatalf("a revoked device must be shown as gone: %s", lb)
	}
	if st, b := w.owner.do("POST", "/api/v1/awg/peers/"+target+"/revoke", nil); st != 409 || errCode(b) != "already_gone" {
		t.Fatalf("revoking twice: %d %s", st, b)
	}
	// a host that no longer knows the device: the list is brought in line with it
	_, _ = w.h.st.Pool().Exec(context.Background(), `UPDATE awg_peers SET gone_at=NULL WHERE id=$1`, target)
	host.fail = "not_found"
	if st, _ := w.owner.do("POST", "/api/v1/awg/peers/"+target+"/revoke", nil); st != 404 {
		t.Fatalf("not found on the host: %d", st)
	}
	var gone bool
	_ = w.h.st.Pool().QueryRow(context.Background(), `SELECT gone_at IS NOT NULL FROM awg_peers WHERE id=$1`, target).Scan(&gone)
	if !gone {
		t.Fatal("the list was not brought in line with the host")
	}
	_ = store.ErrNotFound
}

func TestAWGContainersCanBeCreatedAndRemovedOnlyOnAHostThatOptedIn(t *testing.T) {
	w, host, inst := managedWorld(t)
	if _, err := w.h.st.Pool().Exec(context.Background(), `UPDATE awg_instances SET container='amnezia-awg2'`); err != nil {
		t.Fatal(err)
	}
	// The host list says that nobody has opted in yet.
	_, hb := w.owner.get("/api/v1/awg/hosts")
	var hosts struct {
		Hosts []struct {
			ID             string `json:"id"`
			Online         bool   `json:"online"`
			ContainerAdmin bool   `json:"container_admin"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(hb, &hosts); err != nil || len(hosts.Hosts) != 1 || !hosts.Hosts[0].Online || hosts.Hosts[0].ContainerAdmin {
		t.Fatalf("%s", hb)
	}
	path := "/api/v1/awg/hosts/" + host.id + "/containers"
	body := map[string]any{"container": "amnezia-awg3", "port": 55555, "subnet": "10.9.1.0/24"}
	if st, b := w.owner.do("POST", path, body); st != 409 || !strings.Contains(string(b), "container_admin_off") {
		t.Fatalf("a host that did not opt in must be refused: %d %s", st, b)
	}
	host.hub.SetContainerAdmin(host.id, true)

	// A viewer cannot, and bad fields never reach the host.
	if st, _ := w.viewer.do("POST", path, body); st != 403 {
		t.Fatalf("a viewer created a container: %d", st)
	}
	for name, bad := range map[string]map[string]any{
		"name":   {"container": "amnezia-awg3; rm -rf /", "port": 55555, "subnet": "10.9.1.0/24"},
		"other":  {"container": "nginx", "port": 55555, "subnet": "10.9.1.0/24"},
		"port":   {"container": "amnezia-awg3", "port": 80, "subnet": "10.9.1.0/24"},
		"subnet": {"container": "amnezia-awg3", "port": 55555, "subnet": "192.168.1.0/24"},
	} {
		if st, _ := w.owner.do("POST", path, bad); st != 422 {
			t.Errorf("%s was accepted: %d", name, st)
		}
	}
	host.mu.Lock()
	n := len(host.ops)
	host.mu.Unlock()
	if n != 0 {
		t.Fatalf("a refused request reached the host: %d", n)
	}

	st, b := w.owner.do("POST", path, body)
	if st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	host.mu.Lock()
	op := host.ops[len(host.ops)-1]
	host.mu.Unlock()
	if op.Op != "install" || op.Container != "amnezia-awg3" || op.Port != 55555 || op.Subnet != "10.9.1.0/24" {
		t.Fatalf("%+v", op)
	}

	// Removing needs the container's own name typed back.
	rm := "/api/v1/awg/instances/" + inst + "/remove"
	if st, _ := w.owner.do("POST", rm, map[string]string{"confirm": "yes"}); st != 422 {
		t.Fatalf("removal without the name: %d", st)
	}
	if st, _ := w.owner.do("POST", rm, map[string]string{"confirm": "amnezia-awg2"}); st != 204 {
		t.Fatalf("removal: %d", st)
	}
	host.mu.Lock()
	op = host.ops[len(host.ops)-1]
	host.mu.Unlock()
	if op.Op != "remove" || op.Container != "amnezia-awg2" || op.Confirm != "yes-delete-all-devices" {
		t.Fatalf("%+v", op)
	}
}
