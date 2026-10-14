package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/store"
)

type probesResp struct {
	Targets []probeOut `json:"targets"`
	CanEdit bool       `json:"can_edit"`
	Max     int        `json:"max_per_panel"`
}

func TestProbeTargetsAreValidatedScopedAndLimited(t *testing.T) {
	w := analyzerWorld(t)
	post := func(c *client, panel, name, host string, port int, mode string) (int, []byte) {
		return c.do("POST", "/api/v1/probes", map[string]any{"panel_id": panel, "name": name, "host": host, "port": port, "mode": mode})
	}
	if st, b := post(w.owner, w.home.ID, "Helsinki прямой", "fi.example.com", 443, "tls"); st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	if st, _ := post(w.owner, w.home.ID, "Helsinki прямой", "fi.example.com", 7443, "tls"); st != 409 {
		t.Fatalf("a repeated name: %d", st)
	}
	if st, b := post(w.owner, w.home.ID, "by ip", "93.184.216.34", 443, "tcp"); st != 201 {
		t.Fatalf("a public IP literal: %d %s", st, b)
	}

	// The server will dial these, so nothing private, local or malformed gets in.
	for name, c := range map[string]struct {
		host string
		port int
		mode string
	}{
		"loopback": {"127.0.0.1", 443, "tcp"}, "private": {"192.168.1.1", 443, "tcp"}, "metadata": {"169.254.169.254", 80, "tcp"},
		"ipv6 local": {"::1", 443, "tcp"}, "bad host": {"not a host", 443, "tcp"}, "url": {"https://example.com", 443, "tcp"},
		"no dot": {"localhost", 443, "tcp"}, "port 0": {"example.com", 0, "tcp"}, "port big": {"example.com", 70000, "tcp"}, "bad mode": {"example.com", 443, "udp"},
		"long host": {"a." + string(make([]byte, 300)), 443, "tcp"},
	} {
		if st, b := post(w.owner, w.home.ID, "x-"+name, c.host, c.port, c.mode); st != 422 {
			t.Errorf("%s: %d %s", name, st, b)
		}
	}
	if st, _ := w.owner.do("POST", "/api/v1/probes", map[string]any{"panel_id": w.home.ID, "name": "sni", "host": "example.com", "port": 443, "mode": "tls", "sni": "bad sni!"}); st != 422 {
		t.Errorf("bad sni: %d", st)
	}

	// Who may add: a panel administrator, not an operator or viewer; nobody for a panel out of scope.
	if st, _ := post(w.adm, w.work.ID, "Work edge", "work.example.com", 443, "tls"); st != 201 {
		t.Fatalf("a panel admin: %d", st)
	}
	for who, c := range map[string]*client{"viewer": w.viewer, "operator": w.op} {
		if st, _ := post(c, w.work.ID, "nope-"+who, "work.example.com", 443, "tls"); st != 403 {
			t.Errorf("%s: %d", who, st)
		}
	}
	if st, _ := post(w.adm, w.home.ID, "foreign", "example.com", 443, "tls"); st != 404 {
		t.Errorf("a panel out of scope must look like it does not exist: %d", st)
	}
	if st, _ := w.h.anon().do("POST", "/api/v1/probes", map[string]any{"panel_id": w.home.ID, "name": "a", "host": "example.com", "port": 443, "mode": "tcp"}); st != 401 {
		t.Errorf("anonymous: %d", st)
	}

	// The cap per panel.
	for i := 0; i < store.MaxProbeTargets; i++ {
		st, _ := post(w.owner, w.home.ID, fmt.Sprintf("bulk-%d", i), "bulk.example.com", 443, "tcp")
		if st == 409 {
			if i == 0 {
				t.Fatal("limit reached at once")
			}
			return
		}
	}
	if st, b := post(w.owner, w.home.ID, "one too many", "bulk.example.com", 443, "tcp"); st != 409 || errCode(b) != "limit" {
		t.Fatalf("limit: %d %s", st, b)
	}
}

func TestProbeListShowsLastResultLossAndStaleness(t *testing.T) {
	w := analyzerWorld(t)
	ctx := context.Background()
	_, b := w.owner.do("POST", "/api/v1/probes", map[string]any{"panel_id": w.home.ID, "name": "CDN", "host": "fi.example.com", "port": 7443, "mode": "tls"})
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &created)
	_, b = w.owner.do("POST", "/api/v1/probes", map[string]any{"panel_id": w.work.ID, "name": "Work", "host": "work.example.com", "port": 443, "mode": "tcp"})
	var workT struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &workT)

	now := w.h.srv.Now().UTC()
	ms := func(v int) *int { return &v }
	rec := func(id string, ago time.Duration, ok bool, conn, tls *int, e string) {
		if err := w.h.st.RecordProbe(ctx, id, store.ProbeResult{TS: now.Add(-ago), OK: ok, ConnectMS: conn, TLSMS: tls, Error: e}); err != nil {
			t.Fatal(err)
		}
	}
	rec(created.ID, 4*time.Minute, true, ms(40), ms(90), "")
	rec(created.ID, 3*time.Minute, true, ms(50), ms(110), "")
	rec(created.ID, 2*time.Minute, false, nil, nil, "timeout")
	rec(created.ID, 1*time.Minute, true, ms(60), ms(130), "")
	rec(workT.ID, 2*time.Hour, true, ms(10), nil, "") // old: says nothing about now

	_, lb := w.owner.get("/api/v1/probes?panel_ids=" + w.home.ID)
	r := parse[probesResp](t, lb)
	if len(r.Targets) != 1 || !r.CanEdit || r.Max != store.MaxProbeTargets {
		t.Fatalf("%+v", r)
	}
	c := r.Targets[0]
	if c.State != "up" || c.PanelName != "Home" || c.Samples1h != 4 || c.LossPct != 25 || c.P50TLS == nil || *c.P50TLS != 110 || c.ConnectMS == nil || *c.ConnectMS != 60 || len(c.Series) == 0 {
		t.Fatalf("%+v", c)
	}
	// The latest result failing makes the channel "down", and an old result is "unknown", not "up".
	rec(created.ID, 10*time.Second, false, nil, nil, "refused")
	_, lb = w.owner.get("/api/v1/probes?panel_ids=" + w.home.ID)
	if c := parse[probesResp](t, lb).Targets[0]; c.State != "down" || c.LastError != "refused" {
		t.Fatalf("%+v", c)
	}
	_, lb = w.owner.get("/api/v1/probes?panel_ids=" + w.work.ID)
	if c := parse[probesResp](t, lb).Targets[0]; c.State != "unknown" {
		t.Fatalf("stale: %+v", c)
	}

	// Visibility: the Work viewer sees only Work, read-only, and cannot ask for Home.
	_, vb := w.viewer.get("/api/v1/probes")
	vr := parse[probesResp](t, vb)
	if len(vr.Targets) != 1 || vr.Targets[0].PanelName != "Work" || vr.CanEdit {
		t.Fatalf("%+v", vr)
	}
	if st, bd := w.viewer.get("/api/v1/probes?panel_ids=" + w.home.ID); st != 403 || errCode(bd) != "panel_forbidden" {
		t.Fatalf("%d %s", st, bd)
	}

	// Deleting needs panel admin rights; anyone else gets 403 or "not found".
	if st, _ := w.op.do("DELETE", "/api/v1/probes/"+workT.ID, nil); st != 403 {
		t.Fatalf("operator delete: %d", st)
	}
	if st, _ := w.adm.do("DELETE", "/api/v1/probes/"+created.ID, nil); st != 404 {
		t.Fatalf("a panel admin deleting another panel's target: %d", st)
	}
	if st, _ := w.adm.do("DELETE", "/api/v1/probes/"+workT.ID, nil); st != 204 {
		t.Fatalf("admin delete: %d", st)
	}
	if st, _ := w.owner.do("DELETE", "/api/v1/probes/"+workT.ID, nil); st != 404 {
		t.Fatalf("deleted twice: %d", st)
	}
}
