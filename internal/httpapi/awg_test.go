package httpapi

import (
	"context"
	"encoding/json"
	"github.com/Taminum/Owlery/internal/alerts"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/ingestproto"
	"github.com/Taminum/Owlery/internal/store"
)

const (
	awgKeyA = "AAAA111111111111111111111111111111111111111="
	awgKeyB = "BBBB222222222222222222222222222222222222222="
	awgKeyC = "CCCC333333333333333333333333333333333333333="
)

func awgWorld(t *testing.T, reportAge time.Duration) *world {
	t.Helper()
	w := analyzerWorld(t)
	nodes, _ := w.h.st.ListNodes(context.Background(), store.Scope{All: true}, w.home.ID, false)
	ag, err := w.h.st.CreateAgent(context.Background(), store.Scope{All: true}, w.home.ID, nodes[0].ID, "awg", "awg", "", store.HashAgentSecret("awg-secret"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	hs := func(ago time.Duration) int64 { return now.Add(-ago).Unix() }
	snap := ingestproto.AWG{Type: "awg", Instances: []ingestproto.AWGInstance{{Container: "amnezia-awg2", Interface: "awg0", Port: 49587, Fields: []string{"Jc", "S3", "S4", "H1"},
		Peers: []ingestproto.AWGPeer{
			{Key: awgKeyA, Name: "RouterOne", IP: "10.8.1.2/32", RX: 100, TX: 900, Handshake: hs(time.Minute)},
			{Key: awgKeyB, Name: "old", IP: "10.8.1.3/32", RX: 5, TX: 6, Handshake: hs(5 * time.Hour)},
			{Key: awgKeyC, IP: "10.8.1.4/32"},
		}}}}
	if err := w.h.st.SaveAWG(context.Background(), ag, snap, now.Add(-reportAge)); err != nil {
		t.Fatal(err)
	}
	return w
}

type awgResp struct {
	Instances []struct {
		Container   string `json:"container"`
		Variant     string `json:"variant"`
		Mode        string `json:"mode"`
		ReportFresh bool   `json:"report_fresh"`
		Peers       []struct {
			ID            string `json:"id"`
			Label         string `json:"label"`
			KeyShort      string `json:"key_short"`
			State         string `json:"state"`
			DownloadTotal int64  `json:"download_total"`
			UploadTotal   int64  `json:"upload_total"`
		} `json:"peers"`
	} `json:"instances"`
}

func TestAWGListShowsStatesDirectionsAndNoKeys(t *testing.T) {
	w := awgWorld(t, 10*time.Second)
	if st, _ := w.h.anon().get("/api/v1/awg"); st != 401 {
		t.Fatalf("anonymous: %d", st)
	}
	st, b := w.owner.get("/api/v1/awg")
	if st != 200 || strings.Contains(string(b), awgKeyA) || strings.Contains(strings.ToLower(string(b)), "private") {
		t.Fatalf("%d, a full key or secret field leaked: %s", st, b)
	}
	var out awgResp
	if err := json.Unmarshal(b, &out); err != nil || len(out.Instances) != 1 {
		t.Fatalf("%v %s", err, b)
	}
	in := out.Instances[0]
	if in.Container != "amnezia-awg2" || in.Variant != "AWG 2.0" || in.Mode != "read_only" || !in.ReportFresh || len(in.Peers) != 3 {
		t.Fatalf("%+v", in)
	}
	states := map[string]string{}
	for _, p := range in.Peers {
		states[p.Label] = p.State
		if p.Label == "RouterOne" && (p.DownloadTotal != 900 || p.UploadTotal != 100) { // download = what the server sent to the client
			t.Fatalf("directions: %+v", p)
		}
		if len(p.KeyShort) > 14 {
			t.Fatalf("key not shortened: %s", p.KeyShort)
		}
	}
	if states["RouterOne"] != "active" || states["old"] != "stale" || states["10.8.1.4/32"] != "never" {
		t.Fatalf("%v", states)
	}
}

func TestAWGUnknownWhenTheCollectorStoppedReporting(t *testing.T) {
	w := awgWorld(t, 20*time.Minute)
	_, b := w.owner.get("/api/v1/awg")
	var out awgResp
	_ = json.Unmarshal(b, &out)
	if out.Instances[0].ReportFresh {
		t.Fatal("a 20 minute old report counted as fresh")
	}
	for _, p := range out.Instances[0].Peers {
		if p.State != "unknown" {
			t.Fatalf("%s is %s although nothing is being reported: that is 'no data', not 'never' or 'stale'", p.Label, p.State)
		}
	}
}

func TestAWGSeriesAndAgentKind(t *testing.T) {
	w := awgWorld(t, time.Second)
	_, b := w.owner.get("/api/v1/awg")
	var out awgResp
	_ = json.Unmarshal(b, &out)
	id := out.Instances[0].Peers[0].ID
	st, sb := w.owner.get("/api/v1/awg/peers/" + id + "/series?range=24h")
	if st != 200 || !strings.Contains(string(sb), `"points"`) {
		t.Fatalf("%d %s", st, sb)
	}
	if st, _ := w.owner.get("/api/v1/awg/peers/00000000-0000-4000-8000-000000000001/series"); st != 404 {
		t.Fatalf("unknown peer: %d", st)
	}
	// the enrol dialog may create an agent of this kind
	nodes, _ := w.h.st.ListNodes(context.Background(), store.Scope{All: true}, w.home.ID, false)
	if st, b := w.owner.do("POST", "/api/v1/panels/"+w.home.ID+"/agents", map[string]any{"node_id": nodes[0].ID, "name": "awg-2", "kind": "awg"}); st != 201 {
		t.Fatalf("creating an awg agent: %d %s", st, b)
	}
}

func TestAWGLastSeenComesFromTheBestSourceAndAPastPeerIsNotNeverSeen(t *testing.T) {
	w := analyzerWorld(t)
	nodes, _ := w.h.st.ListNodes(context.Background(), store.Scope{All: true}, w.home.ID, false)
	ag, err := w.h.st.CreateAgent(context.Background(), store.Scope{All: true}, w.home.ID, nodes[0].ID, "awg", "awg", "", store.HashAgentSecret("awg-secret"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	snap := ingestproto.AWG{Type: "awg", Instances: []ingestproto.AWGInstance{{Container: "c", Interface: "awg0", LegacyAt: now.Add(-10 * 24 * time.Hour).Unix(), Peers: []ingestproto.AWGPeer{
		{Key: awgKeyA, Name: "live", Handshake: now.Add(-time.Minute).Unix()},
		{Key: awgKeyB, Name: "panel-only", LegacyDown: 5 << 30, LegacyHS: now.Add(-30 * 24 * time.Hour).Unix()},
		{Key: awgKeyC, Name: "nothing"},
	}}}}
	if err := w.h.st.SaveAWG(context.Background(), ag, snap, now); err != nil {
		t.Fatal(err)
	}
	_, b := w.owner.get("/api/v1/awg")
	var out struct {
		Instances []struct {
			LegacyAt *time.Time `json:"legacy_at"`
			Peers    []struct {
				Label          string     `json:"label"`
				State          string     `json:"state"`
				LastSeenAt     *time.Time `json:"last_seen_at"`
				LastSeenSource string     `json:"last_seen_source"`
				TotalDownload  int64      `json:"total_download"`
			} `json:"peers"`
		} `json:"instances"`
	}
	if err := json.Unmarshal(b, &out); err != nil || len(out.Instances) != 1 || out.Instances[0].LegacyAt == nil {
		t.Fatalf("%v %s", err, b)
	}
	got := map[string]string{}
	for _, p := range out.Instances[0].Peers {
		got[p.Label] = p.State + "/" + p.LastSeenSource
		if p.Label == "panel-only" && (p.TotalDownload != 5<<30 || p.LastSeenAt == nil) {
			t.Fatalf("%+v", p)
		}
	}
	if got["live"] != "active/live" || got["panel-only"] != "stale/panel" || got["nothing"] != "never/" {
		t.Fatalf("%v", got)
	}
}

func TestAWGForgetIsOwnerOnlyAndOnlyForGonePeers(t *testing.T) {
	w := awgWorld(t, time.Second)
	_, b := w.owner.get("/api/v1/awg")
	var out awgResp
	_ = json.Unmarshal(b, &out)
	id := out.Instances[0].Peers[0].ID
	for _, c := range []*client{w.viewer, w.op, w.adm} {
		if st, _ := c.do("DELETE", "/api/v1/awg/peers/"+id, nil); st != 403 {
			t.Fatalf("non-owner: %d", st)
		}
	}
	if st, _ := w.owner.do("DELETE", "/api/v1/awg/peers/"+id, nil); st != 404 {
		t.Fatalf("a live device must not be removable: %d", st)
	}
}

func TestAmneziaWGTrafficIsPartOfSitesAndDomainsWithItsSourceMark(t *testing.T) {
	w := awgWorld(t, time.Second)
	ctx := context.Background()
	var agentID string
	_ = w.h.st.Pool().QueryRow(ctx, `SELECT agent_id::text FROM awg_instances LIMIT 1`).Scan(&agentID)
	if err := w.h.st.SaveAWGFlows(ctx, store.Agent{ID: agentID}, ingestproto.AWGFlows{Type: "awg_flows", Container: "amnezia-awg2", End: time.Now().Unix(), Flows: []ingestproto.AWGFlow{
		{Client: "10.8.1.2", Proto: 6, Remote: "1.2.3.4", Port: 443, Up: 10, Down: 990, Name: "video.example", How: "sni", New: 1},
		{Client: "10.8.1.2", Proto: 6, Remote: "5.6.7.8", Port: 9000, Up: 5, Down: 5, New: 1},
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rng := "from=" + now.Add(-3*time.Hour).Format(time.RFC3339) + "&to=" + now.Add(3*time.Hour).Format(time.RFC3339) + "&panel_ids=" + w.home.ID
	st, b := w.owner.get("/api/v1/analytics/sites?" + rng)
	if st != 200 {
		t.Fatalf("%d %s", st, b)
	}
	var sites struct {
		Rows []struct {
			Site        string   `json:"site"`
			Sources     []string `json:"sources"`
			Connections int      `json:"connections"`
			Visits      int      `json:"visits"`
			Bytes       *int64   `json:"bytes"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(b, &sites); err != nil {
		t.Fatalf("%v %s", err, b)
	}
	found := false
	for _, r := range sites.Rows {
		if r.Site == "video.example" {
			found = true
			if len(r.Sources) != 1 || r.Sources[0] != "awg" || r.Connections != 1 || r.Visits != 0 || r.Bytes == nil || *r.Bytes != 1000 {
				t.Fatalf("%+v", r)
			}
		}
	}
	if !found {
		t.Fatalf("an AmneziaWG-only site is missing from the Sites list: %s", b)
	}
	st, b = w.owner.get("/api/v1/analytics/destinations?group_by=host&" + rng)
	if st != 200 || !strings.Contains(string(b), `"sources":["awg"]`) || !strings.Contains(string(b), `"video.example"`) || !strings.Contains(string(b), `"5.6.7.8"`) {
		t.Fatalf("%d %s", st, b)
	}
	// the site's own page lists the device by its name, as an AmneziaWG device
	st, b = w.owner.get("/api/v1/analytics/sites/detail?" + rng + "&site=video.example")
	if st != 200 || !strings.Contains(string(b), `"kind":"awg"`) || !strings.Contains(string(b), `"label":"RouterOne"`) {
		t.Fatalf("%d %s", st, b)
	}
	// every other row of the older tests keeps a sources list (never null)
	st, b = w.owner.get("/api/v1/analytics/sites?" + strings.Replace(rng, w.home.ID, w.home.ID, 1))
	if st != 200 || strings.Contains(string(b), `"sources":null`) {
		t.Fatalf("sources must never be null: %s", b)
	}
}

func TestAWGContainerWithoutAnInterfaceRaisesAnAlertThatClosesWhenItComesBack(t *testing.T) {
	w := awgWorld(t, 10*time.Second)
	ctx := context.Background()
	nodes, _ := w.h.st.ListNodes(ctx, store.Scope{All: true}, w.home.ID, false)
	ag, err := w.h.st.CreateAgent(ctx, store.Scope{All: true}, w.home.ID, nodes[0].ID, "awg2", "awg", "", store.HashAgentSecret("awg-secret-2"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.h.st.Pool().Exec(ctx, `UPDATE agents SET status='active', last_seen=now() WHERE id=$1`, ag.ID); err != nil {
		t.Fatal(err)
	}
	open := func() map[string]bool {
		if _, _, err := alerts.Evaluate(ctx, w.h.st, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		_, b := w.owner.get("/api/v1/alerts")
		out := map[string]bool{}
		for _, a := range parse[alertsResp](t, b).Alerts {
			if a.ResolvedAt == nil {
				out[a.Kind] = true
			}
		}
		return out
	}
	broken := ingestproto.AWG{Type: "awg", Containers: []ingestproto.AWGContainer{{Name: "amnezia-awg2", Tools: "1.0.20210914", Module: "3.1.20260812", Down: true}}}
	if err := w.h.st.SaveAWG(ctx, ag, broken, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if o := open(); !o["awg_down"] {
		t.Fatalf("a container with no interface must raise an alert: %v", o)
	}
	fixed := ingestproto.AWG{Type: "awg", Containers: []ingestproto.AWGContainer{{Name: "amnezia-awg2", Tools: "3.1.20260812", Module: "3.1.20260812"}}}
	if err := w.h.st.SaveAWG(ctx, ag, fixed, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if o := open(); o["awg_down"] || o["awg_tools_old"] {
		t.Fatalf("the alert must close: %v", o)
	}
}
