package httpapi

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/alerts"
	"github.com/Taminum/Owlery/internal/store"
)

type torrentsResp struct {
	Seen    bool `json:"seen"`
	Reports int  `json:"reports"`
	Subs    int  `json:"subs"`
	Rows    []struct {
		User   string   `json:"user"`
		Label  string   `json:"label"`
		Recent int      `json:"recent"`
		Nodes  []string `json:"nodes"`
		Repeat bool     `json:"repeat"`
	} `json:"rows"`
}

type devicesResp struct {
	Seen bool `json:"seen"`
	Rows []struct {
		Label   string `json:"label"`
		Devices int    `json:"devices"`
		IPs     int    `json:"ips"`
		Level   string `json:"level"`
	} `json:"rows"`
}

func TestTorrentsAndDevicesStaySilentWhileOffThenListMaskAndRaiseAnAlert(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	now := time.Now().UTC()

	st, body := w.owner.get("/api/v1/subscriptions/torrents")
	if got := parse[torrentsResp](t, body); st != 200 || got.Seen || len(got.Rows) != 0 {
		t.Fatalf("a panel with the plugin off reports nothing: %d %s", st, body)
	}
	if st, body := w.owner.get("/api/v1/subscriptions/devices"); st != 200 || parse[devicesResp](t, body).Seen {
		t.Fatalf("%d %s", st, body)
	}

	for _, p := range []struct{ panel, id, name string }{{w.work.ID, "21", "alice-shared"}, {w.work.ID, "22", "bob-calm"}, {w.home.ID, "31", "frank-home"}} {
		if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO users (panel_id, remote_uuid, display_name, status, last_sync_at) VALUES ($1,$2,$3,'ACTIVE',now())`, p.panel, p.id, p.name); err != nil {
			t.Fatal(err)
		}
	}
	id := int64(0)
	caught := func(panel, user, node string, n int) {
		var recs []store.TorrentRow
		for i := 0; i < n; i++ {
			id++
			recs = append(recs, store.TorrentRow{RemoteID: id, RemoteUser: user, Node: node, At: now.Add(-time.Duration(i+1) * time.Hour)})
		}
		if _, err := w.h.st.AddTorrentReports(ctx, panel, recs); err != nil {
			t.Fatal(err)
		}
	}
	caught(w.work.ID, "21", "Steal", 5)
	caught(w.work.ID, "22", "Helsinki", 1)
	caught(w.home.ID, "31", "Steal", 2)

	st, body = w.owner.get("/api/v1/subscriptions/torrents")
	got := parse[torrentsResp](t, body)
	if st != 200 || !got.Seen || got.Subs != 3 || got.Reports != 8 || len(got.Rows) != 3 {
		t.Fatalf("%d %s", st, body)
	}
	if r := got.Rows[0]; r.Label != "alice-shared" || r.Recent != 5 || !r.Repeat || len(r.Nodes) != 1 || r.Nodes[0] != "Steal" {
		t.Fatalf("first row: %+v", r)
	}
	if got.Rows[1].Repeat || got.Rows[2].Repeat {
		t.Fatalf("a subscription caught once or twice is not repeated: %s", body)
	}
	_, vb := w.viewer.get("/api/v1/subscriptions/torrents")
	if strings.Contains(string(vb), "frank") || strings.Contains(string(vb), "alice-shared") {
		t.Fatalf("a viewer sees only their panel and masked names: %s", vb)
	}

	if err := w.h.st.ReplaceDevices(ctx, w.work.ID, map[string]int{"21": 11, "22": 2}, now); err != nil {
		t.Fatal(err)
	}
	asks := func(user string, ips int) {
		var recs []store.SubRequest
		for i := 0; i < ips; i++ {
			id++
			recs = append(recs, store.SubRequest{RemoteID: id, RemoteUser: user, At: now.Add(-time.Hour), IP: fmt.Sprintf("46.0.%d.%d", id%200, i+1)})
		}
		if _, err := w.h.st.AddSubscriptionRequests(ctx, w.work.ID, recs); err != nil {
			t.Fatal(err)
		}
	}
	asks("21", 9)
	st, body = w.owner.get("/api/v1/subscriptions/devices")
	dev := parse[devicesResp](t, body)
	if st != 200 || !dev.Seen || len(dev.Rows) != 1 || dev.Rows[0].Label != "alice-shared" || dev.Rows[0].Devices != 11 || dev.Rows[0].IPs != 9 || dev.Rows[0].Level != "leak" {
		t.Fatalf("only the subscription with many devices is listed: %d %s", st, body)
	}
	if err := w.h.st.ReplaceDevices(ctx, w.work.ID, map[string]int{"22": 2}, now); err != nil {
		t.Fatal(err)
	}
	if _, body = w.owner.get("/api/v1/subscriptions/devices"); len(parse[devicesResp](t, body).Rows) != 0 {
		t.Fatalf("the last look replaces the earlier one: %s", body)
	}

	if _, _, err := alerts.Evaluate(ctx, w.h.st, now); err != nil {
		t.Fatal(err)
	}
	_, ab := w.owner.get("/api/v1/alerts")
	n := 0
	for _, a := range parse[alertsResp](t, ab).Alerts {
		if a.Kind == "torrent" {
			n++
			if !strings.Contains(a.Label, "alice-shared") || !strings.Contains(a.Detail, "5 раз") || !strings.Contains(a.Detail, "Steal") {
				t.Fatalf("alert: %+v", a)
			}
		}
	}
	if n != 1 {
		t.Fatalf("only the subscription caught five times raises an alert, got %d: %s", n, ab)
	}
}
