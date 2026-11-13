package httpapi

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/alerts"
	"github.com/Taminum/Owlery/internal/store"
)

type leaksResp struct {
	Asked int `json:"asked"`
	Leaks int `json:"leaks"`
	New   int `json:"new"`
	Rows  []struct {
		PanelID string   `json:"panel_id"`
		User    string   `json:"user"`
		Label   string   `json:"label"`
		IPs     int      `json:"ips"`
		Clients []string `json:"clients"`
		Level   string   `json:"level"`
	} `json:"rows"`
}

func TestSubscriptionLeaksListByAddressesMaskForViewersStayInScopeAndRaiseAnAlert(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, p := range []struct{ panel, id, name string }{{w.work.ID, "21", "alice-shared"}, {w.work.ID, "22", "bob-calm"}, {w.home.ID, "31", "frank-home"}} {
		if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO users (panel_id, remote_uuid, display_name, status, last_sync_at) VALUES ($1,$2,$3,'ACTIVE',now())`, p.panel, p.id, p.name); err != nil {
			t.Fatal(err)
		}
	}
	id := int64(0)
	asks := func(panel, user string, ips int, ua string) {
		var recs []store.SubRequest
		for i := 0; i < ips; i++ {
			id++
			recs = append(recs, store.SubRequest{RemoteID: id, RemoteUser: user, At: now.Add(-time.Duration(i+1) * time.Hour), IP: fmt.Sprintf("46.0.%d.%d", id%200, i+1), Agent: ua})
		}
		if _, err := w.h.st.AddSubscriptionRequests(ctx, panel, recs); err != nil {
			t.Fatal(err)
		}
	}
	asks(w.work.ID, "21", 12, "Hiddify/2.0 (Android)")
	asks(w.work.ID, "22", 2, "v2rayN/6.4")
	asks(w.home.ID, "31", 6, "Streisand")

	st, body := w.owner.get("/api/v1/subscriptions/leaks")
	got := parse[leaksResp](t, body)
	if st != 200 || got.Asked != 3 || len(got.Rows) != 2 || got.Leaks != 1 {
		t.Fatalf("%d %s", st, body)
	}
	if r := got.Rows[0]; r.Label != "alice-shared" || r.IPs != 12 || r.Level != "leak" || len(r.Clients) != 1 || r.Clients[0] != "Hiddify" {
		t.Fatalf("first row: %+v", r)
	}
	if r := got.Rows[1]; r.Label != "frank-home" || r.Level != "check" {
		t.Fatalf("second row: %+v", r)
	}
	if st, _ := w.owner.get("/api/v1/subscriptions/leaks?min=1"); st != 400 {
		t.Fatalf("a threshold below two is refused, got %d", st)
	}

	_, vb := w.viewer.get("/api/v1/subscriptions/leaks")
	if strings.Contains(string(vb), "frank") || strings.Contains(string(vb), "alice-shared") || !strings.Contains(string(vb), `"ips":12`) {
		t.Fatalf("a viewer sees only their panel and masked names: %s", vb)
	}

	q := url.Values{"panel_id": {w.work.ID}, "user": {"21"}}.Encode()
	st, ib := w.owner.get("/api/v1/subscriptions/leaks/ips?" + q)
	if st != 200 || strings.Count(string(ib), `"ip":"46.0.`) != 12 {
		t.Fatalf("%d %s", st, ib)
	}
	if st, _ := w.viewer.get("/api/v1/subscriptions/leaks/ips?" + url.Values{"panel_id": {w.home.ID}, "user": {"31"}}.Encode()); st != 403 {
		t.Fatalf("another panel's addresses are not for a viewer, got %d", st)
	}

	if _, _, err := alerts.Evaluate(ctx, w.h.st, now); err != nil {
		t.Fatal(err)
	}
	_, ab := w.owner.get("/api/v1/alerts")
	n := 0
	for _, a := range parse[alertsResp](t, ab).Alerts {
		if a.Kind == "sub_leak" {
			n++
			if !strings.Contains(a.Label, "alice-shared") || !strings.Contains(a.Detail, "12 разных IP") {
				t.Fatalf("alert: %+v", a)
			}
		}
	}
	if n != 1 {
		t.Fatalf("only the subscription with twelve addresses raises an alert, got %d: %s", n, ab)
	}
}
