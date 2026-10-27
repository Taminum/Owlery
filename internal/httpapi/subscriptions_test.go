package httpapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/alerts"
	"github.com/Taminum/Owlery/internal/store"
)

func TestSubscriptionsAreListedMaskedForViewersAndRaiseAlertsOnlyForActiveUsers(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	now := time.Now().UTC()
	gb := int64(1 << 30)
	ins := func(panel, uuid, name, status string, exp *time.Time, limit, used *int64) {
		t.Helper()
		if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO users (panel_id, remote_uuid, display_name, status, last_sync_at, expire_at, traffic_limit_bytes, traffic_used_bytes) VALUES ($1,$2,$3,$4,now(),$5,$6,$7)`,
			panel, uuid, name, status, exp, limit, used); err != nil {
			t.Fatal(err)
		}
	}
	soon, far, past := now.Add(30*time.Hour), now.Add(40*24*time.Hour), now.Add(-time.Hour)
	lim, nearly, low := 100*gb, 95*gb, 10*gb
	ins(w.work.ID, "1", "alice-ends-soon", "ACTIVE", &soon, nil, nil)
	ins(w.work.ID, "2", "bob-near-limit", "ACTIVE", &far, &lim, &nearly)
	ins(w.work.ID, "3", "carol-fine", "ACTIVE", &far, &lim, &low)
	ins(w.work.ID, "4", "dave-expired", "EXPIRED", &past, nil, nil)
	ins(w.work.ID, "5", "erin-disabled", "DISABLED", &soon, &lim, &nearly)
	ins(w.work.ID, "6", "frank-unlimited", "ACTIVE", nil, nil, nil)

	if _, _, err := alerts.Evaluate(ctx, w.h.st, now); err != nil {
		t.Fatal(err)
	}
	_, b := w.owner.get("/api/v1/alerts")
	got := map[string]string{}
	for _, a := range parse[alertsResp](t, b).Alerts {
		got[a.Kind] += a.Label + "|"
	}
	if !strings.Contains(got["user_expiry"], "alice-ends-soon") || strings.Count(got["user_expiry"], "|") != 1 {
		t.Fatalf("only the active user whose subscription ends soon: %v", got)
	}
	if !strings.Contains(got["user_traffic"], "bob-near-limit") || strings.Count(got["user_traffic"], "|") != 1 {
		t.Fatalf("only the active user near the limit: %v", got)
	}

	st, body := w.owner.get("/api/v1/subscriptions")
	if st != 200 || !strings.Contains(string(body), "alice-ends-soon") || strings.Index(string(body), "alice-ends-soon") > strings.Index(string(body), "carol-fine") {
		t.Fatalf("%d %s", st, body)
	}
	_, vb := w.viewer.get("/api/v1/subscriptions")
	if strings.Contains(string(vb), "alice-ends-soon") || !strings.Contains(string(vb), "al2022") && !strings.Contains(string(vb), "al•") {
		t.Fatalf("a viewer sees masked names: %s", vb)
	}
	// What the panel did not say stays empty and is not invented.
	if !strings.Contains(string(body), `"traffic_limit_bytes":null`) {
		t.Fatalf("%s", body)
	}
	_ = store.Scope{}
}
