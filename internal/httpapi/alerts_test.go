package httpapi

import (
	"context"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

type alertsResp struct {
	Alerts []alertOut `json:"alerts"`
	Open   int        `json:"open"`
}

func TestAlertsOpenRefreshCloseAndScope(t *testing.T) {
	w := analyzerWorld(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	cond := func(panel, subject, label string) store.Condition {
		return store.Condition{PanelID: panel, Kind: store.AlertAgentSilent, Subject: subject, Label: label, Detail: "d"}
	}
	kinds := []string{store.AlertAgentSilent}

	o, c, err := w.h.st.ApplyConditions(ctx, kinds, []store.Condition{cond(w.home.ID, "a1", "Агент ноды home-a"), cond(w.work.ID, "a2", "Агент ноды work-1")}, t0)
	if err != nil || o != 2 || c != 0 {
		t.Fatalf("open: %d %d %v", o, c, err)
	}
	// The same conditions again refresh, they do not open duplicates.
	o, c, _ = w.h.st.ApplyConditions(ctx, kinds, []store.Condition{cond(w.home.ID, "a1", "Агент ноды home-a"), cond(w.work.ID, "a2", "Агент ноды work-1")}, t0.Add(time.Minute))
	if o != 0 || c != 0 {
		t.Fatalf("refresh: %d %d", o, c)
	}

	_, b := w.owner.get("/api/v1/alerts?panel_ids=" + w.home.ID)
	r := parse[alertsResp](t, b)
	if r.Open != 1 || len(r.Alerts) != 1 || r.Alerts[0].PanelName != "Home" || !r.Alerts[0].OpenedAt.Equal(t0) || !r.Alerts[0].LastSeenAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("%+v", r)
	}
	_, b = w.owner.get("/api/v1/alerts")
	if r := parse[alertsResp](t, b); r.Open != 2 {
		t.Fatalf("owner sees both: %+v", r)
	}

	// The Work viewer sees only Work, and cannot ask for Home.
	_, vb := w.viewer.get("/api/v1/alerts")
	if r := parse[alertsResp](t, vb); r.Open != 1 || r.Alerts[0].PanelName != "Work" {
		t.Fatalf("viewer: %+v", r)
	}
	if st, bd := w.viewer.get("/api/v1/alerts?panel_ids=" + w.home.ID); st != 403 || errCode(bd) != "panel_forbidden" {
		t.Fatalf("%d %s", st, bd)
	}
	if st, _ := w.h.anon().get("/api/v1/alerts"); st != 401 {
		t.Fatalf("anonymous: %d", st)
	}

	// The home agent comes back: its alert closes, the other stays open; history shows both.
	o, c, _ = w.h.st.ApplyConditions(ctx, kinds, []store.Condition{cond(w.work.ID, "a2", "Агент ноды work-1")}, t0.Add(2*time.Minute))
	if o != 0 || c != 1 {
		t.Fatalf("close: %d %d", o, c)
	}
	_, b = w.owner.get("/api/v1/alerts?panel_ids=" + w.home.ID)
	if r := parse[alertsResp](t, b); r.Open != 0 || len(r.Alerts) != 0 {
		t.Fatalf("open only: %+v", r)
	}
	_, b = w.owner.get("/api/v1/alerts?state=all&panel_ids=" + w.home.ID)
	if r := parse[alertsResp](t, b); len(r.Alerts) != 1 || r.Alerts[0].ResolvedAt == nil {
		t.Fatalf("history: %+v", r)
	}
	// A condition that comes back later opens a new alert, the old one stays in the history.
	o, _, _ = w.h.st.ApplyConditions(ctx, kinds, []store.Condition{cond(w.home.ID, "a1", "Агент ноды home-a"), cond(w.work.ID, "a2", "Агент ноды work-1")}, t0.Add(3*time.Minute))
	if o != 1 {
		t.Fatalf("reopen: %d", o)
	}
	_, b = w.owner.get("/api/v1/alerts?state=all&panel_ids=" + w.home.ID)
	if r := parse[alertsResp](t, b); len(r.Alerts) != 2 || r.Open != 1 {
		t.Fatalf("%+v", r)
	}
}

// The last alert of a kind must close when its condition is gone. With no conditions of that kind left
// there is no list of subjects to keep, and an empty list must not be read as "unknown".
func TestAlertClosesWhenNoConditionOfItsKindRemains(t *testing.T) {
	w := analyzerWorld(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	kinds := []string{store.AlertAgentSilent, store.AlertPanelSync}
	one := store.Condition{PanelID: w.home.ID, Kind: store.AlertAgentSilent, Subject: "a1", Label: "Агент роутера", Detail: "d"}

	if o, _, err := w.h.st.ApplyConditions(ctx, kinds, []store.Condition{one}, t0); err != nil || o != 1 {
		t.Fatalf("open: %d %v", o, err)
	}
	// Nothing is wrong any more, for any kind.
	if _, c, err := w.h.st.ApplyConditions(ctx, kinds, nil, t0.Add(time.Minute)); err != nil || c != 1 {
		t.Fatalf("the alert did not close: closed %d, %v", c, err)
	}
	_, b := w.owner.get("/api/v1/alerts?panel_ids=" + w.home.ID)
	if r := parse[alertsResp](t, b); r.Open != 0 {
		t.Fatalf("%+v", r)
	}
	// A different kind that still has a condition does not keep this one open either.
	if o, _, _ := w.h.st.ApplyConditions(ctx, kinds, []store.Condition{one}, t0.Add(2*time.Minute)); o != 1 {
		t.Fatal(o)
	}
	other := store.Condition{PanelID: w.home.ID, Kind: store.AlertPanelSync, Subject: "p1", Label: "Панель", Detail: "d"}
	if _, c, _ := w.h.st.ApplyConditions(ctx, kinds, []store.Condition{other}, t0.Add(3*time.Minute)); c != 1 {
		t.Fatalf("closed %d", c)
	}
}
