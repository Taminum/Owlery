package httpapi

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestHealthStatsCountSlowAndFailedAndLeaveOutStreamsAndCancelled(t *testing.T) {
	var h healthStats
	now := time.Date(2026, 11, 12, 10, 30, 0, 0, time.UTC)
	h.note(now, "GET", "/api/v1/servers", 200, 40*time.Millisecond)
	h.note(now, "GET", "/api/v1/analytics/overview", 200, 3*time.Second)
	h.note(now, "GET", "/api/v1/servers/0b6f2c1e-1111-2222-3333-444455556666/alerts", 500, 20*time.Millisecond)
	h.note(now, "GET", "/api/v1/security/terminal", 101, 2*time.Hour) // a terminal is not a slow answer
	h.note(now, "GET", "/api/v1/servers", 499, 5*time.Second)         // the browser went away
	h.note(now, "GET", "/healthz", 200, 5*time.Second)                // not an API call
	v := h.view(now)
	if v.Total != 3 || v.Failed != 1 || v.Slow != 1 {
		t.Fatalf("%+v", v)
	}
	if len(v.Worst) != 2 || v.Worst[0].Ms != 3000 || !strings.Contains(v.Worst[1].Path, "/servers/{id}/alerts") {
		t.Fatalf("%+v", v.Worst)
	}
	if len(v.Hourly) != 24 || v.Hourly[23].Total != 3 {
		t.Fatalf("%+v", v.Hourly)
	}
	// A day later the old counts are gone.
	if later := h.view(now.Add(25 * time.Hour)); later.Total != 0 || len(later.Worst) != 0 {
		t.Fatalf("%+v", later)
	}
}

func TestPanelHealthIsForTheOwnerAndShowsBackupsAndSize(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	if st, _ := w.viewer.get("/api/v1/panel-health"); st != 403 {
		t.Fatalf("a viewer got %d", st)
	}
	if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO panel_backups (bytes, ok) VALUES (900000000, true), (10, false)`); err != nil {
		t.Fatal(err)
	}
	st, b := w.owner.get("/api/v1/panel-health")
	if st != 200 {
		t.Fatalf("%d %s", st, b)
	}
	for _, want := range []string{`"db_bytes":`, `"backups":[`, `"bytes":900000000`, `"backup_stale_hours":30`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("%s is missing: %s", want, b)
		}
	}
}
