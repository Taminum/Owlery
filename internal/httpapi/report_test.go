package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMonthReportIsForTheOwnerAndSendingNeedsAChannel(t *testing.T) {
	w := newWorld(t)
	if st, _ := w.viewer.get("/api/v1/reports/month"); st != 403 {
		t.Fatalf("a viewer must not read it: %d", st)
	}
	st, b := w.owner.get("/api/v1/reports/month")
	if st != 200 {
		t.Fatalf("%d %s", st, b)
	}
	var rep struct {
		Cur struct {
			Month  string          `json:"month"`
			Worst  json.RawMessage `json:"worst"`
			Events json.RawMessage `json:"events"`
			Paid   json.RawMessage `json:"paid"`
		} `json:"cur"`
		Prev struct {
			Month string `json:"month"`
		} `json:"prev"`
		Upcoming json.RawMessage `json:"upcoming"`
	}
	if err := json.Unmarshal(b, &rep); err != nil || rep.Cur.Month != time.Now().UTC().Format("2006-01") || rep.Prev.Month == "" {
		t.Fatalf("%v %s", err, b)
	}
	for _, f := range []json.RawMessage{rep.Cur.Worst, rep.Cur.Events, rep.Cur.Paid, rep.Upcoming} {
		if string(f) != "[]" {
			t.Errorf("an empty list must be [] and not null: %s", b)
		}
	}
	for _, q := range []string{"?month=2026-13", "?month=abc", "?month=2999-01"} {
		if st, _ := w.owner.get("/api/v1/reports/month" + q); st != 422 {
			t.Errorf("%s: %d", q, st)
		}
	}
	if st, b := w.owner.get("/api/v1/reports/month?month=2026-10"); st != 200 || !strings.Contains(string(b), `"month":"2026-10"`) {
		t.Errorf("a past month: %d %s", st, b)
	}
	if st, _ := w.viewer.do("POST", "/api/v1/reports/month/send", nil); st != 403 {
		t.Errorf("a viewer must not send: %d", st)
	}
	if st, b := w.owner.do("POST", "/api/v1/reports/month/send", nil); st != 409 || errCode(b) != "no_channels" {
		t.Errorf("with no channel: %d %s", st, b)
	}
}
