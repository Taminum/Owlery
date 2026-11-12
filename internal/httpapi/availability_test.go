package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

func TestAvailabilityKeepsDayTotalsAfterTheSamplesAreGone(t *testing.T) {
	w := newAgentWorld(t)
	ctx := context.Background()
	id := mkVPS(t, w, "box", "203.0.113.91", w.work.ID)
	st := w.h.st
	now := time.Now().UTC()
	for i := 0; i < 5; i++ { // five minutes, three days ago
		at := now.AddDate(0, 0, -3).Add(time.Duration(i) * time.Minute)
		if err := st.SaveHost(ctx, id, secproto.Host{Type: "host", At: at, CPUPct: 1}, at); err != nil {
			t.Fatal(err)
		}
	}
	if st, b := w.owner.get("/api/v1/hosts/" + id + "/availability"); st != 200 || !strings.Contains(string(b), `"days":[]`) {
		t.Fatalf("nothing rolled up yet: %d %s", st, b)
	}
	if err := st.RollupUptime(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := st.PurgeHostSamples(ctx, now.AddDate(0, 0, -1)); err != nil { // the samples go, the totals stay
		t.Fatal(err)
	}
	if err := st.RollupUptime(ctx, now); err != nil { // and a second roll-up does not lower them
		t.Fatal(err)
	}
	code, body := w.owner.get("/api/v1/hosts/" + id + "/availability")
	var out struct {
		Days []struct {
			Day     string `json:"day"`
			Minutes int    `json:"minutes"`
			Of      int    `json:"of"`
		} `json:"days"`
	}
	if code != 200 || json.Unmarshal(body, &out) != nil {
		t.Fatalf("%d %s", code, body)
	}
	days := out.Days
	if len(days) != 4 || days[0].Minutes != 5 || days[0].Of != 1440 || days[1].Minutes != 0 || days[1].Of != 1440 || days[3].Of < 1 || days[3].Of > 1440 {
		t.Fatalf("%+v", days)
	}
	if st, _ := w.viewer.get("/api/v1/hosts/00000000-0000-0000-0000-000000000000/availability"); st != 404 {
		t.Errorf("an unknown machine: %d", st)
	}
}
