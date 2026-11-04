package httpapi

import (
	"context"
	"testing"
)

func TestServerCardCarriesTheContainersOnlyWhileTheListIsFresh(t *testing.T) {
	w := newAgentWorld(t)
	id := mkVPS(t, w, "exit-nl", "203.0.113.31", w.work.ID)
	ctx := context.Background()

	card := func() *struct {
		Containers []struct {
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"containers"`
	} {
		st, body := w.owner.get("/api/v1/servers/" + id)
		if st != 200 {
			t.Fatalf("card: %d %s", st, body)
		}
		return parse[struct {
			Docker *struct {
				Containers []struct {
					Name  string `json:"name"`
					State string `json:"state"`
				} `json:"containers"`
			} `json:"docker"`
		}](t, body).Docker
	}

	if card() != nil {
		t.Error("a machine whose agent has not listed containers has none to show")
	}
	put := func(received string) {
		t.Helper()
		if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO security_snapshot_state (vps_id, category, status, source_hash, observed_at, received_at, data)
			VALUES ($1, 'docker', 'ok', 'd', now(), `+received+`, '{"containers":[{"id":"aaaaaaaaaaaa","name":"nginx","image":"nginx","state":"running","ports":[]}]}')
			ON CONFLICT (vps_id, category) DO UPDATE SET received_at = EXCLUDED.received_at`, id); err != nil {
			t.Fatal(err)
		}
	}
	put("now()")
	if got := card(); got == nil || len(got.Containers) != 1 || got.Containers[0].Name != "nginx" {
		t.Errorf("containers: %+v", got)
	}
	put("now() - interval '1 hour'")
	if card() != nil {
		t.Error("an old list says nothing about now")
	}
}
