package httpapi

import "testing"

func TestServerCardCarriesWhatTheAgentReadAboutTheHardware(t *testing.T) {
	w := newAgentWorld(t)
	id := mkVPS(t, w, "home-pc", "203.0.113.30", w.work.ID)

	card := func() struct {
		Hardware *struct {
			Vendor string `json:"vendor"`
			CPU    struct {
				Cores int `json:"cores"`
			} `json:"cpu"`
			Disks []struct {
				Kind string `json:"kind"`
			} `json:"disks"`
		} `json:"hardware"`
	} {
		st, body := w.owner.get("/api/v1/servers/" + id)
		if st != 200 {
			t.Fatalf("card: %d %s", st, body)
		}
		return parse[struct {
			Hardware *struct {
				Vendor string `json:"vendor"`
				CPU    struct {
					Cores int `json:"cores"`
				} `json:"cpu"`
				Disks []struct {
					Kind string `json:"kind"`
				} `json:"disks"`
			} `json:"hardware"`
		}](t, body)
	}

	if card().Hardware != nil {
		t.Error("a machine whose agent has not read its hardware has none to show")
	}
	if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO security_snapshot_state (vps_id, category, status, source_hash, observed_at, received_at, data)
		VALUES ($1, 'hardware', 'ok', 'h', now(), now(), '{"vendor":"ASUS","cpu":{"cores":8},"disks":[{"model":"x","size":1,"kind":"nvme"}],"gpus":[],"nics":[]}')`, id); err != nil {
		t.Fatal(err)
	}
	got := card().Hardware
	if got == nil || got.Vendor != "ASUS" || got.CPU.Cores != 8 || len(got.Disks) != 1 || got.Disks[0].Kind != "nvme" {
		t.Errorf("hardware: %+v", got)
	}
}
