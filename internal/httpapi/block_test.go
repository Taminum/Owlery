package httpapi

import (
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

func TestBlockSettingsStartAtTheDefaultsAndAreCheckedAndGuarded(t *testing.T) {
	w := newAgentWorld(t)
	id := mkVPS(t, w, "autocad", "203.0.113.40", w.work.ID)
	type view struct {
		Settings struct {
			Mode      string   `json:"mode"`
			Threshold int      `json:"threshold"`
			WindowMin int      `json:"window_min"`
			TTLHours  int      `json:"ttl_hours"`
			Whitelist []string `json:"whitelist"`
		} `json:"settings"`
		Supported bool `json:"supported"`
		CanBlock  bool `json:"can_block"`
		CanEdit   bool `json:"can_edit"`
	}

	st, b := w.owner.get("/api/v1/servers/" + id + "/block")
	if st != 200 {
		t.Fatalf("get: %d %s", st, b)
	}
	got := parse[view](t, b)
	if got.Settings.Mode != "watch" || got.Settings.Threshold != 5 || got.Settings.WindowMin != 10 || got.Settings.TTLHours != 24 || got.Supported || got.CanBlock || !got.CanEdit {
		t.Errorf("defaults: %+v", got)
	}

	put := map[string]any{"mode": "block", "threshold": 3, "window_min": 5, "ttl_hours": 48, "whitelist": []string{"198.51.100.7", "203.0.113.0/24", "198.51.100.7"}, "share": true}
	st, b = w.owner.do("PUT", "/api/v1/servers/"+id+"/block", put)
	if st != 200 {
		t.Fatalf("put: %d %s", st, b)
	}
	got = parse[view](t, b)
	if got.Settings.Mode != "block" || got.Settings.Threshold != 3 || len(got.Settings.Whitelist) != 2 || got.Settings.Whitelist[0] != "198.51.100.7/32" {
		t.Errorf("saved: %+v", got.Settings)
	}

	for name, bad := range map[string]map[string]any{
		"mode":      {"mode": "kill", "threshold": 5, "window_min": 10, "ttl_hours": 24, "whitelist": []string{}},
		"threshold": {"mode": "block", "threshold": 1, "window_min": 10, "ttl_hours": 24, "whitelist": []string{}},
		"address":   {"mode": "block", "threshold": 5, "window_min": 10, "ttl_hours": 24, "whitelist": []string{"not-an-address"}},
	} {
		if st, b := w.owner.do("PUT", "/api/v1/servers/"+id+"/block", bad); st != 422 || errCode(b) != "invalid_settings" {
			t.Errorf("a bad %s must be refused: %d %s", name, st, b)
		}
	}

	// Somebody who can only look cannot change it, and a machine with no agent connected cannot lift a block.
	if st, _ := w.viewer.do("PUT", "/api/v1/servers/"+id+"/block", put); st != 403 {
		t.Errorf("a viewer must not change the settings: %d", st)
	}
	if st, b := w.owner.do("POST", "/api/v1/servers/"+id+"/block/unblock", map[string]any{"ip": "203.0.113.5"}); st != 409 {
		t.Errorf("no agent connected: %d %s", st, b)
	}
	if st, b := w.owner.do("POST", "/api/v1/servers/"+id+"/block/unblock", map[string]any{"ip": "nope"}); st != 422 {
		t.Errorf("not an address: %d %s", st, b)
	}
}

func TestSharedBlocksArePassedOnOnceAndNotBackToTheirSource(t *testing.T) {
	w := newAgentWorld(t)
	a := mkVPS(t, w, "autocad", "203.0.113.41", w.work.ID)
	b := mkVPS(t, w, "btr", "203.0.113.42", w.work.ID)
	st := w.h.st
	soon := time.Now().Add(time.Hour)

	if fresh, err := st.ShareBlock(ctx, a, "198.51.100.77", time.Now(), &soon); err != nil || !fresh {
		t.Fatalf("a new block is news: %v %v", fresh, err)
	}
	if fresh, _ := st.ShareBlock(ctx, a, "198.51.100.77", time.Now(), &soon); fresh {
		t.Error("the same block reported again is not news")
	}
	if list, _ := st.ActiveSharedBlocks(ctx, b); len(list) != 1 || list[0].IP != "198.51.100.77" {
		t.Errorf("the other machine is owed it: %+v", list)
	}
	if list, _ := st.ActiveSharedBlocks(ctx, a); len(list) != 0 {
		t.Errorf("the machine that made it is not told its own block: %+v", list)
	}
	if peers, _ := st.SharePeers(ctx, a); len(peers) != 1 || peers[0] != b {
		t.Errorf("peers: %v", peers)
	}

	// Somebody who leaves the shared list neither gets nor gives.
	if err := st.PutBlockSettings(ctx, b, store.BlockSettings{Mode: "block", Threshold: 5, WindowMin: 10, TTLHours: 24, Share: false}); err != nil {
		t.Fatal(err)
	}
	if st.ShareOn(ctx, b) {
		t.Error("a machine that turned sharing off is out")
	}
	if peers, _ := st.SharePeers(ctx, a); len(peers) != 0 {
		t.Errorf("a machine that turned sharing off is not a peer: %v", peers)
	}

	// A block that ended may be shared again; an unblocked address leaves the list.
	past := time.Now().Add(-time.Minute)
	if _, err := w.h.st.Pool().Exec(ctx, `UPDATE security_shared_blocks SET until=$1`, past); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.ActiveSharedBlocks(ctx, b); len(list) != 0 {
		t.Errorf("an ended block is not owed: %+v", list)
	}
	if fresh, _ := st.ShareBlock(ctx, a, "198.51.100.77", time.Now(), &soon); !fresh {
		t.Error("an address whose block ended can be blocked again")
	}
	_ = st.DropSharedBlock(ctx, "198.51.100.77")
	if list, _ := st.ActiveSharedBlocks(ctx, b); len(list) != 0 {
		t.Errorf("an unblocked address is off the list: %+v", list)
	}
}
