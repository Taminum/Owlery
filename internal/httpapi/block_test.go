package httpapi

import "testing"

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
