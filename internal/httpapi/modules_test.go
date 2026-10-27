package httpapi

import "testing"

func TestModulesOnByDefaultOwnerTurnsThemOff(t *testing.T) {
	w := newAgentWorld(t)
	type list struct {
		Modules []struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		} `json:"modules"`
	}
	state := func() map[string]bool {
		_, b := w.viewer.get("/api/v1/modules")
		out := map[string]bool{}
		for _, m := range parse[list](t, b).Modules {
			out[m.ID] = m.Enabled
		}
		return out
	}
	if s := state(); len(s) != 5 || !s["awg"] || !s["remnawave"] {
		t.Fatalf("everything starts on: %v", s)
	}
	if st, _ := w.adm.do("PUT", "/api/v1/modules/awg", map[string]any{"enabled": false}); st != 403 {
		t.Errorf("an admin may not switch modules: %d", st)
	}
	if st, _ := w.owner.do("PUT", "/api/v1/modules/toaster", map[string]any{"enabled": false}); st != 404 {
		t.Errorf("unknown module: %d", st)
	}
	if st, b := w.owner.do("PUT", "/api/v1/modules/awg", map[string]any{"enabled": false}); st != 200 {
		t.Fatalf("owner: %d %s", st, b)
	}
	if s := state(); s["awg"] || !s["billing"] {
		t.Fatalf("awg off, the rest on: %v", s)
	}
	if st, _ := w.owner.do("PUT", "/api/v1/modules/awg", map[string]any{"enabled": true}); st != 200 || !state()["awg"] {
		t.Fatalf("back on: %d", st)
	}
}
