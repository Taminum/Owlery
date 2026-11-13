package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCommandTemplatesAreSharedPerSystemAndChangedOnlyByTheOwner(t *testing.T) {
	w := newWorld(t)
	list := func(q string) []struct {
		ID      string `json:"id"`
		OS      string `json:"os"`
		Name    string `json:"name"`
		Command string `json:"command"`
		Danger  bool   `json:"danger"`
	} {
		st, b := w.viewer.get("/api/v1/command-templates" + q)
		if st != 200 {
			t.Fatalf("%d %s", st, b)
		}
		var out struct {
			Templates []struct {
				ID      string `json:"id"`
				OS      string `json:"os"`
				Name    string `json:"name"`
				Command string `json:"command"`
				Danger  bool   `json:"danger"`
			} `json:"templates"`
		}
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		return out.Templates
	}
	lin := list("?os=linux")
	if len(lin) < 10 || len(list("?os=windows")) != 0 {
		t.Fatalf("the Linux set is there from the start and Windows is empty: %d", len(lin))
	}
	if st, _ := w.viewer.do("POST", "/api/v1/command-templates", map[string]any{"os": "linux", "name": "x", "command": "ls"}); st != 403 {
		t.Errorf("a viewer must not add: %d", st)
	}
	for _, bad := range []map[string]any{
		{"os": "mac", "name": "x", "command": "ls"}, {"os": "linux", "name": " ", "command": "ls"}, {"os": "linux", "name": "x", "command": ""},
		{"os": "linux", "name": "x", "command": strings.Repeat("a", 2001)},
	} {
		if st, b := w.owner.do("POST", "/api/v1/command-templates", bad); st != 422 {
			t.Errorf("%v: %d %s", bad, st, b)
		}
	}
	st, b := w.owner.do("POST", "/api/v1/command-templates", map[string]any{"os": "windows", "name": "Службы 1С", "command": "Get-Service *1C*\r\nGet-Service postgres*", "danger": false})
	if st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	var made struct{ ID string }
	_ = json.Unmarshal(b, &made)
	if st, _ := w.owner.do("POST", "/api/v1/command-templates", map[string]any{"os": "windows", "name": "Службы 1С", "command": "x"}); st != 409 {
		t.Errorf("the same name twice: %d", st)
	}
	win := list("?os=windows")
	if len(win) < 1 || strings.Contains(win[0].Command, "\r") || !strings.Contains(win[0].Command, "\n") {
		t.Fatalf("a command keeps its lines and loses carriage returns: %+v", win)
	}
	if st, _ := w.viewer.do("PATCH", "/api/v1/command-templates/"+made.ID, map[string]any{"name": "n", "command": "c"}); st != 403 {
		t.Errorf("a viewer must not change: %d", st)
	}
	if st, b := w.owner.do("PATCH", "/api/v1/command-templates/"+made.ID, map[string]any{"name": "Службы 1С и база", "command": "Get-Service", "danger": true}); st != 200 {
		t.Fatalf("%d %s", st, b)
	}
	if st, _ := w.owner.do("PATCH", "/api/v1/command-templates/00000000-0000-0000-0000-000000000000", map[string]any{"name": "n", "command": "c"}); st != 404 {
		t.Errorf("a missing one: %d", st)
	}
	if st, _ := w.viewer.do("DELETE", "/api/v1/command-templates/"+made.ID, nil); st != 403 {
		t.Errorf("a viewer must not delete: %d", st)
	}
	if st, _ := w.owner.do("DELETE", "/api/v1/command-templates/"+made.ID, nil); st != 200 {
		t.Errorf("delete: %d", st)
	}
	var n int
	if err := w.h.st.Pool().QueryRow(t.Context(), `SELECT count(*) FROM audit_log WHERE action LIKE 'template.%'`).Scan(&n); err != nil || n < 3 {
		t.Errorf("create, change and delete must be in the audit log: %d %v", n, err)
	}
}
