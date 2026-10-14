package httpapi

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/store"
	"github.com/Taminum/RemnaScope/internal/xraylog"
)

type rulesResp struct {
	Rules []struct {
		ID       string `json:"id"`
		Pattern  string `json:"pattern"`
		Service  string `json:"service"`
		Category string `json:"category"`
		Source   string `json:"source"`
	} `json:"rules"`
	Categories []string `json:"categories"`
	CanEdit    bool     `json:"can_edit"`
}

func TestCustomRulesOverrideBuiltInsAndDeletingRestoresThem(t *testing.T) {
	w := analyzerWorld(t)
	base := "?" + window + "&panel_ids=" + w.home.ID
	// Add a line for a site the built-in rules know (pixiv.net) next to the sample's unknown one.
	agents, err := w.h.st.ListAgents(context.Background(), store.Scope{All: true}, w.home.ID)
	if err != nil || len(agents) == 0 {
		t.Fatal(err)
	}
	ev := &xraylog.Event{Time: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC), ClientIP: netip.MustParseAddr("198.51.100.7"), Protocol: "tcp",
		DestHost: "www.pixiv.net", DestPort: 443, InboundTag: "Steal", OutboundTag: "DIRECT", Arrow: ">>", Email: "2"}
	if _, err := w.h.st.CommitBatch(context.Background(), store.Commit{AgentID: agents[0].ID, Lines: []store.Line{{Seq: 121, Event: ev, FP: []byte{1}}}}); err != nil {
		t.Fatal(err)
	}
	known := &siteOut{Site: "pixiv.net", Category: "Аниме и арт"}
	unknown := &siteOut{Site: "example.test"}
	catOf := func(site string) string {
		_, b := w.owner.get("/api/v1/analytics/sites" + base + "&q=" + site)
		for _, r := range parse[sitesResp](t, b).Rows {
			if r.Site == site {
				return r.Category
			}
		}
		return "?"
	}
	oldCat := known.Category
	if got := catOf(known.Site); got != oldCat {
		t.Fatalf("before: %q", got)
	}

	// An unknown site gets a category from a rule added by the owner.
	st, b := w.owner.do("POST", "/api/v1/rules", map[string]string{"pattern": unknown.Site, "category": "Мои сайты"})
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	if got := catOf(unknown.Site); got != "Мои сайты" {
		t.Fatalf("the new rule did not apply: %q", got)
	}
	// A custom rule beats a built-in one for the same domain, and deleting it brings the built-in back.
	st, b = w.owner.do("POST", "/api/v1/rules", map[string]string{"pattern": known.Site, "service": "Мой сервис", "category": "Переопределено"})
	if st != 201 {
		t.Fatalf("override: %d %s", st, b)
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &created)
	if got := catOf(known.Site); got != "Переопределено" {
		t.Fatalf("override did not win: %q", got)
	}
	if st, _ := w.owner.do("DELETE", "/api/v1/rules/"+created.ID, nil); st != 204 {
		t.Fatalf("delete: %d", st)
	}
	if got := catOf(known.Site); got != oldCat {
		t.Fatalf("deleting the custom rule must restore %q, got %q", oldCat, got)
	}

	// Listing shows only custom rules, plus the categories in use for the picker.
	_, lb := w.owner.get("/api/v1/rules")
	lr := parse[rulesResp](t, lb)
	if !lr.CanEdit || len(lr.Rules) != 1 || lr.Rules[0].Pattern != unknown.Site || lr.Rules[0].Source != "custom" || len(lr.Categories) < 5 {
		t.Fatalf("%+v", lr)
	}
	// Built-in rules cannot be deleted through the API.
	if st, _ := w.owner.do("DELETE", "/api/v1/rules/00000000-0000-4000-8000-000000000001", nil); st != 404 {
		t.Fatalf("delete of something that is not a custom rule: %d", st)
	}
}

func TestRulesAreOwnerOnlyAndValidated(t *testing.T) {
	w := analyzerWorld(t)
	for _, c := range []*client{w.viewer, w.op, w.adm} {
		if st, _ := c.do("POST", "/api/v1/rules", map[string]string{"pattern": "example.com", "category": "X"}); st != 403 {
			t.Errorf("a non-owner created a rule: %d", st)
		}
		if st, _ := c.do("DELETE", "/api/v1/rules/00000000-0000-4000-8000-000000000001", nil); st != 403 {
			t.Errorf("a non-owner deleted a rule: %d", st)
		}
		st, b := c.get("/api/v1/rules")
		if st != 200 || parse[rulesResp](t, b).CanEdit {
			t.Errorf("a non-owner may read rules but must not be told it can edit: %d", st)
		}
	}
	for name, body := range map[string]map[string]string{
		"not a domain":   {"pattern": "not a domain", "category": "X"},
		"an IP":          {"pattern": "1.2.3.4", "category": "X"},
		"a url":          {"pattern": "https://example.com/x", "category": "X"},
		"bare tld":       {"pattern": "com", "category": "X"},
		"no category":    {"pattern": "example.com", "category": ""},
		"long category":  {"pattern": "example.com", "category": strings.Repeat("я", 65)},
		"control in cat": {"pattern": "example.com", "category": "a\u0007b"},
		"wildcard":       {"pattern": "*.example.com", "category": "X"},
	} {
		if st, b := w.owner.do("POST", "/api/v1/rules", body); st != 422 {
			t.Errorf("%s: %d %s", name, st, b)
		}
	}
	if st, _ := w.h.anon().do("POST", "/api/v1/rules", map[string]string{"pattern": "example.com", "category": "X"}); st != 401 && st != 403 {
		t.Errorf("anonymous: %d", st)
	}
}
