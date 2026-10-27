package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/autoclassify"
	"github.com/Taminum/Owlery/internal/gemini"
	"github.com/Taminum/Owlery/internal/store"
)

const apiTestKey = "AIzaHTTPTESTKEY0123456789abcdef"

func autoWorld(t *testing.T, haveKey bool) *world {
	t.Helper()
	w := analyzerWorld(t)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/models") {
			_, _ = rw.Write([]byte(`{"models":[{"name":"models/gemini-test-flash","displayName":"Flash","supportedGenerationMethods":["generateContent"]},{"name":"models/gemini-a-pro","displayName":"Pro","supportedGenerationMethods":["generateContent"]}]}`))
			return
		}
		var body struct {
			Contents []struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"contents"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, rest, _ := strings.Cut(body.Contents[0].Parts[0].Text, "Domains:\n")
		var rows []map[string]any
		for _, d := range strings.Fields(rest) {
			rows = append(rows, map[string]any{"domain": d, "category_id": 1, "service_name": nil, "confidence": 0.5, "reason": "guess"})
		}
		b, _ := json.Marshal(rows)
		_ = json.NewEncoder(rw).Encode(map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"parts": []any{map[string]any{"text": string(b)}}}, "finishReason": "STOP"}},
			"usageMetadata": map[string]any{"promptTokenCount": 10, "candidatesTokenCount": 5}})
	}))
	t.Cleanup(srv.Close)
	keyPath := filepath.Join(t.TempDir(), "key")
	content := ""
	if haveKey {
		content = apiTestKey
	}
	_ = os.WriteFile(keyPath, []byte(content), 0o600)
	cl := &gemini.Client{Endpoint: srv.URL, KeyFile: keyPath}
	w.h.srv.Gemini = cl
	w.h.srv.Auto = &autoclassify.Runner{Store: w.h.st, Client: cl, Sleep: func(context.Context, time.Duration) {}}
	// unknown registrable domains to look at
	agents, _ := w.h.st.ListAgents(context.Background(), store.Scope{All: true}, w.home.ID)
	nodes, _ := w.h.st.ListNodes(context.Background(), store.Scope{All: true}, w.home.ID, false)
	for i := 0; i < 20; i++ {
		_, err := w.h.st.Pool().Exec(context.Background(), `INSERT INTO connection_events (event_id, panel_id, node_id, agent_id, ts, destination_host, destination_port, protocol, raw_fingerprint, site)
			VALUES (gen_random_uuid(), $1, $2, $3, now(), $4, 443, 'tcp', '\x01', $5)`, w.home.ID, nodes[0].ID, agents[0].ID, fmt.Sprintf("www.unk%02d.com", i), fmt.Sprintf("unk%02d.com", i))
		if err != nil {
			t.Fatal(err)
		}
	}
	return w
}

func TestAutoclassifyIsOwnerOnlyAndNeverShowsTheKey(t *testing.T) {
	w := autoWorld(t, true)
	for _, c := range []*client{w.viewer, w.op, w.adm} {
		for _, p := range [][2]string{{"GET", "/api/v1/autoclassify"}, {"GET", "/api/v1/autoclassify/models"}, {"GET", "/api/v1/autoclassify/dryrun"}} {
			if st, _ := c.do(p[0], p[1], nil); st != 403 {
				t.Errorf("%s %s: %d", p[0], p[1], st)
			}
		}
		if st, _ := c.do("PUT", "/api/v1/autoclassify/settings", map[string]any{"model": "gemini-test-flash", "batch_size": 15, "daily_limit": 100}); st != 403 {
			t.Errorf("settings: %d", st)
		}
		if st, _ := c.do("POST", "/api/v1/autoclassify/dryrun", map[string]any{}); st != 403 {
			t.Errorf("dryrun: %d", st)
		}
	}
	if st, _ := w.h.anon().get("/api/v1/autoclassify"); st != 401 {
		t.Fatalf("anonymous: %d", st)
	}
	for _, p := range []string{"/api/v1/autoclassify", "/api/v1/autoclassify/models", "/api/v1/autoclassify/dryrun"} {
		st, b := w.owner.get(p)
		if st != 200 || strings.Contains(string(b), apiTestKey) || strings.Contains(strings.ToLower(string(b)), "aiza") {
			t.Fatalf("%s: %d, and the key must never appear in an answer: %s", p, st, b)
		}
	}
	_, b := w.owner.get("/api/v1/autoclassify")
	var status struct {
		KeyPresent bool `json:"key_present"`
		Running    bool `json:"running"`
		Categories int  `json:"categories"`
		Settings   struct {
			Enabled bool `json:"enabled"`
		} `json:"settings"`
	}
	_ = json.Unmarshal(b, &status)
	if !status.KeyPresent || status.Running || status.Categories < 10 || status.Settings.Enabled {
		t.Fatalf("%s", b)
	}
}

func TestAutoclassifySettingsAreValidatedAndModelsComeFromTheProvider(t *testing.T) {
	w := autoWorld(t, true)
	put := func(m map[string]any) int { st, _ := w.owner.do("PUT", "/api/v1/autoclassify/settings", m); return st }
	for name, m := range map[string]map[string]any{
		"bad model":   {"model": "../x", "batch_size": 15, "daily_limit": 100},
		"uppercase":   {"model": "Gemini Flash", "batch_size": 15, "daily_limit": 100},
		"small batch": {"model": "gemini-test-flash", "batch_size": 2, "daily_limit": 100},
		"huge batch":  {"model": "gemini-test-flash", "batch_size": 99, "daily_limit": 100},
		"neg limit":   {"model": "gemini-test-flash", "batch_size": 15, "daily_limit": -1},
		"huge limit":  {"model": "gemini-test-flash", "batch_size": 15, "daily_limit": 999999},
	} {
		if st := put(m); st != 422 {
			t.Errorf("%s: %d", name, st)
		}
	}
	if st := put(map[string]any{"model": "gemini-test-flash", "batch_size": 12, "daily_limit": 250}); st != 200 {
		t.Fatalf("a good change: %d", st)
	}
	_, b := w.owner.get("/api/v1/autoclassify")
	if !strings.Contains(string(b), `"model":"gemini-test-flash"`) || !strings.Contains(string(b), `"daily_limit":250`) {
		t.Fatalf("%s", b)
	}
	_, mb := w.owner.get("/api/v1/autoclassify/models")
	var ms struct {
		Models []gemini.Model `json:"models"`
		Error  string         `json:"error"`
	}
	_ = json.Unmarshal(mb, &ms)
	if len(ms.Models) != 2 || ms.Models[0].Name != "gemini-a-pro" || ms.Error != "" {
		t.Fatalf("%s", mb)
	}
}

func TestDryRunEndToEndOverHTTPWithNothingApplied(t *testing.T) {
	w := autoWorld(t, true)
	if st, b := w.owner.do("POST", "/api/v1/autoclassify/dryrun", map[string]any{}); st != 422 || errCode(b) != "no_model" {
		t.Fatalf("no model chosen yet: %d %s", st, b)
	}
	_, _ = w.owner.do("PUT", "/api/v1/autoclassify/settings", map[string]any{"model": "gemini-test-flash", "batch_size": 10, "daily_limit": 100})
	var rulesBefore int
	_ = w.h.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM service_rules`).Scan(&rulesBefore)
	st, b := w.owner.do("POST", "/api/v1/autoclassify/dryrun", map[string]any{})
	if st != 202 {
		t.Fatalf("%d %s", st, b)
	}
	var latest struct {
		Run *struct {
			State    string `json:"state"`
			Requests int    `json:"requests"`
		} `json:"run"`
		Items   []store.DryRunItem `json:"items"`
		Summary dryRunSummary      `json:"summary"`
	}
	for i := 0; i < 200; i++ {
		_, lb := w.owner.get("/api/v1/autoclassify/dryrun")
		_ = json.Unmarshal(lb, &latest)
		if latest.Run != nil && latest.Run.State != "running" {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if latest.Run == nil || latest.Run.State != "done" || latest.Run.Requests != 2 || len(latest.Items) != 20 {
		t.Fatalf("%+v items %d", latest.Run, len(latest.Items))
	}
	s := latest.Summary
	if s.Total != 20 || s.Valid != 20 || s.Invalid != 0 || s.LowConf != 20 || len(s.ByCategory) != 1 {
		t.Fatalf("%+v", s) // confidence 0.5 is below the "guess" line
	}
	var rulesAfter int
	_ = w.h.st.Pool().QueryRow(context.Background(), `SELECT count(*) FROM service_rules`).Scan(&rulesAfter)
	if rulesAfter != rulesBefore {
		t.Fatalf("the dry run changed the rules: %d -> %d", rulesBefore, rulesAfter)
	}
	// the sites are still shown as not classified
	_, sb := w.owner.get("/api/v1/analytics/sites?" + window + "&panel_ids=" + w.home.ID + "&q=unk0")
	if !strings.Contains(string(sb), `"classified":false`) {
		t.Fatalf("%s", sb)
	}
}

func TestDryRunWithoutAKeyIsRefusedClearly(t *testing.T) {
	w := autoWorld(t, false)
	_, _ = w.owner.do("PUT", "/api/v1/autoclassify/settings", map[string]any{"model": "gemini-test-flash", "batch_size": 10, "daily_limit": 100})
	if st, b := w.owner.do("POST", "/api/v1/autoclassify/dryrun", map[string]any{}); st != 422 || errCode(b) != "no_key" {
		t.Fatalf("%d %s", st, b)
	}
	_, mb := w.owner.get("/api/v1/autoclassify/models")
	if !strings.Contains(string(mb), `"error":"no_key"`) {
		t.Fatalf("%s", mb)
	}
	_, sb := w.owner.get("/api/v1/autoclassify")
	if !strings.Contains(string(sb), `"key_present":false`) {
		t.Fatalf("%s", sb)
	}
}

func TestSwitchingOnNeedsConfirmationAModelAndAKeyAndIsOwnerOnly(t *testing.T) {
	w := autoWorld(t, true)
	on := func(c *client, confirmed bool) int {
		st, _ := c.do("PUT", "/api/v1/autoclassify/enabled", map[string]any{"enabled": true, "confirmed": confirmed})
		return st
	}
	for _, c := range []*client{w.viewer, w.op, w.adm} {
		if on(c, true) != 403 {
			t.Fatal("a non-owner switched it on")
		}
		if st, _ := c.do("POST", "/api/v1/autoclassify/backfill", map[string]any{}); st != 403 {
			t.Fatalf("backfill: %d", st)
		}
	}
	if on(w.owner, true) != 422 { // no model yet
		t.Fatal("switched on without a model")
	}
	if st, _ := w.owner.do("PUT", "/api/v1/autoclassify/settings", map[string]any{"model": "gemini-test-flash", "batch_size": 15, "daily_limit": 100}); st != 200 {
		t.Fatal(st)
	}
	if on(w.owner, false) != 422 {
		t.Fatal("switched on without confirming that names are sent out")
	}
	if on(w.owner, true) != 200 {
		t.Fatal("could not switch on")
	}
	_, b := w.owner.get("/api/v1/autoclassify")
	var s struct {
		Settings struct {
			Enabled bool `json:"enabled"`
		} `json:"settings"`
		Queue struct {
			Backfill string `json:"backfill"`
		} `json:"queue"`
	}
	_ = json.Unmarshal(b, &s)
	if !s.Settings.Enabled || s.Queue.Backfill != "idle" || strings.Contains(string(b), apiTestKey) {
		t.Fatalf("%s", b)
	}
	if st, _ := w.owner.do("POST", "/api/v1/autoclassify/backfill", map[string]any{}); st != 200 {
		t.Fatal(st)
	}
	if st, _ := w.owner.do("PUT", "/api/v1/autoclassify/enabled", map[string]any{"enabled": false}); st != 200 {
		t.Fatal("could not switch off")
	}
	if enabled, _ := w.h.st.AutoSettings(context.Background()); enabled.Enabled {
		t.Fatal("still on")
	}
}

func TestSitesShowWhereEachClassificationCameFrom(t *testing.T) {
	w := autoWorld(t, true)
	ctx := context.Background()
	_, _ = w.h.st.Pool().Exec(ctx, `UPDATE connection_events SET ts = '2026-10-09T12:00:00Z' WHERE site LIKE 'unk%'`)
	if _, err := w.h.st.ApplyAutoRule(ctx, store.AutoRule{Domain: "unk00.com", Category: "Игры", Model: "m", Score: 0.9, Reason: "r"}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.h.st.ApplyAutoRule(ctx, store.AutoRule{Domain: "unk01.com", Category: "Игры", Model: "m", Score: 0.3}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.h.st.UpsertCustomRule(ctx, "unk02.com", "Mine", "Мои сайты", "high", ""); err != nil {
		t.Fatal(err)
	}
	_, b := w.owner.get("/api/v1/analytics/sites?" + window + "&panel_ids=" + w.home.ID + "&limit=100")
	var out struct {
		Rows []struct {
			Site   string `json:"site"`
			Origin string `json:"origin"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%s", b)
	}
	got := map[string]string{}
	for _, r := range out.Rows {
		got[r.Site] = r.Origin
	}
	if got["unk00.com"] != "auto" || got["unk01.com"] != "guess" || got["unk02.com"] != "manual" || got["unk03.com"] != "" {
		t.Fatalf("%v", got)
	}
}
