package autoclassify

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/gemini"
	"github.com/Taminum/RemnaScope/internal/store"
	"github.com/Taminum/RemnaScope/internal/store/storetest"
)

var ctx = context.Background()

// fake plays the Gemini service. The test decides what each call answers.
type fake struct {
	mu      sync.Mutex
	calls   int
	prompts []string
	reply   func(call int, domains []string) (status int, headers map[string]string, text string)
}

func domainsOf(prompt string) []string {
	_, rest, _ := strings.Cut(prompt, "Domains:\n")
	var out []string
	for _, l := range strings.Split(rest, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (f *fake) handler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Contents []struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"contents"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	prompt := body.Contents[0].Parts[0].Text
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.prompts = append(f.prompts, prompt)
	f.mu.Unlock()
	status, hdr, text := f.reply(n, domainsOf(prompt))
	for k, v := range hdr {
		w.Header().Set(k, v)
	}
	if status != 200 {
		w.WriteHeader(status)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"candidates":    []any{map[string]any{"content": map[string]any{"parts": []any{map[string]any{"text": text}}}, "finishReason": "STOP"}},
		"usageMetadata": map[string]any{"promptTokenCount": 100, "candidatesTokenCount": 40},
	})
}

func answerAll(domains []string, skip map[string]bool) string {
	var rows []map[string]any
	for _, d := range domains {
		if skip[d] {
			continue
		}
		rows = append(rows, map[string]any{"domain": d, "category_id": 1, "service_name": nil, "confidence": 0.8, "reason": "looks like a video site"})
	}
	b, _ := json.Marshal(rows)
	return string(b)
}

type env struct {
	st   *store.Store
	run  *Runner
	f    *fake
	cats []string
}

func newEnv(t *testing.T, sites int, reply func(call int, domains []string) (int, map[string]string, string)) *env {
	t.Helper()
	st := storetest.New(t)
	p, err := st.CreatePanel(ctx, store.NewPanelID(), store.PanelInput{Name: "home", BaseURL: "https://home.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_, _ = st.UpsertNodes(ctx, p.ID, now, []store.NodeRecord{{RemoteUUID: "n", Name: "node"}})
	nodes, _ := st.ListNodes(ctx, store.Scope{All: true}, p.ID, false)
	a, err := st.CreateAgent(ctx, store.Scope{All: true}, p.ID, nodes[0].ID, "a", "node", "", store.HashAgentSecret("s"))
	if err != nil {
		t.Fatal(err)
	}
	// Unknown registrable domains with decreasing traffic, and things that must never be sent.
	pool := st.Pool()
	add := func(site string, n int) {
		_, err := pool.Exec(ctx, `INSERT INTO connection_events (event_id, panel_id, node_id, agent_id, ts, destination_host, destination_port, protocol, raw_fingerprint, site)
			SELECT gen_random_uuid(), $1, $2, $3, now(), $4, 443, 'tcp', '\x01', $5 FROM generate_series(1, $6)`, p.ID, nodes[0].ID, a.ID, "www."+site, site, n)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < sites; i++ {
		add(fmt.Sprintf("unknown-%03d.com", i), 200-i)
	}
	add("192.168.1.1", 50)
	add("localhost", 40)
	add("router.lan", 30)
	add("pixiv.net", 20) // known to the built-in rules
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	_ = os.WriteFile(keyPath, []byte("AIzaTESTKEY0123456789abcdef"), 0o600)
	f := &fake{reply: reply}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	_, _ = st.SetAutoSettings(ctx, "gemini-test-flash", 15, 300, "")
	names, _ := st.RuleCategories(ctx)
	return &env{st: st, f: f, cats: names, run: &Runner{Store: st, Client: &gemini.Client{Endpoint: srv.URL, KeyFile: keyPath},
		Sleep: func(context.Context, time.Duration) {}, Rand: rand.New(rand.NewPCG(1, 2))}}
}

func (e *env) wait(t *testing.T) store.DryRun {
	t.Helper()
	for i := 0; i < 300; i++ {
		if !e.run.Running() {
			r, err := e.st.LatestDryRun(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if r.State != "running" {
				return r
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the dry run did not finish")
	return store.DryRun{}
}

func TestDryRunSamplesOnlyEligibleUnknownDomainsAndAppliesNothing(t *testing.T) {
	e := newEnv(t, 130, func(_ int, d []string) (int, map[string]string, string) { return 200, nil, answerAll(d, nil) })
	var rulesBefore int
	_ = e.st.Pool().QueryRow(ctx, `SELECT count(*) FROM service_rules`).Scan(&rulesBefore)

	id, err := e.run.Start(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	run := e.wait(t)
	if run.ID != id || run.State != "done" || run.Requested != SampleSize || run.Requests != 7 || run.TokensIn != 700 || run.TokensOut != 280 {
		t.Fatalf("%+v", run) // 100 domains in batches of 15: 7 requests
	}
	items, _ := e.st.DryRunItems(ctx, id)
	if len(items) != SampleSize {
		t.Fatalf("%d items", len(items))
	}
	top, random := 0, 0
	for _, it := range items {
		if !it.Valid || it.Category == "" || it.Confidence < 0.79 || it.Confidence > 0.81 {
			t.Fatalf("%+v", it)
		}
		for _, bad := range []string{"192.168.1.1", "localhost", "router.lan", "pixiv.net"} {
			if it.Site == bad {
				t.Fatalf("%s must never be sampled", bad)
			}
		}
		if it.PickedBy == "top" {
			top++
		} else {
			random++
		}
	}
	if top != TopShare || random != SampleSize-TopShare {
		t.Fatalf("top %d random %d", top, random)
	}
	if items[0].Site != "unknown-000.com" || items[0].Connections != 200 {
		t.Fatalf("the busiest domain comes first: %+v", items[0])
	}
	// What was sent holds domains and category names, and nothing else.
	for _, p := range e.f.prompts {
		for _, forbidden := range []string{"192.168", "localhost", "pixiv", "connections", "www."} {
			if strings.Contains(p, forbidden) {
				t.Fatalf("the prompt carries %q:\n%s", forbidden, p)
			}
		}
	}
	// Nothing was applied: no rule was added, and the unknown domains are still unknown.
	var rulesAfter int
	_ = e.st.Pool().QueryRow(ctx, `SELECT count(*) FROM service_rules`).Scan(&rulesAfter)
	if rulesAfter != rulesBefore {
		t.Fatalf("a dry run changed the rules: %d -> %d", rulesBefore, rulesAfter)
	}
	if u, _ := e.st.UnknownSites(ctx, 1000); len(u) < 130 {
		t.Fatalf("the sites must still be unknown: %d", len(u))
	}
}

func TestOnlyWhatIsMissingIsAskedAgain(t *testing.T) {
	e := newEnv(t, 12, func(call int, d []string) (int, map[string]string, string) {
		if call == 1 {
			return 200, nil, answerAll(d, map[string]bool{d[0]: true, d[1]: true}) // two left out
		}
		return 200, nil, answerAll(d, nil)
	})
	id, err := e.run.Start(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	run := e.wait(t)
	if run.Requests != 2 {
		t.Fatalf("requests: %d", run.Requests)
	}
	if got := len(domainsOf(e.f.prompts[1])); got != 2 {
		t.Fatalf("the second request must carry only the two missing domains, got %d", got)
	}
	items, _ := e.st.DryRunItems(ctx, id)
	for _, it := range items {
		if !it.Valid {
			t.Fatalf("%+v", it)
		}
	}
}

func TestRateLimitsAndServerErrorsAreRetriedThenGivenUpOnPolitely(t *testing.T) {
	var slept []time.Duration
	e := newEnv(t, 12, func(call int, d []string) (int, map[string]string, string) {
		switch call {
		case 1:
			return 429, map[string]string{"Retry-After": "7"}, ""
		case 2:
			return 503, nil, ""
		}
		return 200, nil, answerAll(d, nil)
	})
	e.run.Sleep = func(_ context.Context, d time.Duration) { slept = append(slept, d) }
	id, _ := e.run.Start(ctx, "")
	run := e.wait(t)
	items, _ := e.st.DryRunItems(ctx, id)
	if run.State != "done" || run.Requests != 3 || len(slept) != 2 || slept[0] != 7*time.Second {
		t.Fatalf("%+v slept %v", run, slept)
	}
	for _, it := range items {
		if !it.Valid {
			t.Fatalf("%+v", it)
		}
	}

	// A service that keeps failing: every domain is recorded as not processed, the run still finishes,
	// and the number of tries per batch is bounded.
	e2 := newEnv(t, 12, func(int, []string) (int, map[string]string, string) { return 503, nil, "" })
	id2, _ := e2.run.Start(ctx, "")
	run2 := e2.wait(t)
	items2, _ := e2.st.DryRunItems(ctx, id2)
	if run2.State != "done" || run2.Requests != MaxAttempts || len(items2) != 12 {
		t.Fatalf("%+v items %d", run2, len(items2))
	}
	for _, it := range items2 {
		if it.Valid || it.Issue != "upstream" {
			t.Fatalf("%+v", it)
		}
	}
}

func TestARefusedKeyStopsTheRunAtOnce(t *testing.T) {
	e := newEnv(t, 40, func(int, []string) (int, map[string]string, string) { return 401, nil, "" })
	id, _ := e.run.Start(ctx, "")
	run := e.wait(t)
	if run.State != "failed" || run.ErrorCode != "auth" || run.Requests != 1 {
		t.Fatalf("a refused key must not be retried batch after batch: %+v", run)
	}
	items, _ := e.st.DryRunItems(ctx, id)
	for _, it := range items {
		if it.Valid || it.Issue != "auth" {
			t.Fatalf("%+v", it)
		}
	}
}

func TestBadAnswersNeverBecomeCategories(t *testing.T) {
	calls := 0
	e := newEnv(t, 12, func(call int, d []string) (int, map[string]string, string) {
		calls++
		switch d[0] {
		default:
			if call == 1 {
				return 200, nil, "Sure, here you go!" // not JSON
			}
			// a made-up category and an unasked-for domain
			b, _ := json.Marshal([]map[string]any{
				{"domain": d[0], "category_id": 9999, "confidence": 0.9, "reason": "invented"},
				{"domain": "evil.example.com", "category_id": 1, "confidence": 0.9, "reason": "not asked"},
			})
			return 200, nil, string(b)
		}
	})
	id, _ := e.run.Start(ctx, "")
	run := e.wait(t)
	items, _ := e.st.DryRunItems(ctx, id)
	if run.State != "done" || len(items) != 12 {
		t.Fatalf("%+v items %d", run, len(items))
	}
	for _, it := range items {
		if it.Valid || it.Category != "" || it.Issue == "" {
			t.Fatalf("an invalid answer was kept: %+v", it)
		}
		if it.Site == "evil.example.com" {
			t.Fatal("a domain that was not asked about was recorded")
		}
	}
}

func TestStartRefusesWithoutAModelAKeyOrSites(t *testing.T) {
	e := newEnv(t, 5, func(_ int, d []string) (int, map[string]string, string) { return 200, nil, answerAll(d, nil) })
	_, _ = e.st.SetAutoSettings(ctx, "", 15, 300, "")
	if _, err := e.run.Start(ctx, ""); err != ErrNoModel {
		t.Fatalf("no model: %v", err)
	}
	_, _ = e.st.SetAutoSettings(ctx, "gemini-test-flash", 15, 300, "")
	keyFile := e.run.Client.KeyFile
	_ = os.WriteFile(keyFile, nil, 0o600)
	if _, err := e.run.Start(ctx, ""); err != gemini.ErrNoKey {
		t.Fatalf("no key: %v", err)
	}
	_ = os.WriteFile(keyFile, []byte("AIzaTESTKEY0123456789abcdef"), 0o600)
	// nothing unknown: wipe the sites
	if _, err := e.st.Pool().Exec(ctx, `DELETE FROM connection_events`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.run.Start(ctx, ""); err != ErrNoSites {
		t.Fatalf("no sites: %v", err)
	}
}

func TestOnlyOneRunAtATimeAndRestartsDoNotLeaveRunsRunning(t *testing.T) {
	release := make(chan struct{})
	e := newEnv(t, 12, func(_ int, d []string) (int, map[string]string, string) {
		<-release
		return 200, nil, answerAll(d, nil)
	})
	if _, err := e.run.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.run.Start(ctx, ""); err != ErrBusy {
		t.Fatalf("a second run: %v", err)
	}
	close(release)
	e.wait(t)

	// A run left "running" by a crash is closed on the next start-up.
	id, _ := e.st.CreateDryRun(ctx, "m", 1, "")
	if err := e.st.FailStaleDryRuns(ctx); err != nil {
		t.Fatal(err)
	}
	r, _ := e.st.LatestDryRun(ctx)
	if r.ID != id || r.State != "failed" || r.ErrorCode != "interrupted" {
		t.Fatalf("%+v", r)
	}
}

func TestCategoriesAreNumberedStablyFromOne(t *testing.T) {
	c := Categories([]string{"Игры", "Видео", "Соцсети"})
	if len(c) != 3 || c[0].ID != 1 || c[0].Name != "Видео" || c[2].Name != "Соцсети" {
		t.Fatalf("%+v", c)
	}
}
