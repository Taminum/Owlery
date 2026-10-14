package autoclassify

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/store"
)

type replyFn = func(call int, domains []string) (int, map[string]string, string)

func newWorker(t *testing.T, sites int, reply replyFn) (*env, *Worker) {
	t.Helper()
	e := newEnv(t, sites, reply)
	if err := e.st.SetAutoEnabled(ctx, true); err != nil {
		t.Fatal(err)
	}
	return e, &Worker{R: e.run}
}

func okAll(_ int, d []string) (int, map[string]string, string) { return 200, nil, answerAll(d, nil) }

func jobState(t *testing.T, e *env, domain string) (state string, attempts int, code string) {
	t.Helper()
	var c *string
	if err := e.st.Pool().QueryRow(ctx, `SELECT state, attempts, last_error_code FROM classify_jobs WHERE domain=$1`, domain).Scan(&state, &attempts, &c); err != nil {
		t.Fatalf("job %s: %v", domain, err)
	}
	if c != nil {
		code = *c
	}
	return
}

func drain(w *Worker, n int) {
	for i := 0; i < n; i++ {
		w.Tick(ctx)
	}
}

func TestNothingHappensWhileSwitchedOff(t *testing.T) {
	e, w := newWorker(t, 5, func(int, []string) (int, map[string]string, string) {
		t.Error("the provider was called")
		return 500, nil, ""
	})
	_ = e.st.SetAutoEnabled(ctx, false)
	w.Tick(ctx)
	var n int
	_ = e.st.Pool().QueryRow(ctx, `SELECT count(*) FROM classify_jobs`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d jobs queued while switched off", n)
	}
}

func TestNewUnknownDomainsGetAnAutomaticRuleAndKnownOnesCostNothing(t *testing.T) {
	e, w := newWorker(t, 12, okAll)
	drain(w, 3)
	cat, origin, err := e.st.CategoryOf(ctx, "unknown-000.com")
	if err != nil || cat == "" || origin != store.OriginAuto {
		t.Fatalf("category %q origin %q err %v", cat, origin, err)
	}
	if c, _, _ := e.st.CategoryOf(ctx, "www.unknown-000.com"); c != cat {
		t.Fatalf("subdomain got %q", c)
	}
	for _, p := range e.f.prompts {
		for _, bad := range []string{"192.168.1.1", "localhost", "router.lan", "pixiv.net"} {
			if strings.Contains(p, bad) {
				t.Fatalf("%s was sent to the provider", bad)
			}
		}
	}
	for _, d := range []string{"192.168.1.1", "localhost", "router.lan"} {
		if st, _, code := jobState(t, e, d); st != store.JobSkipped || code != "ineligible" {
			t.Fatalf("%s: %s %s", d, st, code)
		}
	}
	calls := e.f.calls
	w.lastDiscover = time.Time{}
	drain(w, 3)
	if e.f.calls != calls {
		t.Fatalf("%d more calls for nothing", e.f.calls-calls)
	}
}

func TestLowConfidenceIsShownAsAGuess(t *testing.T) {
	e, w := newWorker(t, 1, func(_ int, d []string) (int, map[string]string, string) {
		return 200, nil, strings.ReplaceAll(answerAll(d, nil), "0.8", "0.4")
	})
	drain(w, 2)
	if _, origin, _ := e.st.CategoryOf(ctx, "unknown-000.com"); origin != store.OriginGuess {
		t.Fatalf("origin %q", origin)
	}
}

func TestAManualRuleAlwaysBeatsTheModelBeforeAndAfter(t *testing.T) {
	e, w := newWorker(t, 3, okAll)
	if _, err := e.st.UpsertCustomRule(ctx, "unknown-001.com", "Mine", "Мои сайты", "high", ""); err != nil {
		t.Fatal(err)
	}
	drain(w, 3)
	if cat, origin, _ := e.st.CategoryOf(ctx, "unknown-001.com"); cat != "Мои сайты" || origin != store.OriginManual {
		t.Fatalf("manual lost: %q %q", cat, origin)
	}
	var n int
	_ = e.st.Pool().QueryRow(ctx, `SELECT count(*) FROM service_rules WHERE pattern='unknown-001.com' AND source='auto'`).Scan(&n)
	if n != 0 {
		t.Fatal("an automatic rule was stored for a domain the owner classified")
	}
	// The owner overrides an automatic result, then the model is asked again after the TTL.
	if _, err := e.st.UpsertCustomRule(ctx, "unknown-000.com", "Mine", "Мои сайты", "high", ""); err != nil {
		t.Fatal(err)
	}
	_, _ = e.st.Pool().Exec(ctx, `UPDATE service_rules SET classified_at = now() - interval '90 days' WHERE source='auto'`)
	w.lastReview = time.Time{}
	drain(w, 3)
	if cat, origin, _ := e.st.CategoryOf(ctx, "unknown-000.com"); cat != "Мои сайты" || origin != store.OriginManual {
		t.Fatalf("manual lost after review: %q %q", cat, origin)
	}
	rules, _ := e.st.ListCustomRules(ctx)
	for _, r := range rules {
		if r.Pattern == "unknown-000.com" {
			_, _ = e.st.DeleteCustomRule(ctx, r.ID)
		}
	}
	if _, origin, _ := e.st.CategoryOf(ctx, "unknown-000.com"); origin != store.OriginAuto {
		t.Fatalf("origin after deleting the manual rule: %q", origin)
	}
}

func TestPartialBatchesAskOnlyForWhatIsMissing(t *testing.T) {
	e, w := newWorker(t, 4, func(call int, d []string) (int, map[string]string, string) {
		if call == 1 {
			return 200, nil, answerAll(d, map[string]bool{"unknown-002.com": true})
		}
		return 200, nil, answerAll(d, nil)
	})
	w.Tick(ctx)
	if st, _, code := jobState(t, e, "unknown-002.com"); st != store.JobRetry || code == "" {
		t.Fatalf("missing item: %s %s", st, code)
	}
	if st, _, _ := jobState(t, e, "unknown-000.com"); st != store.JobDone {
		t.Fatalf("answered item: %s", st)
	}
	_, _ = e.st.Pool().Exec(ctx, `UPDATE classify_jobs SET next_attempt_at = now()`)
	w.Tick(ctx)
	last := e.f.prompts[len(e.f.prompts)-1]
	if got := domainsOf(last); len(got) != 1 || got[0] != "unknown-002.com" {
		t.Fatalf("second request asked for %v", got)
	}
}

func TestRateLimitsPauseWithoutSpendingTries(t *testing.T) {
	e, w := newWorker(t, 3, func(call int, d []string) (int, map[string]string, string) {
		if call == 1 {
			return 429, map[string]string{"Retry-After": "90"}, ""
		}
		return 200, nil, answerAll(d, nil)
	})
	if d := w.Tick(ctx); d < 90*time.Second {
		t.Fatalf("waited only %v", d)
	}
	if st, attempts, code := jobState(t, e, "unknown-000.com"); st != store.JobPending || attempts != 0 || code != "rate_limited" {
		t.Fatalf("%s attempts %d code %s", st, attempts, code)
	}
	_, _ = e.st.Pool().Exec(ctx, `UPDATE classify_jobs SET next_attempt_at = now()`)
	w.Tick(ctx)
	if st, _, _ := jobState(t, e, "unknown-000.com"); st != store.JobDone {
		t.Fatal(st)
	}
	if w.backoff != 0 {
		t.Fatal("back-off was not reset by a success")
	}
}

func TestServerErrorsRetryThenParkTheJobsWithoutBreakingTheWorker(t *testing.T) {
	e, w := newWorker(t, 2, func(int, []string) (int, map[string]string, string) { return 503, nil, "" })
	for i := 0; i < store.MaxJobAttempts+1; i++ {
		w.Tick(ctx)
		_, _ = e.st.Pool().Exec(ctx, `UPDATE classify_jobs SET next_attempt_at = now() WHERE state = 'retry'`)
	}
	st, attempts, code := jobState(t, e, "unknown-000.com")
	if st != store.JobFailed || attempts != store.MaxJobAttempts || code != "upstream" {
		t.Fatalf("%s attempts %d code %s", st, attempts, code)
	}
	_, _ = e.st.Pool().Exec(ctx, `UPDATE classify_jobs SET next_attempt_at = now() WHERE state='failed'`)
	if err := e.st.RecoverJobs(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	if st, attempts, _ := jobState(t, e, "unknown-000.com"); st != store.JobPending || attempts != 0 {
		t.Fatalf("%s %d", st, attempts)
	}
}

func TestARefusedKeyReleasesTheJobsAndSaysSo(t *testing.T) {
	e, w := newWorker(t, 2, func(int, []string) (int, map[string]string, string) { return 401, nil, "" })
	if d := w.Tick(ctx); d < time.Minute {
		t.Fatalf("hammering a refused key: waited %v", d)
	}
	if st, attempts, code := jobState(t, e, "unknown-000.com"); st != store.JobPending || attempts != 0 || code != "auth" {
		t.Fatalf("%s %d %s", st, attempts, code)
	}
	if q, _ := e.st.QueueStatus(ctx); q.LastErrorCode != "auth" {
		t.Fatalf("status shows %q", q.LastErrorCode)
	}
}

func TestUndeterminedAndInvalidAnswersNeverBecomeRules(t *testing.T) {
	var first, second string
	e, w := newWorker(t, 3, func(_ int, d []string) (int, map[string]string, string) {
		first, second = d[0], d[1]
		return 200, nil, fmt.Sprintf(`[{"domain":%q,"category_id":0,"service_name":null,"confidence":0.2,"reason":"?"},{"domain":%q,"category_id":999,"service_name":null,"confidence":0.9,"reason":"x"}]`, d[0], d[1])
	})
	w.Tick(ctx)
	var n int
	_ = e.st.Pool().QueryRow(ctx, `SELECT count(*) FROM service_rules WHERE source='auto'`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d rules from undetermined or invalid answers", n)
	}
	if st, _, _ := jobState(t, e, first); st != store.JobUndetermined {
		t.Fatal(st)
	}
	if st, _, _ := jobState(t, e, second); st != store.JobRetry {
		t.Fatal(st)
	}
}

func TestTheDailyBudgetPausesProcessing(t *testing.T) {
	e, w := newWorker(t, 30, okAll)
	_, _ = e.st.SetAutoSettings(ctx, "gemini-test-flash", 10, 12, "")
	drain(w, 6)
	var done int
	_ = e.st.Pool().QueryRow(ctx, `SELECT count(*) FROM classify_jobs WHERE state='done'`).Scan(&done)
	if done != 12 {
		t.Fatalf("%d domains processed on a budget of 12", done)
	}
	if spent, _ := e.st.SpentToday(ctx); spent != 12 {
		t.Fatalf("spent %d", spent)
	}
}

func TestTwoWorkersNeverTakeTheSameDomain(t *testing.T) {
	e, _ := newWorker(t, 40, okAll)
	cands, _ := e.st.UnknownCandidates(ctx, time.Time{}, 100)
	if _, err := e.st.EnqueueJobs(ctx, "live", cands, nil); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	seen := map[string]int{}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				got, err := e.st.ClaimJobs(ctx, 3)
				if err != nil || len(got) == 0 {
					return
				}
				mu.Lock()
				for _, d := range got {
					seen[d]++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(seen) != len(cands) {
		t.Fatalf("%d domains claimed, want %d", len(seen), len(cands))
	}
	for d, n := range seen {
		if n != 1 {
			t.Fatalf("%s claimed %d times", d, n)
		}
	}
}

func TestJobsLeftRunningByACrashAreRecovered(t *testing.T) {
	e, w := newWorker(t, 3, okAll)
	cands, _ := e.st.UnknownCandidates(ctx, time.Time{}, 10)
	_, _ = e.st.EnqueueJobs(ctx, "live", cands, nil)
	got, _ := e.st.ClaimJobs(ctx, 3)
	if len(got) != 3 {
		t.Fatal(got)
	}
	_, _ = e.st.Pool().Exec(ctx, `UPDATE classify_jobs SET locked_at = now() - interval '1 hour'`)
	if err := e.st.RecoverJobs(ctx, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	drain(w, 2)
	if st, _, _ := jobState(t, e, got[0]); st != store.JobDone {
		t.Fatalf("not recovered: %s", st)
	}
}

func TestBackfillPicksUpHistoryAndFinishes(t *testing.T) {
	e, w := newWorker(t, 3, okAll)
	_, _ = e.st.Pool().Exec(ctx, `UPDATE connection_events SET ts = now() - interval '90 days'`)
	w.Tick(ctx)
	var n int
	_ = e.st.Pool().QueryRow(ctx, `SELECT count(*) FROM classify_jobs`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d jobs from history without a backfill", n)
	}
	if err := e.st.SetBackfill(ctx, "running"); err != nil {
		t.Fatal(err)
	}
	drain(w, 4)
	if q, _ := e.st.QueueStatus(ctx); q.Backfill != "done" || q.Counts[store.JobDone] != 3 {
		t.Fatalf("%+v", q)
	}
	if _, origin, _ := e.st.CategoryOf(ctx, "unknown-002.com"); origin != store.OriginAuto {
		t.Fatal(origin)
	}
}

func TestSwitchingOffStopsEverythingAndKeepsWhatWasCollected(t *testing.T) {
	e, w := newWorker(t, 4, okAll)
	drain(w, 2)
	_ = e.st.SetAutoEnabled(ctx, false)
	calls := e.f.calls
	drain(w, 3)
	if e.f.calls != calls {
		t.Fatal("the provider was called after switching off")
	}
	if _, origin, _ := e.st.CategoryOf(ctx, "unknown-000.com"); origin != store.OriginAuto {
		t.Fatal("collected classifications were lost")
	}
}

func TestRawEventsAreNeverTouched(t *testing.T) {
	e, w := newWorker(t, 3, okAll)
	var before, after string
	q := `SELECT md5(string_agg(site || ts::text || destination_host, ',' ORDER BY event_id)) FROM connection_events`
	_ = e.st.Pool().QueryRow(ctx, q).Scan(&before)
	drain(w, 3)
	_ = e.st.Pool().QueryRow(ctx, q).Scan(&after)
	if before != after {
		t.Fatal("events changed")
	}
}
