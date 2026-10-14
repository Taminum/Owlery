package autoclassify

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/Taminum/RemnaScope/internal/classify"
	"github.com/Taminum/RemnaScope/internal/gemini"
	"github.com/Taminum/RemnaScope/internal/store"
)

const (
	idleWait     = 30 * time.Second
	busyWait     = 2 * time.Second
	discoverEach = 5 * time.Minute
	liveWindow   = 48 * time.Hour // how far back live discovery looks
	discoverMax  = 300            // domains queued per discovery pass
	staleAfter   = 10 * time.Minute
	reviewTTL    = 30 * 24 * time.Hour
	reviewBatch  = 50
	maxBackoff   = 15 * time.Minute
)

// Worker is the background part: it finds unknown domains, asks the model in small batches, and
// stores what it answers as automatic rules. It does nothing unless the owner has switched it on, and
// it never touches ingest: it only reads events to find names and writes rules and queue rows.
type Worker struct {
	R *Runner
	// Now is replaced in tests.
	Now func() time.Time

	lastDiscover time.Time
	lastReview   time.Time
	backoff      time.Duration // current pause after rate limits / failures
	shrunk       int           // batch size reduction after unparsable replies
}

func (w *Worker) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// Run loops until ctx ends.
func (w *Worker) Run(ctx context.Context) {
	if err := w.R.Store.RecoverJobs(ctx, 0); err != nil { // anything "running" at start is from a dead process
		w.R.log().Error("autoclassify: recovering jobs", "err", err)
	}
	for ctx.Err() == nil {
		d := w.Tick(ctx)
		w.R.sleep(ctx, d)
	}
}

// Tick does one unit of work and says how long to wait before the next.
func (w *Worker) Tick(ctx context.Context) time.Duration {
	st := w.R.Store
	cfg, err := st.AutoSettings(ctx)
	if err != nil {
		w.R.log().Error("autoclassify: settings", "err", err)
		return idleWait
	}
	if !cfg.Enabled || cfg.Model == "" || !w.R.Client.HasKey() {
		return idleWait
	}
	_ = st.RecoverJobs(ctx, staleAfter)
	w.discover(ctx)
	w.review(ctx)

	spent, err := st.SpentToday(ctx)
	if err != nil {
		return idleWait
	}
	left := cfg.DailyLimit - spent
	if left <= 0 {
		return idleWait // budget used up for today: wait for the next day, nothing else suffers
	}
	size := min(batchSize(cfg.BatchSize)-w.shrunk, left)
	size = max(size, 1)
	jobs, err := st.ClaimJobs(ctx, size)
	if err != nil {
		w.R.log().Error("autoclassify: claim", "err", err)
		return idleWait
	}
	if len(jobs) == 0 {
		return idleWait
	}
	names, err := st.RuleCategories(ctx)
	if err != nil {
		_ = st.ReleaseJobs(ctx, jobs, "", time.Minute)
		return idleWait
	}
	return w.process(ctx, cfg, Categories(names), jobs)
}

// discover queues unknown domains: new ones seen lately, and, while a backfill is running, history.
func (w *Worker) discover(ctx context.Context) {
	st := w.R.Store
	cfg, _ := st.QueueStatus(ctx)
	backfill := cfg.Backfill == "running"
	if !backfill && w.now().Sub(w.lastDiscover) < discoverEach {
		return
	}
	w.lastDiscover = w.now()
	since, origin := w.now().Add(-liveWindow), "live"
	if backfill {
		since, origin = time.Time{}, "backfill"
	}
	cands, err := st.UnknownCandidates(ctx, since, discoverMax)
	if err != nil {
		w.R.log().Error("autoclassify: discovery", "err", err)
		return
	}
	var ready []store.Candidate
	var skip []string
	for _, c := range cands {
		if site, ok := classify.Eligible(c.Domain); ok && site == c.Domain {
			ready = append(ready, c)
		} else {
			skip = append(skip, c.Domain)
		}
	}
	if _, err := st.EnqueueJobs(ctx, origin, ready, skip); err != nil {
		w.R.log().Error("autoclassify: queueing", "err", err)
		return
	}
	if backfill && len(cands) == 0 {
		_ = st.SetBackfill(ctx, "done")
	}
}

// review sends old automatic results back for another look, a few at a time.
func (w *Worker) review(ctx context.Context) {
	if w.now().Sub(w.lastReview) < time.Hour {
		return
	}
	w.lastReview = w.now()
	if _, err := w.R.Store.RequeueStaleAutoRules(ctx, reviewTTL, reviewBatch); err != nil {
		w.R.log().Error("autoclassify: review", "err", err)
	}
}

func (w *Worker) process(ctx context.Context, cfg store.AutoSettings, cats []classify.Category, jobs []string) time.Duration {
	st := w.R.Store
	text, usage, err := w.R.Client.GenerateJSON(ctx, cfg.Model, classify.System, classify.BuildPrompt(jobs, cats), classify.Schema(), 120*len(jobs)+400)
	_ = st.AddSpent(ctx, len(jobs), 1, usage.In, usage.Out)
	if err != nil {
		code := errCode(err)
		_ = st.NoteAutoError(ctx, code)
		var rl *gemini.RateLimited
		switch {
		case errors.Is(err, gemini.ErrAuth), errors.Is(err, gemini.ErrNoKey), errors.Is(err, gemini.ErrBadRequest):
			// Not the domains' fault and retrying at once will not help: give them back, wait long.
			_ = st.ReleaseJobs(ctx, jobs, code, 10*time.Minute)
			return 10 * time.Minute
		case errors.As(err, &rl):
			d := w.grow(rl.RetryAfter)
			_ = st.ReleaseJobs(ctx, jobs, code, d)
			return d
		default:
			d := w.grow(0)
			_ = st.FailJobsTry(ctx, jobs, code, d)
			return d
		}
	}
	got, issues := classify.Validate(jobs, cats, text)
	w.backoff = 0
	answered := map[string]bool{}
	for _, g := range got {
		answered[g.Site] = true
		if g.Undetermined {
			_ = st.CompleteJob(ctx, g.Site, store.JobUndetermined, "")
			continue
		}
		ok, err := st.ApplyAutoRule(ctx, store.AutoRule{Domain: g.Site, Service: g.Service, Category: g.Category, Model: cfg.Model, Reason: g.Reason, Score: g.Confidence})
		switch {
		case err != nil:
			w.R.log().Error("autoclassify: storing rule", "err", err)
			_ = st.FailJobsTry(ctx, []string{g.Site}, "store", time.Minute)
		case !ok:
			_ = st.CompleteJob(ctx, g.Site, store.JobSkipped, "known") // classified by a real rule in the meantime
		default:
			_ = st.CompleteJob(ctx, g.Site, store.JobDone, "")
		}
	}
	var missing []string
	for _, j := range jobs {
		if !answered[j] {
			missing = append(missing, j)
		}
	}
	if len(missing) > 0 {
		code := "bad_reply"
		for _, is := range issues {
			code = is.Code
			break
		}
		_ = st.FailJobsTry(ctx, missing, code, w.jitter(time.Minute))
		if len(got) == 0 { // an unreadable reply: ask for less next time
			w.shrunk = min(w.shrunk+5, 10)
		}
	} else {
		w.shrunk = 0
	}
	if len(got) > 0 {
		_ = st.NoteAutoSuccess(ctx)
	}
	return busyWait
}

// grow doubles the pause after a failure (what the service asked for wins), with jitter, up to a cap.
func (w *Worker) grow(asked time.Duration) time.Duration {
	if asked > 0 {
		w.backoff = min(asked, maxBackoff)
	} else if w.backoff == 0 {
		w.backoff = 15 * time.Second
	} else {
		w.backoff = min(w.backoff*2, maxBackoff)
	}
	return w.jitter(w.backoff)
}

func (w *Worker) jitter(d time.Duration) time.Duration {
	return d + time.Duration(rand.Int64N(int64(d)/4+1))
}
