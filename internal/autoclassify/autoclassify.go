// Package autoclassify asks a model to categorise unknown domains. This stage does a dry run only:
// the answers are stored apart from the real rules and nothing is applied.
package autoclassify

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"github.com/Taminum/Owlery/internal/classify"
	"github.com/Taminum/Owlery/internal/gemini"
	"github.com/Taminum/Owlery/internal/store"
)

const (
	// SampleSize is how many unknown domains a dry run looks at; the first TopShare are the busiest,
	// the rest are picked at random from what remains so the quality is not judged only on easy cases.
	SampleSize = 100
	TopShare   = 60
	// MaxAttempts is how often one batch is tried when the service is rate limiting or failing.
	MaxAttempts = 3
)

var (
	ErrBusy    = errors.New("autoclassify: a run is already in progress")
	ErrNoModel = errors.New("autoclassify: no model chosen")
	ErrNoSites = errors.New("autoclassify: there are no unknown domains to look at")
)

// Categories numbers the categories Owlery has, in a stable order, for the prompt.
func Categories(names []string) []classify.Category {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	out := make([]classify.Category, 0, len(sorted))
	for i, n := range sorted {
		out = append(out, classify.Category{ID: i + 1, Name: n})
	}
	return out
}

type Runner struct {
	Store  *store.Store
	Client *gemini.Client
	Log    *slog.Logger
	// Sleep is replaced in tests; Rand picks the random part of the sample.
	Sleep func(context.Context, time.Duration)
	Rand  *rand.Rand

	mu      sync.Mutex
	running bool
}

func (r *Runner) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

func (r *Runner) sleep(ctx context.Context, d time.Duration) {
	if r.Sleep != nil {
		r.Sleep(ctx, d)
		return
	}
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// Running reports whether a dry run is in progress right now.
func (r *Runner) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

// pick chooses the sample: the busiest TopShare eligible domains plus random ones from the rest.
func (r *Runner) pick(unknown []store.UnknownSite) []store.DryRunItem {
	var eligible []store.UnknownSite
	for _, u := range unknown {
		if site, ok := classify.Eligible(u.Site); ok && site == u.Site {
			eligible = append(eligible, u)
		}
	}
	var out []store.DryRunItem
	n := min(TopShare, len(eligible))
	for _, u := range eligible[:n] {
		out = append(out, store.DryRunItem{Site: u.Site, Connections: u.Connections, PickedBy: "top"})
	}
	rest := append([]store.UnknownSite(nil), eligible[n:]...)
	rng := r.Rand
	if rng == nil {
		rng = rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 1))
	}
	rng.Shuffle(len(rest), func(i, j int) { rest[i], rest[j] = rest[j], rest[i] })
	for _, u := range rest[:min(SampleSize-n, len(rest))] {
		out = append(out, store.DryRunItem{Site: u.Site, Connections: u.Connections, PickedBy: "random"})
	}
	return out
}

// Start begins a dry run in the background and returns its id. Only one run goes at a time.
func (r *Runner) Start(ctx context.Context, by string) (string, error) {
	st, err := r.Store.AutoSettings(ctx)
	if err != nil {
		return "", err
	}
	if st.Model == "" {
		return "", ErrNoModel
	}
	if !r.Client.HasKey() {
		return "", gemini.ErrNoKey
	}
	names, err := r.Store.RuleCategories(ctx)
	if err != nil {
		return "", err
	}
	unknown, err := r.Store.UnknownSites(ctx, 5000)
	if err != nil {
		return "", err
	}
	sample := r.pick(unknown)
	if len(sample) == 0 {
		return "", ErrNoSites
	}
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return "", ErrBusy
	}
	r.running = true
	r.mu.Unlock()

	id, err := r.Store.CreateDryRun(ctx, st.Model, len(sample), by)
	if err != nil {
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
		return "", err
	}
	go func() {
		defer func() { r.mu.Lock(); r.running = false; r.mu.Unlock() }()
		rctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		state, code := r.run(rctx, id, st, Categories(names), sample)
		if err := r.Store.FinishDryRun(context.Background(), id, state, code); err != nil {
			r.log().Error("finishing dry run", "err", err)
		}
	}()
	return id, nil
}

func batchSize(n int) int { return min(max(n, 10), 20) }

// run works through the sample batch by batch. It never lets one bad batch stop the rest.
func (r *Runner) run(ctx context.Context, id string, st store.AutoSettings, cats []classify.Category, sample []store.DryRunItem) (state, code string) {
	size := batchSize(st.BatchSize)
	conns := map[string]store.DryRunItem{}
	for _, s := range sample {
		conns[s.Site] = s
	}
	state = "done"
	for start := 0; start < len(sample); start += size {
		chunk := sample[start:min(start+size, len(sample))]
		domains := make([]string, len(chunk))
		for i, c := range chunk {
			domains[i] = c.Site
		}
		var items []store.DryRunItem
		pending := domains
		var lastCode string
		for attempt := 0; attempt < MaxAttempts && len(pending) > 0 && ctx.Err() == nil; attempt++ {
			text, usage, err := r.Client.GenerateJSON(ctx, st.Model, classify.System, classify.BuildPrompt(pending, cats), classify.Schema(), 120*len(pending)+400)
			_ = r.Store.AddDryRunUsage(ctx, id, 1, usage.In, usage.Out)
			if err != nil {
				lastCode = errCode(err)
				if errors.Is(err, gemini.ErrAuth) || errors.Is(err, gemini.ErrNoKey) || errors.Is(err, gemini.ErrBadRequest) {
					state, code = "failed", lastCode // retrying will not help
					r.record(ctx, id, conns, pending, nil, lastCode)
					return state, code
				}
				r.sleep(ctx, wait(err, attempt))
				continue
			}
			got, issues := classify.Validate(pending, cats, text)
			answered := map[string]bool{}
			for _, g := range got {
				items = append(items, valid(conns[g.Site], g))
				answered[g.Site] = true
			}
			// Only what was not answered is asked again. A reply that was not JSON at all answered nothing,
			// so the whole batch is asked again.
			for _, is := range issues {
				lastCode = is.Code
			}
			var next []string
			for _, d := range pending {
				if !answered[d] {
					next = append(next, d)
				}
			}
			if len(next) > 0 && lastCode == "" {
				lastCode = "bad_reply"
			}
			pending = next
		}
		r.record(ctx, id, conns, pending, items, lastCode)
		if ctx.Err() != nil {
			return "failed", "interrupted"
		}
	}
	return state, code
}

func valid(base store.DryRunItem, g classify.Item) store.DryRunItem {
	base.Valid, base.Undetermined = true, g.Undetermined
	base.Category, base.Service, base.Confidence, base.Reason = g.Category, g.Service, g.Confidence, g.Reason
	return base
}

// record stores the valid answers and marks the domains that never got one.
func (r *Runner) record(ctx context.Context, id string, base map[string]store.DryRunItem, unanswered []string, items []store.DryRunItem, code string) {
	for _, d := range unanswered {
		b := base[d]
		b.Valid, b.Issue = false, coalesce(code, "not_processed")
		items = append(items, b)
	}
	if err := r.Store.AddDryRunItems(ctx, id, items); err != nil {
		r.log().Error("storing dry-run items", "err", err)
	}
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// errCode is a short machine word for an error, safe to store and show.
func errCode(err error) string {
	var rl *gemini.RateLimited
	var up *gemini.Upstream
	switch {
	case errors.Is(err, gemini.ErrNoKey):
		return "no_key"
	case errors.Is(err, gemini.ErrAuth):
		return "auth"
	case errors.Is(err, gemini.ErrBadRequest):
		return "bad_request"
	case errors.As(err, &rl):
		return "rate_limited"
	case errors.As(err, &up):
		if up.Status == 0 {
			return "network"
		}
		return "upstream"
	case errors.Is(err, gemini.ErrBadReply):
		return "bad_reply"
	}
	return "error"
}

// wait is how long to pause before the next try: what the service asked for, else exponential
// back-off with jitter, never more than a minute in a dry run.
func wait(err error, attempt int) time.Duration {
	var rl *gemini.RateLimited
	if errors.As(err, &rl) && rl.RetryAfter > 0 {
		return min(rl.RetryAfter, time.Minute)
	}
	base := time.Duration(1<<attempt) * 2 * time.Second
	return min(base+time.Duration(rand.Int64N(int64(time.Second))), time.Minute)
}
