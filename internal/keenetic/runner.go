package keenetic

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Taminum/Owlery/internal/secrets"
	"github.com/Taminum/Owlery/internal/store"
)

// Runner asks every Keenetic router that was added for asking, once in a while, and keeps what they say as if they had posted it.
type Runner struct {
	St   *store.Store
	Ring *secrets.Keyring
	Log  *slog.Logger
	Now  func() time.Time

	mu   sync.Mutex
	last map[string]string // the failure code last logged for each router, so a router that stays down is logged once
}

const (
	pollTimeout = 45 * time.Second
	pollWorkers = 4
)

// Run asks the routers every interval until the context ends.
func (r *Runner) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		r.Once(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Once asks every router one time, a few at a time.
func (r *Runner) Once(ctx context.Context) {
	devs, err := r.St.PullDevices(ctx)
	if err != nil || len(devs) == 0 {
		return
	}
	sem := make(chan struct{}, pollWorkers)
	var wg sync.WaitGroup
	for _, d := range devs {
		sem <- struct{}{}
		wg.Add(1)
		go func(d store.PullDevice) {
			defer func() { <-sem; wg.Done() }()
			r.ask(ctx, d)
		}(d)
	}
	wg.Wait()
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *Runner) fail(ctx context.Context, d store.PullDevice, code string, err error) {
	if ctx.Err() != nil {
		return
	}
	_ = r.St.SavePullError(ctx, d.ID, code, r.now())
	r.mu.Lock()
	if r.last == nil {
		r.last = map[string]string{}
	}
	changed := r.last[d.ID] != code
	r.last[d.ID] = code
	r.mu.Unlock()
	if changed && r.Log != nil {
		r.Log.Warn("router did not answer", "router", d.ID, "name", d.Name, "code", code, "detail", err.Error())
	}
}

func (r *Runner) ask(ctx context.Context, d store.PullDevice) {
	ctx, cancel := context.WithTimeout(ctx, pollTimeout)
	defer cancel()
	raw, err := r.Ring.Open(store.NetPullAAD(d.ID), d.Sealed)
	if err != nil {
		r.fail(ctx, d, "unexpected", err)
		return
	}
	password := string(raw)
	for i := range raw {
		raw[i] = 0
	}
	c, err := New(d.URL, d.Login, password)
	if err != nil {
		r.fail(ctx, d, "unexpected", err)
		return
	}
	rep, err := c.Poll(ctx)
	if err != nil {
		r.fail(ctx, d, Code(err), err)
		return
	}
	if err := r.St.SaveNetReport(ctx, d.ID, rep, r.now()); err != nil {
		if ctx.Err() == nil && r.Log != nil {
			r.Log.Warn("router reading not saved", "router", d.ID, "detail", err.Error())
		}
		return
	}
	r.mu.Lock()
	delete(r.last, d.ID)
	r.mu.Unlock()
}
