// Package dnsworker runs the DNS Map studies in the background: on a map's own schedule (24 hours by
// default, with jitter) and when asked. A run is never carried out inside an HTTP request. Its status is a
// row in the database from the moment it starts, so a restart cannot lose track of it.
package dnsworker

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"

	"github.com/Taminum/Owlery/internal/dnsmap"
	"github.com/Taminum/Owlery/internal/netintel"
	"github.com/Taminum/Owlery/internal/store"
)

const (
	tick        = 30 * time.Second
	concurrent  = 2
	runDeadline = 4 * time.Minute
	roundLimit  = 10
)

// DefaultResolvers are the public recursive resolvers a study asks. The machine's own resolver is not used:
// from inside a container its address is not known, and a fixed pair lets a run record exactly who answered.
var DefaultResolvers = []netip.AddrPort{
	netip.MustParseAddrPort("1.1.1.1:53"),
	netip.MustParseAddrPort("8.8.8.8:53"),
}

type Worker struct {
	Store     *store.Store
	Log       *slog.Logger
	Client    *dnsmap.Client
	Resolvers []netip.AddrPort
	// Intel supplies names from public certificates for a map that asked for them (nil = never).
	Intel    *netintel.Tool
	AuthPort uint16
	Retry    time.Duration
	Now      func() time.Time
	nudge    chan struct{}
}

func New(st *store.Store, log *slog.Logger, intel *netintel.Tool) *Worker {
	return &Worker{Store: st, Log: log, Intel: intel, nudge: make(chan struct{}, 1)}
}

func (w *Worker) Nudge() {
	select {
	case w.nudge <- struct{}{}:
	default:
	}
}

func (w *Worker) now() time.Time {
	if w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}

func (w *Worker) resolvers() []netip.AddrPort {
	if len(w.Resolvers) > 0 {
		return w.Resolvers
	}
	return DefaultResolvers
}

// next is when a map is due again: its interval, give or take 5% so that maps created together drift apart.
func next(from time.Time, hours int) time.Time {
	d := time.Duration(hours) * time.Hour
	return from.Add(d + time.Duration((rand.Float64()*0.1-0.05)*float64(d)))
}

func (w *Worker) Run(ctx context.Context) {
	if err := w.Store.SweepDNSRuns(ctx, w.now()); err != nil {
		w.Log.Error("sweeping dns runs", "err", err)
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		w.Round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-w.nudge:
		}
	}
}

// Round carries out the runs that are due, a couple at a time.
func (w *Worker) Round(ctx context.Context) {
	due, err := w.Store.DueDNSMaps(ctx, w.now(), roundLimit)
	if err != nil {
		w.Log.Error("due dns maps", "err", err)
		return
	}
	sem := make(chan struct{}, concurrent)
	var wg sync.WaitGroup
	for _, m := range due {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			w.runOne(ctx, m)
		}()
	}
	wg.Wait()
}

func (w *Worker) runOne(ctx context.Context, m store.DNSMap) {
	trigger := "schedule"
	if m.LastRunAt == nil || m.NextRunAt == nil {
		trigger = "manual" // the first run, or one that was asked for
	}
	runID, err := w.Store.StartDNSRun(ctx, m.ID, trigger, w.now())
	if err != nil {
		w.Log.Error("starting a dns run", "map", m.ID, "err", err)
		return
	}
	cctx, cancel := context.WithTimeout(ctx, runDeadline)
	defer cancel()

	cfg := dnsmap.Config{Domain: m.Domain, ExtraNames: m.ExtraNames, Resolvers: w.resolvers(), Client: w.Client, AuthPort: w.AuthPort, Retry: w.Retry}
	if m.UseCT && w.Intel != nil {
		cfg.CTNames = w.ctNames(cctx, m.Domain)
	}
	res := dnsmap.Run(cctx, cfg)
	at := w.now()
	if err := w.Store.FinishDNSRun(ctx, m.ID, runID, res, at, next(at, m.IntervalH)); err != nil {
		w.Log.Error("storing a dns run", "map", m.ID, "err", err)
		_ = w.Store.FailDNSRun(ctx, m.ID, runID, "could_not_store", at, next(at, m.IntervalH))
	}
}

// ctNames asks Network Intel for names seen in public certificates. It only ever adds candidates: every one
// is then looked up like any other name, within the domain, and marked as coming from there.
func (w *Worker) ctNames(ctx context.Context, domain string) []string {
	tg, err := netintel.Parse(domain)
	if err != nil {
		return nil
	}
	env := w.Intel.Subdomains(ctx, tg, false)
	if s, ok := env.Data.(netintel.Subdomains); ok {
		return s.Names
	}
	return nil
}
