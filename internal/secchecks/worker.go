package secchecks

import (
	"context"
	"encoding/json"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/Taminum/RemnaScope/internal/store"
)

const (
	PortEvery   = 60 * time.Minute
	TLSEvery    = 24 * time.Hour
	Concurrency = 4
	roundLimit  = 100
	tick        = 30 * time.Second
)

// jitter spreads the next check by up to 5% either way, so checks that started together drift apart.
func jitter(every time.Duration) time.Duration {
	return every + time.Duration((rand.Float64()*0.1-0.05)*float64(every))
}

// Worker runs the external checks. A manual request marks endpoints due and calls Nudge.
type Worker struct {
	Store *store.Store
	Log   *slog.Logger
	Now   func() time.Time
	nudge chan struct{}
}

func New(st *store.Store, log *slog.Logger) *Worker {
	return &Worker{Store: st, Log: log, nudge: make(chan struct{}, 1)}
}

// Nudge asks for a round now. It never blocks and never queues more than one.
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

func (w *Worker) Run(ctx context.Context) {
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

// Round checks everything that is due, a few targets at a time.
func (w *Worker) Round(ctx context.Context) {
	if err := w.Store.SyncPortCandidates(ctx); err != nil {
		w.Log.Error("syncing port candidates", "err", err)
	}
	now := w.now()
	ports, err := w.Store.DuePorts(ctx, now, roundLimit)
	if err != nil {
		w.Log.Error("due ports", "err", err)
	}
	tlss, err := w.Store.DueTLS(ctx, now, roundLimit)
	if err != nil {
		w.Log.Error("due tls", "err", err)
	}
	sem := make(chan struct{}, Concurrency)
	var wg sync.WaitGroup
	run := func(f func()) {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			f()
		}()
	}
	for _, p := range ports {
		run(func() {
			r := TCP(ctx, p.Host, p.Port)
			at := w.now()
			if err := w.Store.RecordPortCheck(ctx, p.ID, store.PortObservation{Result: r.Result, IP: r.IP, RTTms: r.RTTms, Error: r.Error}, at, at.Add(jitter(PortEvery))); err != nil {
				w.Log.Error("recording port check", "err", err)
			}
		})
	}
	for _, e := range tlss {
		run(func() {
			r := TLS(ctx, e.Host, e.Port, e.SNI, w.now())
			data, _ := json.Marshal(map[string]any{
				"state": r.State, "ip": r.IP, "resolved": r.Resolved, "sni": r.SNI, "name_checked": r.NameChecked, "version": r.Version,
				"fingerprint": r.Fingerprint, "subject": r.Subject, "issuer": r.Issuer, "dns_names": r.DNSNames, "serial": r.Serial,
				"not_before": nilTime(r.NotBefore), "not_after": nilTime(r.NotAfter), "days_left": r.DaysLeft, "has_cert": r.HasCert, "error": r.Error,
				"vantage": VantageID, "independent": Independent,
			})
			at := w.now()
			if err := w.Store.RecordTLSCheck(ctx, e.ID, store.TLSObservation{State: r.State, IP: r.IP, HasCert: r.HasCert, Fingerprint: r.Fingerprint,
				NotAfter: r.NotAfter, DaysLeft: r.DaysLeft, Data: data}, at, at.Add(jitter(TLSEvery))); err != nil {
				w.Log.Error("recording tls check", "err", err)
			}
		})
	}
	wg.Wait()
}

func nilTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
