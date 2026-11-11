package httpapi

import (
	"context"
	"errors"
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

// WarmAnalytics keeps the Sites view of the long ranges ready: counting days of traffic takes seconds, so the first
// person to open the page would wait for it. It asks for the same queries the page does (every panel, no filter),
// as soon as the range moves on (a quarter of an hour for a day, an hour for a week): the answers are cached, so a call
// within the same window costs nothing.
func (s *Server) WarmAnalytics(ctx context.Context) {
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.warmOnce(ctx)
		t.Reset(time.Minute)
	}
}

func (s *Server) warmOnce(ctx context.Context) {
	panels, err := s.Store.ListPanels(ctx, store.Scope{All: true})
	if err != nil {
		return
	}
	var ids []string
	for _, p := range panels {
		if !p.Demo {
			ids = append(ids, p.ID)
		}
	}
	if len(ids) == 0 {
		return
	}
	// First the windows the pages ask for right now (ready already, unless the service has just started), then the ones
	// they will move to in a few minutes (see pageEnd), counted before they get there.
	type window struct {
		rng string
		d   time.Duration
		to  time.Time
	}
	now := s.Now().UTC()
	var windows []window
	for _, rng := range []string{"24h", "7d"} {
		windows = append(windows, window{rng, presets[rng], pageEnd(now, presets[rng])})
	}
	for _, rng := range []string{"24h", "7d"} {
		if next := presetEnd(now, presets[rng]); !next.Equal(pageEnd(now, presets[rng])) {
			windows = append(windows, window{rng, presets[rng], next})
		}
	}
	for _, w := range windows {
		rng, d, to := w.rng, w.d, w.to
		q := store.AnalyticsQuery{PanelIDs: ids, From: to.Add(-d), To: to, Limit: 1}
		if _, _, _, err := s.Store.Sites(ctx, q); err != nil {
			s.Log.Warn("analytics warm-up failed", "range", rng, "err", err)
			return
		}
		if _, err := s.Store.Categories(ctx, q); err != nil {
			s.Log.Warn("analytics warm-up failed", "range", rng, "err", err)
			return
		}
		// The other analytics pages open on the same ranges; each call fills the cache their first request would otherwise
		// wait for. A cached answer is found by the whole question, so each one is asked exactly as its page asks it:
		// the pages set no limit, and a question with one is a different question that warms nothing.
		page := store.AnalyticsQuery{PanelIDs: ids, From: q.From, To: q.To}
		dq := page
		// Every grouping a tab of the Sites and domains page opens on: the first call of each would otherwise take seconds.
		var e1 error
		for _, g := range []string{"site", "service", "host", "ip"} {
			dq.GroupBy = g
			if _, _, _, err := s.Store.Destinations(ctx, dq); err != nil {
				e1 = errors.Join(e1, err)
			}
		}
		_, _, e2 := s.Store.UsersAnalytics(ctx, page)
		_, e3 := s.Store.Subjects(ctx, page)
		_, e4 := s.Store.Countries(ctx, page)
		if err := errors.Join(e1, e2, e3, e4); err != nil {
			s.Log.Warn("analytics warm-up failed", "range", rng, "err", err)
			return
		}
		if rng == "24h" { // "What changed" opens on a day: the sites nobody had visited before, and the devices at home
			nq := page
			nq.NewOnly, nq.Limit = true, 10
			_, _, _, e5 := s.Store.Sites(ctx, nq)
			_, e6 := s.Store.DevicesAnalytics(ctx, page)
			if err := errors.Join(e5, e6); err != nil {
				s.Log.Warn("analytics warm-up failed", "range", rng, "err", err)
				return
			}
		}
	}
}
