package syncer

import (
	"context"
	"time"

	"golang.org/x/time/rate"

	"github.com/Taminum/Owlery/internal/remnawave"
	"github.com/Taminum/Owlery/internal/store"
)

const (
	historyPage     = 200
	historyMaxPages = 60 // a first look reaches back 12 000 requests, later ones stop at the first page with nothing new
)

// RunSubscriptions copies the subscription request history of every panel into the store every interval. A panel
// whose version lacks the endpoint, or whose token may not read it, is left alone for a long while.
func (s *Syncer) RunSubscriptions(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	skipUntil := map[string]time.Time{}
	for {
		s.subscriptionsOnce(ctx, skipUntil)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Syncer) subscriptionsOnce(ctx context.Context, skipUntil map[string]time.Time) {
	panels, err := s.St.ListPanels(ctx, store.Scope{All: true})
	if err != nil {
		return
	}
	now := s.Now().UTC()
	for _, p := range panels {
		if p.Demo || p.Status == "disabled" || !p.HasCredential || !p.SyncOptions.Users {
			continue
		}
		if p.CircuitOpenUntil != nil && p.CircuitOpenUntil.After(now) {
			continue
		}
		if until, ok := skipUntil[p.ID]; ok && until.After(now) {
			continue
		}
		code := s.subscriptionsPanel(ctx, p)
		if code == remnawave.CodeNotFound || code == remnawave.CodeForbidden {
			skipUntil[p.ID] = now.Add(6 * time.Hour)
		}
	}
	_ = s.St.PruneSubscriptionRequests(ctx, now)
}

func (s *Syncer) subscriptionsPanel(ctx context.Context, p store.Panel) string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	sealed, err := s.St.Credential(ctx, p.ID)
	if err != nil {
		return "credential_missing"
	}
	raw, err := s.Ring.Open(p.ID, sealed)
	if err != nil {
		return "credential_unreadable"
	}
	token := string(raw)
	for i := range raw {
		raw[i] = 0
	}
	g := limitedGetter{g: s.Fetch(p), lim: rate.NewLimiter(rate.Limit(s.Cfg.RPS), 1)}
	ad, err := s.Factory(p, token, g)
	if err != nil {
		return "adapter_unavailable"
	}
	rd, ok := ad.(remnawave.SubscriptionHistoryReader)
	if !ok {
		return remnawave.CodeNotFound
	}
	add := func(recs []remnawave.SubscriptionRequest) (int64, error) {
		out := make([]store.SubRequest, 0, len(recs))
		for _, r := range recs {
			out = append(out, store.SubRequest{RemoteID: r.ID, RemoteUser: r.UserID, At: r.At, IP: r.IP, Agent: r.Agent})
		}
		return s.St.AddSubscriptionRequests(ctx, p.ID, out)
	}
	if err := copyHistory(ctx, rd, add); err != nil {
		if ctx.Err() == nil {
			s.Log.Warn("subscription history", "panel", p.ID, "code", remnawave.ErrorCode(err))
		}
		return remnawave.ErrorCode(err)
	}
	return ""
}

// copyHistory walks the history from its newest end and stops at the first page that held nothing new. The panel does
// not promise an order, so the first page says which way the history runs: newest first is read from the start,
// oldest first from the end backwards.
func copyHistory(ctx context.Context, rd remnawave.SubscriptionHistoryReader, add func([]remnawave.SubscriptionRequest) (int64, error)) error {
	first, err := rd.SubscriptionHistory(ctx, 0, historyPage)
	if err != nil {
		return err
	}
	recs := first.Records
	newestFirst := len(recs) < 2 || !recs[0].At.Before(recs[len(recs)-1].At)
	if !newestFirst && first.Total > len(recs) {
		return copyHistoryBackwards(ctx, rd, add, first.Total)
	}
	for page := 0; ; page++ {
		n, err := add(recs)
		if err != nil {
			return err
		}
		if n == 0 || len(recs)+first.Skipped == 0 || page+1 >= historyMaxPages {
			return nil
		}
		next, err := rd.SubscriptionHistory(ctx, (page+1)*historyPage, historyPage)
		if err != nil {
			return err
		}
		if len(next.Records) == 0 {
			return nil
		}
		recs = next.Records
	}
}

func copyHistoryBackwards(ctx context.Context, rd remnawave.SubscriptionHistoryReader, add func([]remnawave.SubscriptionRequest) (int64, error), total int) error {
	start := max(0, total-historyPage)
	for page := 0; page < historyMaxPages; page++ {
		h, err := rd.SubscriptionHistory(ctx, start, historyPage)
		if err != nil {
			return err
		}
		n, err := add(h.Records)
		if err != nil {
			return err
		}
		if n == 0 || start == 0 {
			return nil
		}
		start = max(0, start-historyPage)
	}
	return nil
}
