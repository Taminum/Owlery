package syncer

import (
	"context"
	"time"

	"golang.org/x/time/rate"

	"github.com/Taminum/Owlery/internal/remnawave"
	"github.com/Taminum/Owlery/internal/store"
)

const (
	protectionPage     = 200
	protectionMaxPages = 50 // 10 000 rows a pass: a panel with more is read as far as that
)

// RunProtection copies what the panels know about torrents and devices into the store every interval. Both are only
// read. A panel without the plugin or the HWID limit answers with an empty list, or with an error that leaves it alone
// for a long while.
func (s *Syncer) RunProtection(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	skipUntil := map[string]time.Time{}
	seenTotal := map[string]int{}
	for {
		s.protectionOnce(ctx, skipUntil, seenTotal)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Syncer) protectionOnce(ctx context.Context, skipUntil map[string]time.Time, seenTotal map[string]int) {
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
		for _, kind := range []string{"torrents", "devices"} {
			key := kind + ":" + p.ID
			if until, ok := skipUntil[key]; ok && until.After(now) {
				continue
			}
			code := s.protectionPanel(ctx, p, kind, key, seenTotal)
			if code == remnawave.CodeNotFound || code == remnawave.CodeForbidden {
				skipUntil[key] = now.Add(6 * time.Hour)
			}
		}
	}
	_ = s.St.PruneTorrentReports(ctx, now)
}

func (s *Syncer) protectionPanel(ctx context.Context, p store.Panel, kind, key string, seenTotal map[string]int) string {
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
	var runErr error
	switch kind {
	case "torrents":
		rd, ok := ad.(remnawave.TorrentReader)
		if !ok {
			return remnawave.CodeNotFound
		}
		runErr = s.copyTorrents(ctx, p.ID, rd, key, seenTotal)
	default:
		rd, ok := ad.(remnawave.DeviceReader)
		if !ok {
			return remnawave.CodeNotFound
		}
		runErr = s.copyDevices(ctx, p.ID, rd)
	}
	if runErr != nil {
		if ctx.Err() == nil {
			s.Log.Warn("panel protection data", "panel", p.ID, "kind", kind, "code", remnawave.ErrorCode(runErr), "detail", runErr.Error())
		}
		return remnawave.ErrorCode(runErr)
	}
	return ""
}

// copyTorrents reads every page of the reports; when the panel's total has not changed since the last look there is
// nothing new and the pages are not read again.
func (s *Syncer) copyTorrents(ctx context.Context, panelID string, rd remnawave.TorrentReader, key string, seenTotal map[string]int) error {
	first, err := rd.TorrentReports(ctx, 0, protectionPage)
	if err != nil {
		return err
	}
	if t, ok := seenTotal[key]; ok && t == first.Total {
		return nil
	}
	page := first
	for i := 0; ; i++ {
		rows := make([]store.TorrentRow, 0, len(page.Reports))
		for _, r := range page.Reports {
			rows = append(rows, store.TorrentRow{RemoteID: r.ID, RemoteUser: r.User, Node: r.Node, At: r.At})
		}
		if _, err := s.St.AddTorrentReports(ctx, panelID, rows); err != nil {
			return err
		}
		if (i+1)*protectionPage >= first.Total || i+1 >= protectionMaxPages {
			break
		}
		if page, err = rd.TorrentReports(ctx, (i+1)*protectionPage, protectionPage); err != nil {
			return err
		}
		if len(page.Reports) == 0 {
			break
		}
	}
	seenTotal[key] = first.Total
	return nil
}

// copyDevices counts the different devices of every subscription and replaces the panel's last look with it.
func (s *Syncer) copyDevices(ctx context.Context, panelID string, rd remnawave.DeviceReader) error {
	first, err := rd.HWIDDevices(ctx, 0, protectionPage)
	if err != nil {
		return err
	}
	sets := map[string]map[string]bool{}
	page := first
	for i := 0; ; i++ {
		for _, d := range page.Devices {
			if sets[d.User] == nil {
				sets[d.User] = map[string]bool{}
			}
			sets[d.User][d.HWID] = true
		}
		if (i+1)*protectionPage >= first.Total || i+1 >= protectionMaxPages {
			break
		}
		if page, err = rd.HWIDDevices(ctx, (i+1)*protectionPage, protectionPage); err != nil {
			return err
		}
		if len(page.Devices) == 0 {
			break
		}
	}
	counts := make(map[string]int, len(sets))
	for u, set := range sets {
		counts[u] = len(set)
	}
	return s.St.ReplaceDevices(ctx, panelID, counts, s.Now().UTC())
}
