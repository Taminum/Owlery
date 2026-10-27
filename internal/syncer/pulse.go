package syncer

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/Taminum/Owlery/internal/remnawave"
	"github.com/Taminum/Owlery/internal/store"
)

// NodeSpeed is one node's current speed. Kept in memory only: a speed that is a minute old is not a speed.
type NodeSpeed struct {
	NodeUUID string `json:"node_uuid"`
	Name     string `json:"name"`
	DownBps  int64  `json:"down_bps"`
	UpBps    int64  `json:"up_bps"`
}

// PanelPulse is the last reading of one panel.
type PanelPulse struct {
	PanelID string      `json:"panel_id"`
	At      time.Time   `json:"at"`
	Nodes   []NodeSpeed `json:"nodes"`
	Err     string      `json:"error,omitempty"` // the error code of the last try, when it failed
}

// Pulse keeps the latest reading of every panel.
type Pulse struct {
	mu   sync.Mutex
	last map[string]PanelPulse
}

func NewPulse() *Pulse { return &Pulse{last: map[string]PanelPulse{}} }

func (p *Pulse) set(v PanelPulse) {
	p.mu.Lock()
	p.last[v.PanelID] = v
	p.mu.Unlock()
}

// For returns the readings of the given panels, those with no reading left out.
func (p *Pulse) For(sc store.Scope, ids []string) []PanelPulse {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []PanelPulse
	for _, id := range ids {
		if v, ok := p.last[id]; ok && sc.Allows(id) {
			out = append(out, v)
		}
	}
	return out
}

func (p *Pulse) forget(id string) {
	p.mu.Lock()
	delete(p.last, id)
	p.mu.Unlock()
}

// RunPulse reads the speed of the nodes of every panel every interval. It is cheap (one request per panel)
// and independent of the full sync, which runs every few minutes. A panel whose version lacks the endpoint is
// left alone for a long while; any other failure keeps the old reading, marked with the error, until it is too
// old to be shown.
func (s *Syncer) RunPulse(ctx context.Context, pl *Pulse, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	skipUntil := map[string]time.Time{}
	for {
		s.pulseOnce(ctx, pl, skipUntil)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Syncer) pulseOnce(ctx context.Context, pl *Pulse, skipUntil map[string]time.Time) {
	panels, err := s.St.ListPanels(ctx, store.Scope{All: true})
	if err != nil {
		return
	}
	now := s.Now().UTC()
	for _, p := range panels {
		if p.Demo || p.Status == "disabled" || !p.HasCredential || !p.SyncOptions.Nodes {
			pl.forget(p.ID)
			continue
		}
		if p.CircuitOpenUntil != nil && p.CircuitOpenUntil.After(now) {
			continue
		}
		if until, ok := skipUntil[p.ID]; ok && until.After(now) {
			continue
		}
		code := s.pulsePanel(ctx, pl, p, now)
		if code == remnawave.CodeNotFound || code == remnawave.CodeForbidden {
			skipUntil[p.ID] = now.Add(15 * time.Minute)
		}
	}
}

func (s *Syncer) pulsePanel(ctx context.Context, pl *Pulse, p store.Panel, now time.Time) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	keep := func(code string) string {
		pl.mu.Lock()
		v := pl.last[p.ID]
		pl.mu.Unlock()
		v.PanelID, v.Err = p.ID, code
		pl.set(v)
		return code
	}
	sealed, err := s.St.Credential(ctx, p.ID)
	if err != nil {
		return keep("credential_missing")
	}
	raw, err := s.Ring.Open(p.ID, sealed)
	if err != nil {
		return keep("credential_unreadable")
	}
	token := string(raw)
	for i := range raw {
		raw[i] = 0
	}
	g := limitedGetter{g: s.Fetch(p), lim: rate.NewLimiter(rate.Limit(s.Cfg.RPS), 1)}
	ad, err := s.Factory(p, token, g)
	if err != nil {
		return keep("adapter_unavailable")
	}
	rd, ok := ad.(remnawave.RealtimeReader)
	if !ok {
		return keep(remnawave.CodeNotFound)
	}
	rates, err := rd.NodesRealtime(ctx)
	if err != nil {
		return keep(remnawave.ErrorCode(err))
	}
	v := PanelPulse{PanelID: p.ID, At: now, Nodes: make([]NodeSpeed, 0, len(rates))}
	for _, r := range rates {
		v.Nodes = append(v.Nodes, NodeSpeed{NodeUUID: r.NodeUUID, Name: r.Name, DownBps: r.DownBps, UpBps: r.UpBps})
	}
	pl.set(v)
	return ""
}
