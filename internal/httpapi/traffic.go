package httpapi

import (
	"net/http"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/store"
)

const sourcePanelCounters = "panel_api_counters"

type trafficNodeOut struct {
	NodeID     string     `json:"node_id"`
	Name       string     `json:"name"`
	Bytes      int64      `json:"bytes"`
	Share      float64    `json:"share"`
	Resets     int        `json:"counter_resets"`
	CounterNow int64      `json:"counter_bytes"`
	LastSample *time.Time `json:"last_sample"`
	Samples    int        `json:"samples"`
}

type trafficUserOut struct {
	PanelID   string  `json:"panel_id"`
	PanelName string  `json:"panel_name"`
	Label     string  `json:"label"`
	Note      string  `json:"note,omitempty"`
	Bytes     int64   `json:"bytes"`
	Share     float64 `json:"share"`
	Counter   string  `json:"counter"` // lifetime | period
}

type trafficPointOut struct {
	TS    int64 `json:"ts"`
	Bytes int64 `json:"bytes"`
}

// analyticsTraffic reports bytes from the panel's own cumulative counters. They are totals:
// the panel gives no up/down split, so none is shown, and nothing here is derived from log lines.
func (s *Server) analyticsTraffic(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	sc, ok := s.resolveScope(w, r, a)
	if !ok {
		return
	}
	nodes, err := s.Store.NodesInScope(r.Context(), sc.ids, sc.nodeIDs)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	meta := s.metaFor(r, sc, nodes)
	meta.MetricKind, meta.Source = "bytes", sourcePanelCounters
	// Counters come from the panel API, not from agents: agent coverage does not decide the state.
	meta.State, meta.Reason = "ok", ""
	if len(sc.ids) == 0 {
		meta.State, meta.Reason = "no_data", "no_real_panels"
	}
	out := struct {
		Meta       aMeta             `json:"meta"`
		Direction  string            `json:"direction"`
		TotalBytes int64             `json:"total_bytes"`
		UsersBytes int64             `json:"users_total_bytes"`
		Resets     int               `json:"counter_resets"`
		Samples    int               `json:"samples"`
		FirstAt    *time.Time        `json:"first_sample"`
		LastAt     *time.Time        `json:"last_sample"`
		Timeline   []trafficPointOut `json:"timeline"`
		Nodes      []trafficNodeOut  `json:"nodes"`
		Users      []trafficUserOut  `json:"users"`
	}{Meta: meta, Direction: "total", Timeline: []trafficPointOut{}, Nodes: []trafficNodeOut{}, Users: []trafficUserOut{}}
	if meta.State == "ok" {
		q := sc.query()
		sum, err := s.Store.TrafficSummaryFor(r.Context(), q)
		if err == nil {
			var nrows []store.TrafficNode
			var urows []store.TrafficUser
			if nrows, err = s.Store.TrafficByNode(r.Context(), q); err == nil {
				urows, err = s.Store.TrafficByUser(r.Context(), q, 50)
			}
			if err == nil {
				out.TotalBytes, out.UsersBytes, out.Resets, out.Samples = sum.NodeBytes, sum.UserBytes, sum.Resets, sum.Samples
				out.FirstAt, out.LastAt = sum.First, sum.Last
				for _, p := range sum.Timeline {
					out.Timeline = append(out.Timeline, trafficPointOut{TS: p.TS.Unix(), Bytes: p.Bytes})
				}
				for _, n := range nrows {
					o := trafficNodeOut{NodeID: n.NodeID, Name: n.Name, Bytes: n.Bytes, Resets: n.Resets, CounterNow: n.Current, Samples: n.Samples}
					if !n.Last.IsZero() {
						t := n.Last.UTC()
						o.LastSample = &t
					}
					if out.TotalBytes > 0 {
						o.Share = float64(n.Bytes) * 100 / float64(out.TotalBytes)
					}
					out.Nodes = append(out.Nodes, o)
				}
				for _, u := range urows {
					l, note := s.label(a, u.PanelID, u.Name, u.RemoteID, false)
					c := "period"
					if u.Source == store.SrcUserLifetime {
						c = "lifetime"
					}
					o := trafficUserOut{PanelID: u.PanelID, PanelName: sc.names[u.PanelID], Label: l, Note: note, Bytes: u.Bytes, Counter: c}
					if out.UsersBytes > 0 {
						o.Share = float64(u.Bytes) * 100 / float64(out.UsersBytes)
					}
					out.Users = append(out.Users, o)
				}
			}
		}
		if err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		if out.Samples == 0 {
			out.Meta.State, out.Meta.Reason = "no_data", "no_counters"
		}
	}
	writeJSON(w, http.StatusOK, out)
}
