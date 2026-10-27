package httpapi

import (
	"net/http"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/store"
)

// serverOut is one machine of the fleet as a whole: what a person said about it, what its agent measures, which
// nodes run on it and what is wrong with it.
type serverOut struct {
	store.VPS
	CanEdit  bool               `json:"can_edit"`
	Status   string             `json:"status"` // ok | warn | bad | unknown
	Reason   string             `json:"reason"` // why it is not ok: offline | critical | alerts | no_agent
	Host     *store.HostRow     `json:"host"`
	Nodes    []store.ServerNode `json:"nodes"`
	Open     int                `json:"alerts_open"`
	Critical int                `json:"alerts_critical"`
	Alerts   []store.Alert      `json:"alerts,omitempty"` // only on the card: open and the last 30 days
}

// serverStatus is the one colour of a machine. No agent says nothing about it, so it is "unknown", not "ok".
func serverStatus(h *store.HostRow, open, critical int) (string, string) {
	switch {
	case h == nil || !h.HasData:
		return "unknown", "no_agent"
	case !h.Online:
		return "bad", "offline"
	case critical > 0:
		return "bad", "critical"
	case open > 0:
		return "warn", "alerts"
	}
	return "ok", ""
}

func (s *Server) servers(r *http.Request, a auth.Actor, vs []store.VPS, withAlerts bool) ([]serverOut, error) {
	ids := make([]string, len(vs))
	for i, v := range vs {
		ids[i] = v.ID
	}
	now := s.Now().UTC()
	hosts, err := s.Store.Hosts(r.Context(), a.Scope(), now)
	if err != nil {
		return nil, err
	}
	byID := map[string]*store.HostRow{}
	for i := range hosts {
		byID[hosts[i].ID] = &hosts[i]
	}
	since := now
	if withAlerts {
		since = now.Add(-30 * 24 * time.Hour)
	}
	alerts, err := s.Store.ServerAlerts(r.Context(), ids, since)
	if err != nil {
		return nil, err
	}
	nodes, err := s.Store.ServerNodes(r.Context(), a.Scope(), ids)
	if err != nil {
		return nil, err
	}
	out := make([]serverOut, 0, len(vs))
	for _, v := range vs {
		o := serverOut{VPS: v, CanEdit: vpsCanEdit(a, v), Host: byID[v.ID], Nodes: nodes[v.ID]}
		if o.Nodes == nil {
			o.Nodes = []store.ServerNode{}
		}
		for _, al := range alerts[v.ID] {
			if al.ResolvedAt == nil {
				o.Open++
				if store.CriticalKinds[al.Kind] {
					o.Critical++
				}
			}
		}
		o.Status, o.Reason = serverStatus(o.Host, o.Open, o.Critical)
		if withAlerts {
			o.Alerts = alerts[v.ID]
			if o.Alerts == nil {
				o.Alerts = []store.Alert{}
			}
		}
		out = append(out, o)
	}
	return out, nil
}

// serverList is the fleet: every machine the caller can see, with its colour and latest reading.
func (s *Server) serverList(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	vs, err := s.Store.ListVPS(r.Context(), a.Scope())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	out, err := s.servers(r, a, vs, false)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"servers": out, "roles": store.ServerRoles})
}

// serverCard is one machine with its alerts of the last 30 days.
func (s *Server) serverCard(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.vpsNotFound(w, r)
		return
	}
	out, err := s.servers(r, a, []store.VPS{v}, true)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out[0])
}
