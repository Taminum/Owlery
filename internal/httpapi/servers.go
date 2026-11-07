package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/store"
)

// serverOut is one machine of the fleet as a whole: what a person said about it, what its agent measures, which
// nodes run on it and what is wrong with it.
type serverOut struct {
	store.VPS
	CanEdit    bool               `json:"can_edit"`
	Status     string             `json:"status"` // ok | warn | bad | unknown
	Reason     string             `json:"reason"` // why it is not ok: offline | critical | alerts | no_agent
	Host       *store.HostRow     `json:"host"`
	Nodes      []store.ServerNode `json:"nodes"`
	Open       int                `json:"alerts_open"`
	Critical   int                `json:"alerts_critical"`
	Alerts     []store.Alert      `json:"alerts,omitempty"`      // only on the card: open and the last 30 days
	ExternalIP string             `json:"external_ip"`           // where its agent connected from; empty until it has, or without an agent
	Wol        bool               `json:"wol,omitempty"`         // Wake-on-LAN is turned on for it
	MaintUntil *time.Time         `json:"maint_until,omitempty"` // a maintenance window is open until then
	MaintNote  string             `json:"maint_note,omitempty"`
	Agent      *store.AgentBrief  `json:"agent"` // its live agent: version, whether it is connected and whether it may be updated from the card
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
	ips, err := s.Store.AgentRemoteIPs(r.Context(), ids)
	if err != nil {
		return nil, err
	}
	briefs, err := s.Store.AgentBriefs(r.Context(), ids, now.Add(-secproto.StaleAfter))
	if err != nil {
		return nil, err
	}
	wols, err := s.Store.WolEnabled(r.Context(), ids)
	if err != nil {
		return nil, err
	}
	windows, err := s.Store.ActiveMaintenance(r.Context(), now)
	if err != nil {
		return nil, err
	}
	until := map[string]store.Maintenance{}
	for _, m := range windows {
		until[m.VPSID] = m
	}
	nodes, err := s.Store.ServerNodes(r.Context(), a.Scope(), ids)
	if err != nil {
		return nil, err
	}
	out := make([]serverOut, 0, len(vs))
	for _, v := range vs {
		o := serverOut{VPS: v, CanEdit: vpsCanEdit(a, v), Host: byID[v.ID], Nodes: nodes[v.ID], ExternalIP: ips[v.ID]}
		o.Wol = wols[v.ID]
		if m, ok := until[v.ID]; ok {
			u := m.Until
			o.MaintUntil, o.MaintNote = &u, m.Note
		}
		if b, ok := briefs[v.ID]; ok {
			o.Agent = &b
		}
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
		s.applyPulse(o.Host, v.ID, now)
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
	// What the machine is made of, as its agent last read it; nil until it has.
	var hw, dk json.RawMessage // the hardware, and the containers when the agent listed them a moment ago
	if states, err := s.Store.SnapshotStates(r.Context(), a.Scope(), v.ID); err == nil {
		for _, st := range states {
			if st.Category == secproto.CatHardware && st.Status == secproto.StatusOK && len(st.Data) > 2 {
				hw = st.Data
			}
			if st.Category == secproto.CatDocker && st.Status == secproto.StatusOK && len(st.Data) > 2 && time.Since(st.ReceivedAt) < 5*time.Minute {
				dk = st.Data
			}
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, struct {
		serverOut
		Hardware json.RawMessage `json:"hardware"`
		Docker   json.RawMessage `json:"docker"`
	}{out[0], hw, dk})
}
