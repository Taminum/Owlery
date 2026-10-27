package httpapi

import (
	"net/http"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/live"
	"github.com/Taminum/Owlery/internal/store"
)

type liveAgentOut struct {
	AgentID   string        `json:"agent_id"`
	Name      string        `json:"name"`
	PanelID   string        `json:"panel_id"`
	PanelName string        `json:"panel_name"`
	Live      bool          `json:"live"`
	AgeMS     int64         `json:"age_ms"`
	Conns     int           `json:"connections"`
	UpBps     int64         `json:"up_bps"`
	DownBps   int64         `json:"down_bps"`
	Devices   []live.Device `json:"devices"`
	Series    []live.Point  `json:"series"`
}

// liveNow reports what the router agents of the visible panels last said: the speed right now,
// the last five minutes of it, and the busiest devices. Numbers from an agent that has gone quiet
// are marked as not live, and its device list is withheld.
func (s *Server) liveNow(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	req := splitCSV(r.URL.Query().Get("panel_ids"))
	for _, id := range req {
		if !a.Scope().Allows(id) {
			s.writeErr(w, r, http.StatusForbidden, "panel_forbidden", "panel is not available")
			return
		}
	}
	visible, err := s.Store.ListPanels(r.Context(), a.Scope())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	ids := map[string]bool{}
	names := map[string]string{}
	for _, p := range visible {
		if p.Demo || (len(req) > 0 && !contains(req, p.ID)) {
			continue
		}
		ids[p.ID], names[p.ID] = true, p.Name
	}
	out := struct {
		Agents    []liveAgentOut `json:"agents"`
		HasRouter bool           `json:"has_router"`
	}{Agents: []liveAgentOut{}}
	if len(ids) > 0 {
		pids := make([]string, 0, len(ids))
		for id := range ids {
			pids = append(pids, id)
		}
		out.HasRouter, _ = s.Store.HasRouterAgent(r.Context(), pids)
	}
	if s.Live != nil {
		for _, v := range s.Live.Views(ids) {
			o := liveAgentOut{AgentID: v.Source.AgentID, Name: v.Source.Name, PanelID: v.Source.PanelID, PanelName: names[v.Source.PanelID],
				Live: v.Live, AgeMS: v.AgeMS, Series: v.Series, Devices: v.Devices}
			if o.Devices == nil {
				o.Devices = []live.Device{}
			}
			if v.Live {
				o.Conns, o.UpBps, o.DownBps = v.Latest.Conns, v.Latest.Up, v.Latest.Down
			}
			out.Agents = append(out.Agents, o)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}
