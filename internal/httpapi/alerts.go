package httpapi

import (
	"net/http"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/store"
)

type alertOut struct {
	ID         string     `json:"id"`
	PanelID    string     `json:"panel_id"`
	PanelName  string     `json:"panel_name"`
	Kind       string     `json:"kind"`
	Label      string     `json:"label"`
	Detail     string     `json:"detail"`
	OpenedAt   time.Time  `json:"opened_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	ResolvedAt *time.Time `json:"resolved_at"`
}

// listAlerts returns the alerts of the panels the caller may see (and asked for).
func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	qs := r.URL.Query()
	req := splitCSV(qs.Get("panel_ids"))
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
	var ids []string
	names := map[string]string{}
	for _, p := range visible {
		if p.Demo || (len(req) > 0 && !contains(req, p.ID)) {
			continue
		}
		ids = append(ids, p.ID)
		names[p.ID] = p.Name
	}
	out := struct {
		Alerts []alertOut `json:"alerts"`
		Open   int        `json:"open"`
	}{Alerts: []alertOut{}}
	if len(ids) > 0 {
		list, err := s.Store.ListAlerts(r.Context(), ids, qs.Get("state") != "all", 200)
		if err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		for _, x := range list {
			if x.ResolvedAt == nil {
				out.Open++
			}
			out.Alerts = append(out.Alerts, alertOut{ID: x.ID, PanelID: x.PanelID, PanelName: names[x.PanelID], Kind: x.Kind, Label: x.Label, Detail: x.Detail,
				OpenedAt: x.OpenedAt.UTC(), LastSeenAt: x.LastSeenAt.UTC(), ResolvedAt: x.ResolvedAt})
		}
	}
	writeJSON(w, http.StatusOK, out)
}
