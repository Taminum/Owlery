package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/store"
)

type summaryOut struct {
	store.FleetSummary
	From   time.Time             `json:"from"`
	To     time.Time             `json:"to"`
	Owlery *store.OwleryActivity `json:"owlery"` // only for an owner: sign-ins belong to no panel
}

// fleetSummary is the home page's one look at the last day: bans, changes, certificates, who did what in Owlery.
func (s *Server) fleetSummary(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	hours := 24
	if h, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && h >= 1 && h <= 168 {
		hours = h
	}
	to := s.Now().UTC()
	from := to.Add(-time.Duration(hours) * time.Hour)
	sum, err := s.Store.FleetSummary(r.Context(), a.Scope(), from, to)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	out := summaryOut{FleetSummary: sum, From: from, To: to}
	if a.IsOwner {
		act, err := s.Store.OwleryActivity(r.Context(), from, to)
		if err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		out.Owlery = &act
	}
	writeJSON(w, http.StatusOK, out)
}
