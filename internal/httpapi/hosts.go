package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/store"
)

// hostList says how loaded each monitored server is: the machine, the latest reading and the last hour.
func (s *Server) hostList(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	hosts, err := s.Store.Hosts(r.Context(), a.Scope(), time.Now().UTC())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"hosts": hosts})
}

// hostSeries is the history of one server for the last hours (1 to 168), at most 300 points.
func (s *Server) hostSeries(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 168 {
			s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_range", "hours must be 1 to 168")
			return
		}
		hours = n
	}
	pts, err := s.Store.HostSeries(r.Context(), a.Scope(), r.PathValue("id"), hours, time.Now().UTC(), 300)
	if err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "server not found")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"hours": hours, "points": pts})
}
