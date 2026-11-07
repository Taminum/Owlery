package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/store"
)

// maintenanceView is a machine's window as the page shows it; Active is false when there is none.
type maintenanceView struct {
	Active  bool       `json:"active"`
	Until   *time.Time `json:"until,omitempty"`
	Note    string     `json:"note,omitempty"`
	CanEdit bool       `json:"can_edit"`
}

func (s *Server) maintenanceOf(r *http.Request, a auth.Actor, v store.VPS) (maintenanceView, error) {
	out := maintenanceView{CanEdit: vpsCanEdit(a, v)}
	all, err := s.Store.ActiveMaintenance(r.Context(), time.Now().UTC())
	if err != nil {
		return out, err
	}
	for _, m := range all {
		if m.VPSID == v.ID {
			u := m.Until
			out.Active, out.Until, out.Note = true, &u, m.Note
		}
	}
	return out, nil
}

func (s *Server) getMaintenance(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.vpsNotFound(w, r)
		return
	}
	out, err := s.maintenanceOf(r, a, v)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// putMaintenance opens a window for some hours (or moves the end of the one that is open). While it lasts nothing of the machine is
// reported; open alerts of it close now and come back if the cause is still there when the window ends.
func (s *Server) putMaintenance(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.vpsNotFound(w, r)
		return
	}
	if !vpsCanEdit(a, v) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of a linked panel is required")
		return
	}
	var in struct {
		Hours int    `json:"hours"`
		Note  string `json:"note"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	in.Note = strings.TrimSpace(in.Note)
	if in.Hours < 1 || in.Hours > 168 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_hours", "between 1 hour and 7 days")
		return
	}
	if len([]rune(in.Note)) > 200 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_note", "the note is too long")
		return
	}
	until := time.Now().UTC().Add(time.Duration(in.Hours) * time.Hour)
	if err := s.Store.SetMaintenance(r.Context(), v.ID, until, in.Note); err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "maintenance.start", "server", v.ID, map[string]any{"name": v.Name, "hours": in.Hours})
	out, err := s.maintenanceOf(r, a, v)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// deleteMaintenance ends the window at once.
func (s *Server) deleteMaintenance(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.vpsNotFound(w, r)
		return
	}
	if !vpsCanEdit(a, v) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of a linked panel is required")
		return
	}
	if err := s.Store.ClearMaintenance(r.Context(), v.ID); err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "maintenance.end", "server", v.ID, map[string]any{"name": v.Name})
	out, err := s.maintenanceOf(r, a, v)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, out)
}
