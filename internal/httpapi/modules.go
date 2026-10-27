package httpapi

import (
	"net/http"
	"slices"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/store"
)

// moduleList says which optional parts are on; every signed-in person needs it to draw the menu.
func (s *Server) moduleList(w http.ResponseWriter, r *http.Request, _ auth.Actor, _ store.Session) {
	ms, err := s.Store.ModuleStates(r.Context())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"modules": ms})
}

// moduleSet turns a module on or off. It is the owner's: it changes what everybody sees.
func (s *Server) moduleSet(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can turn modules on and off")
		return
	}
	id := r.PathValue("id")
	if !slices.Contains(store.Modules, id) {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such module")
		return
	}
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if in.Enabled == nil {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_module", "enabled is required")
		return
	}
	if err := s.Store.SetModule(r.Context(), id, *in.Enabled, a.AccountID); err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "module.set", "module", id, map[string]any{"enabled": *in.Enabled})
	s.moduleList(w, r, a, store.Session{})
}
