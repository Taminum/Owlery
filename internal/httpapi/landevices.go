package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/store"
)

func (s *Server) listLANDevices(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	ds, err := s.Store.ListLANDevices(r.Context(), time.Now().UTC())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"devices": ds})
}

// setLANDevice names a device and marks it as looked at. An empty name only confirms it.
func (s *Server) setLANDevice(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if len(in.Name) > 60 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_name", "a name of up to 60 characters")
		return
	}
	err := s.Store.SetLANDevice(r.Context(), r.PathValue("mac"), strings.TrimSpace(in.Name))
	if errors.Is(err, store.ErrNotFound) {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such device")
		return
	}
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "landevice.set", "landevice", r.PathValue("mac"), map[string]any{"name": strings.TrimSpace(in.Name)})
	w.WriteHeader(http.StatusNoContent)
}
