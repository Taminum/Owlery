package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/store"
)

type templateIn struct {
	OS      string `json:"os"`
	Name    string `json:"name"`
	Command string `json:"command"`
	Note    string `json:"note"`
	Danger  bool   `json:"danger"`
}

func (s *Server) templateInOK(w http.ResponseWriter, r *http.Request, in templateIn, needOS bool) bool {
	if strings.TrimSpace(in.Name) == "" || len(in.Name) > store.MaxTemplateName {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_name", "a name of up to 80 characters is required")
		return false
	}
	if strings.TrimSpace(in.Command) == "" || len(in.Command) > store.MaxTemplateCommand || len(in.Note) > store.MaxTemplateNote {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_command", "a command of up to 2000 characters is required")
		return false
	}
	if needOS && in.OS != "linux" && in.OS != "windows" {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_os", "the system is linux or windows")
		return false
	}
	return true
}

// listCommandTemplates: anyone signed in may read the commands (the terminal tab is shown only to those who may use it).
func (s *Server) listCommandTemplates(w http.ResponseWriter, r *http.Request, _ auth.Actor, _ store.Session) {
	os := r.URL.Query().Get("os")
	if os != "" && os != "linux" && os != "windows" {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_os", "the system is linux or windows")
		return
	}
	ts, err := s.Store.ListCommandTemplates(r.Context(), os)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"templates": ts})
}

func (s *Server) createCommandTemplate(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	var in templateIn
	if !s.decode(w, r, &in) || !s.templateInOK(w, r, in, true) {
		return
	}
	c, err := s.Store.CreateCommandTemplate(r.Context(), store.CommandTemplate{OS: in.OS, Name: in.Name, Command: in.Command, Note: in.Note, Danger: in.Danger})
	switch {
	case errors.Is(err, store.ErrConflict):
		s.writeErr(w, r, http.StatusConflict, "name_taken", "a command with this name already exists")
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
	default:
		s.audit(r, a, "", "template.create", "command_template", c.ID, map[string]any{"os": c.OS, "name": c.Name, "danger": c.Danger})
		writeJSON(w, http.StatusCreated, c)
	}
}

func (s *Server) updateCommandTemplate(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	var in templateIn
	if !s.decode(w, r, &in) || !s.templateInOK(w, r, in, false) {
		return
	}
	id := r.PathValue("id")
	err := s.Store.UpdateCommandTemplate(r.Context(), id, store.CommandTemplate{Name: in.Name, Command: in.Command, Note: in.Note, Danger: in.Danger})
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such command")
	case errors.Is(err, store.ErrConflict):
		s.writeErr(w, r, http.StatusConflict, "name_taken", "a command with this name already exists")
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
	default:
		s.audit(r, a, "", "template.update", "command_template", id, map[string]any{"name": in.Name, "danger": in.Danger})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

func (s *Server) deleteCommandTemplate(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	id := r.PathValue("id")
	switch err := s.Store.DeleteCommandTemplate(r.Context(), id); {
	case errors.Is(err, store.ErrNotFound):
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such command")
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
	default:
		s.audit(r, a, "", "template.delete", "command_template", id, nil)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}
