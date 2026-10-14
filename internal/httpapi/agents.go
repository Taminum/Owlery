package httpapi

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/ingestproto"
	"github.com/Taminum/RemnaScope/internal/store"
)

var coversRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	p, ok := s.panelFor(w, r, a, auth.PermOperate)
	if !ok {
		return
	}
	list, err := s.Store.ListAgents(r.Context(), a.Scope(), p.ID)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if list == nil {
		list = []store.Agent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": list, "ingest_path": ingestproto.Path})
}

// createAgent enrols an agent for one node. The credential is shown once, here, and only its
// hash is stored: it cannot be read back later, only replaced by revoking and enrolling again.
func (s *Server) createAgent(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	p, ok := s.panelFor(w, r, a, auth.PermAdmin)
	if !ok {
		return
	}
	if p.Demo {
		s.writeErr(w, r, http.StatusConflict, "demo_panel", "demo panels have no nodes to attach an agent to")
		return
	}
	var in struct {
		NodeID string `json:"node_id"`
		Name   string `json:"name"`
		Kind   string `json:"kind"`
		// CoversUser is, for a router agent, the panel user the router appears as on the nodes.
		CoversUser string `json:"covers_user"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if in.Kind == "" {
		in.Kind = "node"
	}
	if in.Kind != "node" && in.Kind != "router" && in.Kind != "awg" {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_kind", "kind must be node, router or awg")
		return
	}
	if in.CoversUser != "" && (in.Kind != "router" || len(in.CoversUser) > 64 || !coversRe.MatchString(in.CoversUser)) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_covers_user", "covers_user is only for router agents and must be the panel user id")
		return
	}
	name, nameOK := validName(in.Name)
	if in.Name != "" && !nameOK {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_name", "name must be 1 to 64 characters without control characters")
		return
	}
	secret, err := auth.NewToken()
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	ag, err := s.Store.CreateAgent(r.Context(), a.Scope(), p.ID, in.NodeID, name, in.Kind, in.CoversUser, store.HashAgentSecret(secret))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.writeErr(w, r, http.StatusNotFound, "not_found", "node not found in this panel")
		return
	case errors.Is(err, store.ErrConflict):
		s.writeErr(w, r, http.StatusConflict, "agent_exists", "this node already has an agent; revoke it first")
		return
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, p.ID, "agent.create", "agent", ag.ID, map[string]any{"node": ag.NodeName, "kind": ag.Kind})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"agent": ag, "token": ag.ID + "." + secret, "ingest_path": ingestproto.Path})
}

func (s *Server) revokeAgent(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	p, ok := s.panelFor(w, r, a, auth.PermAdmin)
	if !ok {
		return
	}
	id := r.PathValue("agent")
	if err := s.Store.RevokeAgent(r.Context(), a.Scope(), p.ID, id); err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "agent not found")
		return
	}
	s.audit(r, a, p.ID, "agent.revoke", "agent", id, nil)
	w.WriteHeader(http.StatusNoContent)
}
