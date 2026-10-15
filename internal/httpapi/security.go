package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/netintel"
	"github.com/Taminum/RemnaScope/internal/store"
)

// The security module's unit is the VPS. A server is visible to the owner and to anyone holding a
// role on a panel it is linked to; a manual server with no links is the owner's alone. Creating and
// archiving a server is the owner's; changing one needs an administrator role on a linked panel.

type vpsOut struct {
	store.VPS
	CanEdit bool `json:"can_edit"`
}

func vpsCanEdit(a auth.Actor, v store.VPS) bool {
	if a.IsOwner {
		return true
	}
	for _, l := range v.Links {
		if a.Can(l.PanelID, auth.PermAdmin) {
			return true
		}
	}
	return false
}

func (s *Server) vpsNotFound(w http.ResponseWriter, r *http.Request) {
	s.writeErr(w, r, http.StatusNotFound, "not_found", "server not found")
}

// normAddress validates and normalises one address a person typed: an IP address or a domain, nothing else.
func normAddress(raw string) (store.VPSAddress, bool) {
	tg, err := netintel.Parse(raw)
	if err != nil {
		return store.VPSAddress{}, false
	}
	switch tg.Kind {
	case netintel.KindIP:
		a := store.VPSAddress{Address: tg.Addr.Unmap().String(), Kind: "ipv6"}
		if tg.Addr.Unmap().Is4() {
			a.Kind = "ipv4"
		}
		return a, true
	case netintel.KindDomain:
		return store.VPSAddress{Address: tg.Value, Kind: "domain"}, true
	}
	return store.VPSAddress{}, false
}

func vpsAddresses(in []string) ([]store.VPSAddress, string) {
	if len(in) > store.MaxVPSAddresses {
		return nil, "too many addresses"
	}
	seen := map[string]bool{}
	out := make([]store.VPSAddress, 0, len(in))
	for _, raw := range in {
		a, ok := normAddress(raw)
		if !ok {
			return nil, "invalid address: " + strings.TrimSpace(raw)
		}
		if !seen[a.Address] {
			seen[a.Address] = true
			out = append(out, a)
		}
	}
	return out, ""
}

func (s *Server) vpsNote(w http.ResponseWriter, r *http.Request, note string) (string, bool) {
	note = strings.TrimSpace(note)
	if len([]rune(note)) > 500 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_note", "note is at most 500 characters")
		return "", false
	}
	return note, true
}

func (s *Server) listVPS(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	vs, err := s.Store.ListVPS(r.Context(), a.Scope())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	out := make([]vpsOut, 0, len(vs))
	for _, v := range vs {
		out = append(out, vpsOut{VPS: v, CanEdit: vpsCanEdit(a, v)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "can_create": a.IsOwner})
}

func (s *Server) getVPS(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.vpsNotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, vpsOut{VPS: v, CanEdit: vpsCanEdit(a, v)})
}

func (s *Server) createVPS(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can add a server")
		return
	}
	var in struct {
		Name      string   `json:"name"`
		Note      string   `json:"note"`
		Addresses []string `json:"addresses"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	name, ok := validName(in.Name)
	if !ok {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_name", "name must be 1 to 64 characters without control characters")
		return
	}
	note, ok := s.vpsNote(w, r, in.Note)
	if !ok {
		return
	}
	addrs, bad := vpsAddresses(in.Addresses)
	if bad != "" {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_address", bad)
		return
	}
	v, err := s.Store.CreateVPS(r.Context(), a.AccountID, name, note, addrs)
	switch {
	case errors.Is(err, store.ErrConflict):
		s.writeErr(w, r, http.StatusConflict, "name_taken", "a server with this name already exists")
		return
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "security.vps.create", "vps", v.ID, map[string]any{"name": v.Name})
	writeJSON(w, http.StatusCreated, vpsOut{VPS: v, CanEdit: true})
}

func (s *Server) patchVPS(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	id := r.PathValue("id")
	cur, err := s.Store.GetVPS(r.Context(), a.Scope(), id)
	if err != nil {
		s.vpsNotFound(w, r)
		return
	}
	if !vpsCanEdit(a, cur) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of a linked panel is required")
		return
	}
	var in struct {
		Name      *string   `json:"name"`
		Note      *string   `json:"note"`
		Enabled   *bool     `json:"enabled"`
		Addresses *[]string `json:"addresses"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	var p store.VPSPatch
	p.Enabled = in.Enabled
	if in.Name != nil {
		n, ok := validName(*in.Name)
		if !ok {
			s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_name", "name must be 1 to 64 characters without control characters")
			return
		}
		p.Name = &n
	}
	if in.Note != nil {
		n, ok := s.vpsNote(w, r, *in.Note)
		if !ok {
			return
		}
		p.Note = &n
	}
	if in.Addresses != nil {
		addrs, bad := vpsAddresses(*in.Addresses)
		if bad != "" {
			s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_address", bad)
			return
		}
		p.Addresses = &addrs
	}
	v, err := s.Store.UpdateVPS(r.Context(), a.Scope(), id, p)
	switch {
	case errors.Is(err, store.ErrConflict):
		s.writeErr(w, r, http.StatusConflict, "name_taken", "a server with this name already exists")
		return
	case errors.Is(err, store.ErrNotFound):
		s.vpsNotFound(w, r)
		return
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "security.vps.update", "vps", v.ID, nil)
	writeJSON(w, http.StatusOK, vpsOut{VPS: v, CanEdit: vpsCanEdit(a, v)})
}

// archiveVPS hides a server and keeps its history. Hard deletion is not offered in v1.
func (s *Server) archiveVPS(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if _, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id")); err != nil {
		s.vpsNotFound(w, r)
		return
	}
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can archive a server")
		return
	}
	if err := s.Store.ArchiveVPS(r.Context(), a.Scope(), r.PathValue("id")); err != nil {
		s.vpsNotFound(w, r)
		return
	}
	s.audit(r, a, "", "security.vps.archive", "vps", r.PathValue("id"), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) addVPSLink(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	id := r.PathValue("id")
	if _, err := s.Store.GetVPS(r.Context(), a.Scope(), id); err != nil {
		s.vpsNotFound(w, r)
		return
	}
	var in struct {
		PanelID string `json:"panel_id"`
		NodeID  string `json:"node_id"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if !a.Scope().Allows(in.PanelID) {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "panel not found")
		return
	}
	if !a.Can(in.PanelID, auth.PermAdmin) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of the panel is required")
		return
	}
	l, err := s.Store.AddVPSLink(r.Context(), a.Scope(), id, in.PanelID, in.NodeID, a.AccountID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.writeErr(w, r, http.StatusNotFound, "not_found", "panel or node not found")
		return
	case errors.Is(err, store.ErrConflict):
		s.writeErr(w, r, http.StatusConflict, "already_linked", "this link already exists")
		return
	case errors.Is(err, store.ErrLimit):
		s.writeErr(w, r, http.StatusConflict, "limit", "too many links")
		return
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, in.PanelID, "security.vps.link", "vps", id, map[string]any{"link_id": l.ID, "node_id": in.NodeID})
	writeJSON(w, http.StatusCreated, l)
}

func (s *Server) removeVPSLink(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	id, linkID := r.PathValue("id"), r.PathValue("link")
	if _, err := s.Store.GetVPS(r.Context(), a.Scope(), id); err != nil {
		s.vpsNotFound(w, r)
		return
	}
	panelID, err := s.Store.VPSLinkPanel(r.Context(), id, linkID)
	if err != nil || !a.Scope().Allows(panelID) {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "link not found")
		return
	}
	if !a.Can(panelID, auth.PermAdmin) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of the panel is required")
		return
	}
	if err := s.Store.RemoveVPSLink(r.Context(), id, linkID); err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "link not found")
		return
	}
	s.audit(r, a, panelID, "security.vps.unlink", "vps", id, map[string]any{"link_id": linkID})
	w.WriteHeader(http.StatusNoContent)
}
