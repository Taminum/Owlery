package httpapi

import (
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/store"
)

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)

type accountFullDTO struct {
	ID          string             `json:"id"`
	Username    string             `json:"username"`
	IsOwner     bool               `json:"is_owner"`
	Disabled    bool               `json:"disabled"`
	LastLoginAt *time.Time         `json:"last_login_at"`
	CreatedAt   time.Time          `json:"created_at"`
	Memberships []store.Membership `json:"memberships"`
}

func (s *Server) requireOwner(w http.ResponseWriter, r *http.Request, a auth.Actor) bool {
	if !a.CanGlobal() {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only owners can manage accounts")
		return false
	}
	return true
}

func (s *Server) listAccounts(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.requireOwner(w, r, a) {
		return
	}
	accs, err := s.Store.ListAccounts(r.Context())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	out := make([]accountFullDTO, 0, len(accs))
	for _, ac := range accs {
		ms, _ := s.Store.Memberships(r.Context(), ac.ID)
		if ms == nil {
			ms = []store.Membership{}
		}
		out = append(out, accountFullDTO{ID: ac.ID, Username: ac.Username, IsOwner: ac.IsOwner, Disabled: ac.Disabled,
			LastLoginAt: ac.LastLoginAt, CreatedAt: ac.CreatedAt, Memberships: ms})
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": out})
}

// validMemberships checks roles and that every panel exists. Account management is
// owner-only, so the owner's scope (all panels) is the right lens.
func (s *Server) validMemberships(r *http.Request, ms []store.Membership) (string, bool) {
	seen := map[string]bool{}
	for _, m := range ms {
		if !auth.ValidRole(m.Role) {
			return "role must be viewer, operator or admin", false
		}
		if seen[m.PanelID] {
			return "a panel can appear only once", false
		}
		seen[m.PanelID] = true
		if _, err := s.Store.GetPanel(r.Context(), store.Scope{All: true}, m.PanelID); err != nil {
			return "unknown panel", false
		}
	}
	return "", true
}

func (s *Server) createAccount(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.requireOwner(w, r, a) {
		return
	}
	var in struct {
		Username    string             `json:"username"`
		Password    string             `json:"password"`
		IsOwner     bool               `json:"is_owner"`
		Memberships []store.Membership `json:"memberships"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if !usernameRe.MatchString(in.Username) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_username", "username must be 3 to 64 letters, digits, dots, dashes or underscores")
		return
	}
	if err := auth.ValidatePassword(in.Username, in.Password); err != nil {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "weak_password", err.Error())
		return
	}
	if msg, ok := s.validMemberships(r, in.Memberships); !ok {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_memberships", msg)
		return
	}
	h, err := auth.HashPassword(in.Password, s.Hash)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	acc, err := s.Store.CreateAccount(r.Context(), in.Username, h, in.IsOwner)
	if errors.Is(err, store.ErrConflict) {
		s.writeErr(w, r, http.StatusConflict, "username_taken", "this username is taken")
		return
	}
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if len(in.Memberships) > 0 {
		if err := s.Store.SetMemberships(r.Context(), acc.ID, in.Memberships); err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
	}
	s.audit(r, a, "", "account.create", "account", acc.ID, map[string]any{"username": acc.Username, "is_owner": acc.IsOwner, "panels": len(in.Memberships)})
	ms := in.Memberships
	if ms == nil {
		ms = []store.Membership{}
	}
	writeJSON(w, http.StatusCreated, accountFullDTO{ID: acc.ID, Username: acc.Username, IsOwner: acc.IsOwner, CreatedAt: acc.CreatedAt, Memberships: ms})
}

func (s *Server) patchAccount(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.requireOwner(w, r, a) {
		return
	}
	id := r.PathValue("id")
	acc, err := s.Store.AccountByID(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "account not found")
		return
	}
	var in struct {
		Disabled *bool   `json:"disabled"`
		Password *string `json:"password"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if in.Disabled == nil && in.Password == nil {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "nothing_to_change", "pass disabled and/or password")
		return
	}
	if in.Disabled != nil && *in.Disabled && acc.ID == a.AccountID {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "cannot_disable_self", "you cannot disable your own account")
		return
	}
	if in.Password != nil {
		if err := auth.ValidatePassword(acc.Username, *in.Password); err != nil {
			s.writeErr(w, r, http.StatusUnprocessableEntity, "weak_password", err.Error())
			return
		}
		h, err := auth.HashPassword(*in.Password, s.Hash)
		if err != nil || s.Store.SetPassword(r.Context(), acc.ID, h) != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		s.audit(r, a, "", "account.password_reset", "account", acc.ID, map[string]any{"username": acc.Username})
	}
	if in.Disabled != nil {
		if err := s.Store.SetAccountDisabled(r.Context(), acc.ID, *in.Disabled); err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		action := "account.enable"
		if *in.Disabled {
			action = "account.disable"
		}
		s.audit(r, a, "", action, "account", acc.ID, map[string]any{"username": acc.Username})
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) setMemberships(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.requireOwner(w, r, a) {
		return
	}
	acc, err := s.Store.AccountByID(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "account not found")
		return
	}
	var in struct {
		Memberships []store.Membership `json:"memberships"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if msg, ok := s.validMemberships(r, in.Memberships); !ok {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_memberships", msg)
		return
	}
	if err := s.Store.SetMemberships(r.Context(), acc.ID, in.Memberships); err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "account.memberships", "account", acc.ID, map[string]any{"username": acc.Username, "memberships": in.Memberships})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	q := r.URL.Query()
	var before time.Time
	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_cursor", "before must be an RFC 3339 time")
			return
		}
		before = t
	}
	sc := a.ScopeAt(auth.PermAdmin)
	pid := q.Get("panel_id")
	if pid != "" && !a.Can(pid, auth.PermAdmin) {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "panel not found")
		return
	}
	rows, err := s.Store.ListAudit(r.Context(), sc, pid, before, 50)
	if err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "panel not found")
		return
	}
	if rows == nil {
		rows = []store.AuditRow{}
	}
	next := ""
	if len(rows) == 50 {
		next = rows[len(rows)-1].TS.Format(time.RFC3339Nano)
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": rows, "next_before": next})
}
