package httpapi

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/site"
	"github.com/Taminum/Owlery/internal/store"
)

var patternRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

func (s *Server) listRules(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	rules, err := s.Store.ListCustomRules(r.Context())
	cats, err2 := s.Store.RuleCategories(r.Context())
	if err != nil || err2 != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules, "categories": cats, "can_edit": a.IsOwner})
}

// createRule adds a classification rule by domain. Rules are global, so only the owner may.
func (s *Server) createRule(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can change classification rules")
		return
	}
	var in struct {
		Pattern  string `json:"pattern"`
		Service  string `json:"service"`
		Category string `json:"category"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	pattern := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Pattern), "."))
	category, catOK := validName(in.Category)
	service, svcOK := validName(in.Service)
	switch {
	case len(pattern) < 4 || len(pattern) > 253 || !patternRe.MatchString(pattern) || site.Of(pattern) == "":
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_pattern", "pattern must be a domain name such as example.com")
		return
	case !catOK || category == "":
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_category", "category must be 1 to 64 characters without control characters")
		return
	case in.Service != "" && !svcOK:
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_service", "service must be 1 to 64 characters without control characters")
		return
	}
	if service == "" {
		service = pattern // no brand given: the site itself names the service
	}
	rule, err := s.Store.UpsertCustomRule(r.Context(), pattern, service, category, "high", a.AccountID)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "rule.upsert", "rule", rule.ID, map[string]any{"pattern": pattern, "category": category})
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can change classification rules")
		return
	}
	pattern, err := s.Store.DeleteCustomRule(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "rule not found")
		return
	}
	s.audit(r, a, "", "rule.delete", "rule", r.PathValue("id"), map[string]any{"pattern": pattern})
	w.WriteHeader(http.StatusNoContent)
}
