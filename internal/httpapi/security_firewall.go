package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/secfw"
	"github.com/Taminum/Owlery/internal/store"
)

// fwHistory lists a server's stored firewall readings, newest first. A reading is stored only when the
// rules or the verdict changed, so this is a list of changes, not of polls.
func (s *Server) fwHistory(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.visibleVPS(w, r, a)
	if !ok {
		return
	}
	limit := 30
	if x := r.URL.Query().Get("limit"); x != "" {
		n, err := strconv.Atoi(x)
		if err != nil || n < 1 || n > 100 {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_limit", "limit must be 1 to 100")
			return
		}
		limit = n
	}
	items, err := s.Store.FirewallSnapshots(r.Context(), a.Scope(), v.ID, limit, false)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type fwRef struct {
	ID         string    `json:"id"`
	ObservedAt time.Time `json:"observed_at"`
	Hash       string    `json:"hash"`
	Backend    string    `json:"backend"`
}

// fwDiff compares two stored readings (by id), or by default the two newest complete ones. The answer is
// a difference of rule text, canonicalised by the agent (counters, handles and Fail2ban's bans are gone),
// so it shows changes of the rules and not the noise of a running firewall.
func (s *Server) fwDiff(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.visibleVPS(w, r, a)
	if !ok {
		return
	}
	q := r.URL.Query()
	var older, newer store.FWSnapshot
	if q.Get("from") != "" || q.Get("to") != "" {
		var err error
		if older, err = s.Store.FirewallSnapshot(r.Context(), a.Scope(), v.ID, q.Get("from")); err != nil {
			s.writeErr(w, r, http.StatusNotFound, "not_found", "snapshot not found")
			return
		}
		if newer, err = s.Store.FirewallSnapshot(r.Context(), a.Scope(), v.ID, q.Get("to")); err != nil {
			s.writeErr(w, r, http.StatusNotFound, "not_found", "snapshot not found")
			return
		}
	} else {
		list, err := s.Store.FirewallSnapshots(r.Context(), a.Scope(), v.ID, 50, true)
		if err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		var ok2 []store.FWSnapshot
		for _, x := range list {
			if x.Status == "ok" {
				ok2 = append(ok2, x)
			}
		}
		if len(ok2) < 2 {
			writeJSON(w, http.StatusOK, map[string]any{"available": false, "reason": "fewer_than_two_readings"})
			return
		}
		newer, older = ok2[0], ok2[1]
	}
	if older.Status != "ok" || newer.Status != "ok" {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "reason": "a_reading_was_incomplete"})
		return
	}
	lines, added, removed, trunc := secfw.Diff(older.Rules, newer.Rules, 2, 400)
	if lines == nil {
		lines = []secfw.Line{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"available":       true,
		"from":            fwRef{older.ID, older.ObservedAt, older.Hash, older.Backend},
		"to":              fwRef{newer.ID, newer.ObservedAt, newer.Hash, newer.Backend},
		"backend_changed": older.Backend != newer.Backend,
		"added":           added, "removed": removed, "truncated": trunc, "lines": lines,
	})
}

// fwModel reads the firewall category's data into the structured model, for the screen.
func fwModel(data json.RawMessage) *secfw.Model {
	var d struct {
		Backend string `json:"backend"`
		Rules   string `json:"rules"`
	}
	if json.Unmarshal(data, &d) != nil || d.Backend == "" {
		return nil
	}
	m := secfw.Parse(d.Backend, d.Rules)
	return &m
}
