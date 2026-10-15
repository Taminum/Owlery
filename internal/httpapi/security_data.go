package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/secchecks"
	"github.com/Taminum/RemnaScope/internal/secfw"
	"github.com/Taminum/RemnaScope/internal/secproto"
	"github.com/Taminum/RemnaScope/internal/store"
)

// visibleVPS loads the server for the actor or writes "not found".
func (s *Server) visibleVPS(w http.ResponseWriter, r *http.Request, a auth.Actor) (store.VPS, bool) {
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.vpsNotFound(w, r)
		return v, false
	}
	return v, true
}

type secAgentOut struct {
	store.SecAgent
	Online bool `json:"online"`
}

func (s *Server) agentOut(ag store.SecAgent) secAgentOut {
	return secAgentOut{SecAgent: ag, Online: ag.LastSeen != nil && s.Now().Sub(*ag.LastSeen) < secproto.StaleAfter}
}

// getSecAgent reports the server's agent. "Online" is only about the agent's connection: it says nothing
// about whether the things it reads are healthy.
func (s *Server) getSecAgent(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.visibleVPS(w, r, a)
	if !ok {
		return
	}
	ag, err := s.Store.SecAgentOf(r.Context(), v.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"agent": nil})
		return
	}
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent": s.agentOut(ag)})
}

// createSecAgent issues the server's one agent credential. The secret is shown once.
func (s *Server) createSecAgent(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.visibleVPS(w, r, a)
	if !ok {
		return
	}
	if !vpsCanEdit(a, v) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of a linked panel is required")
		return
	}
	secret, err := auth.NewToken()
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	ag, err := s.Store.CreateSecAgent(r.Context(), v.ID, a.AccountID, store.HashAgentSecret(secret))
	switch {
	case errors.Is(err, store.ErrConflict):
		s.writeErr(w, r, http.StatusConflict, "agent_exists", "this server already has an agent; revoke it first")
		return
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "security.agent.create", "vps", v.ID, map[string]any{"agent_id": ag.ID})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"agent": s.agentOut(ag), "token": ag.ID + "." + secret, "ingest_path": secproto.Path})
}

func (s *Server) revokeSecAgent(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.visibleVPS(w, r, a)
	if !ok {
		return
	}
	if !vpsCanEdit(a, v) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of a linked panel is required")
		return
	}
	if err := s.Store.RevokeSecAgent(r.Context(), v.ID); err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no agent")
		return
	}
	s.audit(r, a, "", "security.agent.revoke", "vps", v.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

type secCategoryOut struct {
	Category    string          `json:"category"`
	State       string          `json:"state"` // agent_required | waiting | ok | stale | not_installed | stopped | permission_denied | unsupported | error
	Status      string          `json:"status,omitempty"`
	ObservedAt  *time.Time      `json:"observed_at"`
	ReceivedAt  *time.Time      `json:"received_at"`
	ClockSkewMS int64           `json:"clock_skew_ms"`
	Data        json.RawMessage `json:"data"`
	Agent       *secAgentOut    `json:"agent"`
	Manage      *manageInfo     `json:"manage,omitempty"` // fail2ban only: whether a ban or unban can be sent
	Model       *secfw.Model    `json:"model,omitempty"`  // firewall only: the rules read into tables and chains
}

// secCategory serves the latest snapshot of one category. A server with no agent says so; a snapshot
// that stopped refreshing is "stale" and keeps its own time, never presented as current.
func (s *Server) secCategory(category string) authedHandler {
	return func(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
		v, ok := s.visibleVPS(w, r, a)
		if !ok {
			return
		}
		out := secCategoryOut{Category: category, State: "agent_required", Data: json.RawMessage("null")}
		if ag, err := s.Store.SecAgentOf(r.Context(), v.ID); err == nil {
			ao := s.agentOut(ag)
			out.Agent, out.State = &ao, "waiting"
		} else if !errors.Is(err, store.ErrNotFound) {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		states, err := s.Store.SnapshotStates(r.Context(), a.Scope(), v.ID)
		if err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		for _, st := range states {
			if st.Category != category {
				continue
			}
			obs, rec := st.ObservedAt, st.ReceivedAt
			out.ObservedAt, out.ReceivedAt, out.ClockSkewMS, out.Status, out.Data = &obs, &rec, st.ClockSkewMS, st.Status, st.Data
			out.State = st.Status
			if s.Now().Sub(rec) > secproto.StaleAfter {
				out.State = "stale"
			}
		}
		if category == secproto.CatFail2ban {
			out.Manage = s.manageFor(r.Context(), a, v.ID)
		}
		if category == secproto.CatFirewall && out.Status == secproto.StatusOK {
			out.Model = fwModel(out.Data)
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) secEvents(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.visibleVPS(w, r, a)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit := 50
	if x := q.Get("limit"); x != "" {
		n, err := strconv.Atoi(x)
		if err != nil || n < 1 || n > 200 {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_limit", "limit must be 1 to 200")
			return
		}
		limit = n
	}
	cat := q.Get("category")
	if cat != "" && !secproto.ValidEventCategory(cat) {
		s.writeErr(w, r, http.StatusBadRequest, "invalid_category", "unknown category")
		return
	}
	var before *time.Time
	if x := q.Get("before_ts"); x != "" {
		t, err := time.Parse(time.RFC3339Nano, x)
		if err != nil {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_cursor", "before_ts must be RFC 3339")
			return
		}
		before = &t
	}
	evs, err := s.Store.SecEvents(r.Context(), a.Scope(), v.ID, cat, before, q.Get("before_id"), limit+1)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	more := len(evs) > limit
	if more {
		evs = evs[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": evs, "more": more})
}

var eventTypeRe = regexp.MustCompile(`^[a-z0-9_.]{1,64}$`)

// secJournal is the journal of every server the caller can see, newest first, filtered and paged with a
// (time, id) cursor.
func (s *Server) secJournal(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	q := r.URL.Query()
	bad := func(code, msg string) { s.writeErr(w, r, http.StatusBadRequest, code, msg) }
	f := store.JournalFilter{VPSID: q.Get("vps_id"), Category: q.Get("category"), Type: q.Get("type"), Severity: q.Get("severity"), Query: strings.TrimSpace(q.Get("q")), BeforeID: q.Get("before_id"), Limit: 50}
	if x := q.Get("limit"); x != "" {
		n, err := strconv.Atoi(x)
		if err != nil || n < 1 || n > 200 {
			bad("invalid_limit", "limit must be 1 to 200")
			return
		}
		f.Limit = n
	}
	if f.Category != "" && !secproto.ValidEventCategory(f.Category) {
		bad("invalid_category", "unknown category")
		return
	}
	if f.Severity != "" && f.Severity != "info" && f.Severity != "warning" && f.Severity != "critical" {
		bad("invalid_severity", "severity must be info, warning or critical")
		return
	}
	if f.Type != "" && !eventTypeRe.MatchString(f.Type) {
		bad("invalid_type", "invalid event type")
		return
	}
	if len([]rune(f.Query)) > 100 {
		bad("invalid_query", "search is at most 100 characters")
		return
	}
	for name, dst := range map[string]**time.Time{"from": &f.From, "to": &f.To, "before_ts": &f.BeforeTS} {
		if x := q.Get(name); x != "" {
			t, err := time.Parse(time.RFC3339Nano, x)
			if err != nil {
				bad("invalid_time", name+" must be RFC 3339")
				return
			}
			*dst = &t
		}
	}
	f.Limit++
	evs, err := s.Store.Journal(r.Context(), a.Scope(), f)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	more := len(evs) > f.Limit-1
	if more {
		evs = evs[:f.Limit-1]
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": evs, "more": more})
}

// secSettings reports the fixed parameters of the module, so the screen never has to guess them.
func (s *Server) secSettings(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	writeJSON(w, http.StatusOK, map[string]any{
		"agent_interval_seconds": 30, "stale_after_seconds": int(secproto.StaleAfter / time.Second),
		"port_check_minutes": int(secchecks.PortEvery / time.Minute), "tls_check_hours": int(secchecks.TLSEvery / time.Hour),
		"tls_warn_days": []int{30, 14, 7, 3}, "retention_days": int(store.SecurityRetention / (24 * time.Hour)),
		"vantage": vantageOut(), "discovery_scan": "per_server_opt_in",
	})
}
