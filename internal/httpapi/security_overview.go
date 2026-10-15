package httpapi

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/secevents"
	"github.com/Taminum/RemnaScope/internal/secproto"
	"github.com/Taminum/RemnaScope/internal/store"
)

// tlsWarnDays matches the alert threshold: a certificate this close to its end needs attention.
const tlsWarnDays = 30

// tlsBroken are the verdicts that are a fault of the certificate itself; "could not check" is not one.
var tlsBroken = map[string]bool{secevents.TLSExpired: true, secevents.TLSUntrusted: true, secevents.TLSHostname: true, secevents.TLSInvalid: true, secevents.TLSHandshake: true}

type ovReason struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

type ovCategory struct {
	State      string     `json:"state"`
	ObservedAt *time.Time `json:"observed_at"`
}

type ovChecks struct {
	PortsTotal      int        `json:"ports_total"`
	PortsUnexpected int        `json:"ports_unexpected"` // answers from outside and is not marked expected
	PortsDown       int        `json:"ports_down"`       // expected, but does not answer
	TLSTotal        int        `json:"tls_total"`
	TLSProblems     int        `json:"tls_problems"`
	TLSNearestEnd   *time.Time `json:"tls_nearest_end"`
	LastCheckedAt   *time.Time `json:"last_checked_at"`
}

// secOverview is a server's one-page picture. "unknown" is a real answer: it means nothing has been read
// or checked yet, which is not the same as healthy.
type secOverview struct {
	Health     string                `json:"health"` // healthy | attention | unknown | disabled
	Reasons    []ovReason            `json:"reasons"`
	Agent      string                `json:"agent"` // none | waiting | online | offline
	Categories map[string]ovCategory `json:"categories"`
	Checks     ovChecks              `json:"checks"`
	LastEvent  *store.SecEvent       `json:"last_event"`
	Events24h  int                   `json:"events_24h"`
}

func (s *Server) secOverview(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.visibleVPS(w, r, a)
	if !ok {
		return
	}
	ctx, sc, now := r.Context(), a.Scope(), s.Now()
	fail := func() { s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error") }
	o := secOverview{Reasons: []ovReason{}, Agent: "none", Categories: map[string]ovCategory{}}
	add := func(code, detail string) { o.Reasons = append(o.Reasons, ovReason{code, detail}) }

	if ag, err := s.Store.SecAgentOf(ctx, v.ID); err == nil {
		switch {
		case ag.LastSeen == nil:
			o.Agent = "waiting"
		case now.Sub(*ag.LastSeen) < secproto.StaleAfter:
			o.Agent = "online"
		default:
			o.Agent = "offline"
		}
	}
	states, err := s.Store.SnapshotStates(ctx, sc, v.ID)
	if err != nil {
		fail()
		return
	}
	for _, st := range states {
		state := st.Status
		if now.Sub(st.ReceivedAt) > secproto.StaleAfter {
			state = "stale"
		}
		obs := st.ObservedAt
		o.Categories[st.Category] = ovCategory{State: state, ObservedAt: &obs}
	}
	for _, c := range []string{secproto.CatFail2ban, secproto.CatSockets, secproto.CatFirewall} {
		if _, ok := o.Categories[c]; !ok {
			state := "agent_required"
			if o.Agent != "none" {
				state = "waiting"
			}
			o.Categories[c] = ovCategory{State: state}
		}
	}

	ports, err := s.Store.ListPortEndpoints(ctx, sc, v.ID)
	if err != nil {
		fail()
		return
	}
	tls, err := s.Store.ListTLSEndpoints(ctx, sc, v.ID)
	if err != nil {
		fail()
		return
	}
	ck := &o.Checks
	seen := func(t *time.Time) {
		if t != nil && (ck.LastCheckedAt == nil || t.After(*ck.LastCheckedAt)) {
			ck.LastCheckedAt = t
		}
	}
	for _, p := range ports {
		if !p.Enabled {
			continue
		}
		ck.PortsTotal++
		seen(p.LastCheckedAt)
		res := ""
		if p.LastResult != nil {
			res = *p.LastResult
		}
		switch {
		// The same rule as the alert: a port that was already open at the first check is the baseline, not news.
		case !p.Expected && res == secevents.PortReachable && (p.UnexpectedSince != nil || p.Source == "discovered"):
			ck.PortsUnexpected++
		case p.Expected && res != "" && res != secevents.PortReachable && res != secevents.PortError:
			ck.PortsDown++
		}
	}
	for _, e := range tls {
		if !e.Enabled {
			continue
		}
		ck.TLSTotal++
		seen(e.LastCheckedAt)
		if e.LastNotAfter != nil && (ck.TLSNearestEnd == nil || e.LastNotAfter.Before(*ck.TLSNearestEnd)) {
			t := *e.LastNotAfter
			ck.TLSNearestEnd = &t
		}
		st := ""
		if e.LastState != nil {
			st = *e.LastState
		}
		expiring := e.LastNotAfter != nil && e.LastNotAfter.Sub(now) <= tlsWarnDays*24*time.Hour
		if expiring || tlsBroken[st] {
			ck.TLSProblems++
		}
	}

	// Last event and the count of the last day.
	if u, err := uuid.Parse(v.ID); err == nil {
		evs, err := s.Store.Journal(ctx, sc, store.JournalFilter{VPSID: u.String(), Limit: 1})
		if err != nil {
			fail()
			return
		}
		if len(evs) > 0 {
			e := evs[0].SecEvent
			o.LastEvent = &e
		}
		from := now.Add(-24 * time.Hour)
		day, err := s.Store.Journal(ctx, sc, store.JournalFilter{VPSID: u.String(), From: &from, Limit: 200})
		if err != nil {
			fail()
			return
		}
		o.Events24h = len(day)
	}

	// Verdict. Order matters: a disabled server is not judged at all.
	switch {
	case !v.Enabled:
		o.Health = "disabled"
	default:
		if o.Agent == "offline" {
			add("agent_offline", "")
		}
		for name, c := range o.Categories {
			switch c.State {
			case "error", "permission_denied", "stopped", "stale":
				add("category_"+c.State, name)
			}
		}
		if ck.TLSProblems > 0 {
			add("tls_problem", "")
		}
		if ck.PortsUnexpected > 0 {
			add("port_unexpected", "")
		}
		if ck.PortsDown > 0 {
			add("port_down", "")
		}
		switch {
		case len(o.Reasons) > 0:
			o.Health = "attention"
		case o.Agent != "online" && ck.LastCheckedAt == nil:
			o.Health = "unknown"
		default:
			o.Health = "healthy"
		}
	}
	writeJSON(w, http.StatusOK, o)
}

// secEventDetail returns one journal event, the server it belongs to and what else was recorded on that
// server in the minutes around it (the same category first), so a single line can be read in context.
func (s *Server) secEventDetail(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "event not found")
		return
	}
	got, err := s.Store.Journal(r.Context(), a.Scope(), store.JournalFilter{ID: id, Limit: 1})
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if len(got) == 0 {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "event not found")
		return
	}
	e := got[0]
	from, to := e.ObservedAt.Add(-10*time.Minute), e.ObservedAt.Add(10*time.Minute)
	near, err := s.Store.Journal(r.Context(), a.Scope(), store.JournalFilter{VPSID: e.VPSID, From: &from, To: &to, Limit: 31})
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	related := []store.JournalEvent{}
	for _, x := range near {
		if x.ID != e.ID {
			related = append(related, x)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"event": e, "related": related})
}
