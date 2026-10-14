package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/demo"
	"github.com/Taminum/RemnaScope/internal/store"
)

type scopePanel struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Demo  bool            `json:"demo"`
	Role  string          `json:"role"`
	Nodes []demo.NodeInfo `json:"nodes"`
}

// scope lists exactly the panels and nodes the caller may filter by.
func (s *Server) scope(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	ps, err := s.Store.ListPanels(r.Context(), a.Scope())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	fixtures := map[string]demo.PanelInfo{}
	for _, f := range demo.ListPanels() {
		fixtures[f.ID] = f
	}
	out := make([]scopePanel, 0, len(ps))
	for _, p := range ps {
		sp := scopePanel{ID: p.ID, Name: p.Name, Demo: p.Demo, Role: a.RoleOn(p.ID), Nodes: []demo.NodeInfo{}}
		if p.Demo {
			sp.Nodes = fixtures[p.ID].Nodes
		} else {
			ns, err := s.Store.ListNodes(r.Context(), a.Scope(), p.ID, false)
			if err != nil {
				s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
				return
			}
			for _, n := range ns {
				sp.Nodes = append(sp.Nodes, demo.NodeInfo{ID: n.ID, PanelID: p.ID, Name: n.Name, AgentStatus: "none"})
			}
		}
		out = append(out, sp)
	}
	writeJSON(w, http.StatusOK, map[string]any{"panels": out})
}

var presets = map[string]time.Duration{
	"15m": 15 * time.Minute, "1h": time.Hour, "24h": 24 * time.Hour,
	"7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour,
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// overview answers for the panels the caller may see. Synthetic data is returned only
// when every selected panel is a demo panel; real panels have no event collection until
// M2, and say so instead of showing invented numbers.
func (s *Server) overview(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	qs := r.URL.Query()
	now := s.Now().UTC()

	var from, to time.Time
	if rng := qs.Get("range"); rng != "" {
		d, ok := presets[rng]
		if !ok {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_range", "unknown range preset")
			return
		}
		to, from = now, now.Add(-d)
	} else {
		var err1, err2 error
		from, err1 = time.Parse(time.RFC3339, qs.Get("from"))
		to, err2 = time.Parse(time.RFC3339, qs.Get("to"))
		if err1 != nil || err2 != nil {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_range", "pass range=<preset> or RFC3339 from and to")
			return
		}
	}

	scope := a.Scope()
	req := splitCSV(qs.Get("panel_ids"))
	for _, id := range req {
		if !scope.Allows(id) {
			// Same answer for "does not exist" and "not yours": no UUID probing.
			s.writeErr(w, r, http.StatusForbidden, "panel_forbidden", "panel is not available")
			return
		}
	}
	visible, err := s.Store.ListPanels(r.Context(), scope)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	var ids, realIDs []string
	var realPanels []store.Panel
	allDemo := true
	for _, p := range visible {
		if len(req) > 0 && !contains(req, p.ID) {
			continue
		}
		ids = append(ids, p.ID)
		allDemo = allDemo && p.Demo
		if !p.Demo {
			realIDs = append(realIDs, p.ID)
			realPanels = append(realPanels, p)
		}
	}

	nodeIDs := splitCSV(qs.Get("node_ids"))
	if len(nodeIDs) > 0 {
		// Every requested node must belong to one of the selected panels, real or demo.
		allowed := map[string]bool{}
		fix := map[string]demo.PanelInfo{}
		for _, f := range demo.ListPanels() {
			fix[f.ID] = f
		}
		for _, p := range visible {
			if !contains(ids, p.ID) {
				continue
			}
			if p.Demo {
				for _, n := range fix[p.ID].Nodes {
					allowed[n.ID] = true
				}
				continue
			}
			ns, err := s.Store.ListNodes(r.Context(), scope, p.ID, false)
			if err != nil {
				s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
				return
			}
			for _, n := range ns {
				allowed[n.ID] = true
			}
		}
		for _, n := range nodeIDs {
			if !allowed[n] {
				s.writeErr(w, r, http.StatusBadRequest, "node_out_of_scope", "node does not belong to the selected panels")
				return
			}
		}
	}
	q := demo.Query{PanelIDs: ids, NodeIDs: nodeIDs, From: from, To: to, Now: now}
	var ov demo.Overview
	if len(ids) > 0 && allDemo {
		switch qs.Get("demo_state") {
		case "error":
			s.writeErr(w, r, http.StatusServiceUnavailable, "api_unavailable", "demo: upstream API unavailable")
			return
		case "empty", "pending":
			q.State = qs.Get("demo_state")
		}
		ov, err = demo.BuildOverview(q)
	} else if len(realIDs) > 0 {
		// Real panels: the numbers come from collected events. Demo panels in a mixed scope are
		// left out, so synthetic data never blends into real data.
		q.PanelIDs = realIDs
		ov, err = s.realOverview(r.Context(), a, realPanels, realIDs, nodeIDs, q)
	} else {
		ov, err = demo.Empty(q, ids, "agents_not_connected")
	}
	switch {
	case errors.Is(err, demo.ErrUnknownPanel):
		s.writeErr(w, r, http.StatusForbidden, "panel_forbidden", "panel is not available")
	case errors.Is(err, demo.ErrNodeOutOfScope):
		s.writeErr(w, r, http.StatusBadRequest, "node_out_of_scope", "node does not belong to the selected panels")
	case errors.Is(err, demo.ErrBadRange):
		s.writeErr(w, r, http.StatusBadRequest, "invalid_range", "time range is empty or too long for its granularity")
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
	default:
		writeJSON(w, http.StatusOK, ov)
	}
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
