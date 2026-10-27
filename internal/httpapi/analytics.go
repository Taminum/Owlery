package httpapi

import (
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Taminum/Owlery/internal/asn"
	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/demo"
	"github.com/Taminum/Owlery/internal/store"
)

const (
	sourceLog     = "agent_access_log"
	maxCustomSpan = 92 * 24 * time.Hour
)

// scope is what an analyzer request resolved to. Demo panels never take part: the analyzer
// reads collected events, and demo panels have none.
type aScope struct {
	panels  []store.Panel
	ids     []string
	nodeIDs []string
	from    time.Time
	to      time.Time
	gran    time.Duration
	names   map[string]string
}

type aMeta struct {
	Demo        bool      `json:"demo"`
	State       string    `json:"state"` // ok | no_data
	Reason      string    `json:"reason,omitempty"`
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	Granularity int       `json:"granularity_seconds"`
	PanelIDs    []string  `json:"panel_ids"`
	MetricKind  string    `json:"metric_kind"`
	Source      string    `json:"source"`
	Coverage    aCoverage `json:"coverage"`
}

type aCoverage struct {
	NodesTotal     int `json:"nodes_total"`
	NodesWithAgent int `json:"nodes_with_agent"`
}

// presetEnd is where a preset range ends: now, rounded down (to a minute, to five for a day and more) so that the same
// view asked again within that time is the same query and its cached answer is used instead of a recount.
func presetEnd(now time.Time, d time.Duration) time.Time {
	step := time.Minute
	if d >= 24*time.Hour {
		step = 5 * time.Minute
	}
	return now.Truncate(step)
}

// resolveScope parses range, panels and nodes and enforces the caller's access. It writes the
// error response itself and returns ok=false when the request cannot proceed.
func (s *Server) resolveScope(w http.ResponseWriter, r *http.Request, a auth.Actor) (aScope, bool) {
	var sc aScope
	qs := r.URL.Query()
	now := s.Now().UTC()
	if rng := qs.Get("range"); rng != "" {
		d, ok := presets[rng]
		if !ok {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_range", "unknown range preset")
			return sc, false
		}
		// The end of a preset range is rounded down (a minute, or five for a day and more) so that the same view asked
		// again within that time is the same query: its cached answer is used instead of a recount.
		sc.to = presetEnd(now, d)
		sc.from = sc.to.Add(-d)
	} else {
		var e1, e2 error
		sc.from, e1 = time.Parse(time.RFC3339, qs.Get("from"))
		sc.to, e2 = time.Parse(time.RFC3339, qs.Get("to"))
		if e1 != nil || e2 != nil || !sc.to.After(sc.from) || sc.to.Sub(sc.from) > maxCustomSpan {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_range", "pass range=<preset> or a valid RFC 3339 from and to (at most 92 days)")
			return sc, false
		}
	}
	sc.gran = demo.GranularityFor(sc.to.Sub(sc.from))

	scope := a.Scope()
	req := splitCSV(qs.Get("panel_ids"))
	for _, id := range req {
		if !scope.Allows(id) {
			s.writeErr(w, r, http.StatusForbidden, "panel_forbidden", "panel is not available")
			return sc, false
		}
	}
	visible, err := s.Store.ListPanels(r.Context(), scope)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return sc, false
	}
	sc.names = map[string]string{}
	for _, p := range visible {
		if len(req) > 0 && !contains(req, p.ID) {
			continue
		}
		if p.Demo {
			continue
		}
		sc.panels = append(sc.panels, p)
		sc.ids = append(sc.ids, p.ID)
		sc.names[p.ID] = p.Name
	}
	if nodes := splitCSV(qs.Get("node_ids")); len(nodes) > 0 && len(sc.ids) > 0 {
		have, err := s.Store.NodesInScope(r.Context(), sc.ids, nil)
		if err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return sc, false
		}
		ok := map[string]bool{}
		for _, n := range have {
			ok[n.NodeID] = true
		}
		for _, id := range nodes {
			if !ok[id] {
				s.writeErr(w, r, http.StatusBadRequest, "node_out_of_scope", "node does not belong to the selected panels")
				return sc, false
			}
		}
		sc.nodeIDs = nodes
	}
	return sc, true
}

func (s *Server) metaFor(r *http.Request, sc aScope, nodes []store.NodeSeen) aMeta {
	m := aMeta{State: "ok", From: sc.from, To: sc.to, Granularity: int(sc.gran.Seconds()), PanelIDs: sc.ids, MetricKind: demo.KindConnections, Source: sourceLog}
	if m.PanelIDs == nil {
		m.PanelIDs = []string{}
	}
	m.Coverage.NodesTotal = len(nodes)
	for _, n := range nodes {
		if n.HasAgent {
			m.Coverage.NodesWithAgent++
		}
	}
	switch {
	case len(sc.ids) == 0:
		m.State, m.Reason = "no_data", "no_real_panels"
	case m.Coverage.NodesWithAgent == 0:
		m.State, m.Reason = "no_data", "agents_not_connected"
	}
	return m
}

func (sc aScope) query() store.AnalyticsQuery {
	return store.AnalyticsQuery{PanelIDs: sc.ids, NodeIDs: sc.nodeIDs, From: sc.from, To: sc.to, Granularity: sc.gran}
}

func share(c, total int) float64 {
	if total == 0 {
		return 0
	}
	return math.Round(float64(c)/float64(total)*1000) / 10
}

// label names a user row without ever guessing. Account names are masked below operator.
func (s *Server) label(a auth.Actor, panelID, name, email string, internal bool) (label, note string) {
	switch {
	case internal:
		return "система", ""
	case name != "":
		if !a.Can(panelID, auth.PermOperate) {
			name = auth.MaskUsername(name)
		}
		return name, ""
	default:
		return "id " + email, "не сопоставлен"
	}
}

// --- destinations -------------------------------------------------------------

type destOut struct {
	Key         string    `json:"key"`
	Kind        string    `json:"kind"`
	Service     string    `json:"service,omitempty"`
	Confidence  string    `json:"confidence,omitempty"`
	Connections int       `json:"connections"`
	Share       float64   `json:"share"`
	Users       int       `json:"users"`
	Nodes       int       `json:"nodes"`
	LastSeen    time.Time `json:"last_seen"`
	Ports       []int32   `json:"ports"`
	Category    string    `json:"category,omitempty"`
	Origin      string    `json:"origin,omitempty"`
	Sources     []string  `json:"sources"` // where the connections came from: node | router | awg
	// Owner is the organisation that owns the address, for rows that are a bare IP.
	Owner string `json:"owner,omitempty"`
	ASN   uint32 `json:"asn,omitempty"`
	// Bytes and RouterConnections come from a router agent only; Bytes is null for rows without
	// router records, so "no data" is never shown as zero.
	Bytes             *int64 `json:"bytes"`
	RouterConnections int    `json:"router_connections"`
}

func bytesIf(d store.DestRow) *int64 {
	if d.RouterConns == 0 {
		return nil
	}
	return &d.Bytes
}

func (s *Server) analyticsDestinations(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	sc, ok := s.resolveScope(w, r, a)
	if !ok {
		return
	}
	qs := r.URL.Query()
	nodes, err := s.Store.NodesInScope(r.Context(), sc.ids, sc.nodeIDs)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	meta := s.metaFor(r, sc, nodes)
	if meta.State == "ok" || meta.Reason == "agents_not_connected" {
		if has, err := s.Store.HasRouterAgent(r.Context(), sc.ids); err == nil && has {
			meta.Source = sourceLog + "+" + sourceRouter
			if meta.State != "ok" && len(nodes) > 0 {
				meta.State, meta.Reason = "ok", ""
			}
		}
	}
	out := struct {
		Meta    aMeta     `json:"meta"`
		GroupBy string    `json:"group_by"`
		Rows    []destOut `json:"rows"`
		Groups  int       `json:"groups"`
		Total   int       `json:"total_connections"`
		Limit   int       `json:"limit"`
		Offset  int       `json:"offset"`
	}{Meta: meta, GroupBy: "host", Rows: []destOut{}}

	gb := qs.Get("group_by")
	switch gb {
	case "", "host":
	case "ip", "service", "site", "category":
		out.GroupBy = gb
	default:
		s.writeErr(w, r, http.StatusBadRequest, "invalid_group", "group_by must be host, ip, service, site or category")
		return
	}
	limit, offset := 50, 0
	if v := qs.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 100 {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_paging", "limit must be 1 to 100")
			return
		} else {
			limit = n
		}
	}
	if v := qs.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err != nil || n < 0 || n > 100000 {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_paging", "offset must be 0 or more")
			return
		} else {
			offset = n
		}
	}
	search := strings.TrimSpace(qs.Get("q"))
	if len(search) > 100 {
		s.writeErr(w, r, http.StatusBadRequest, "invalid_search", "search is too long")
		return
	}
	out.Limit, out.Offset = limit, offset
	subj, ok := s.subjectFrom(w, r, sc)
	if !ok {
		return
	}
	siteFilter := strings.ToLower(strings.TrimSpace(qs.Get("site")))
	if len(siteFilter) > 253 {
		s.writeErr(w, r, http.StatusBadRequest, "invalid_site", "site is too long")
		return
	}
	svcFilter, catFilter := strings.TrimSpace(qs.Get("service")), strings.TrimSpace(qs.Get("category"))
	if len(svcFilter) > 64 || len(catFilter) > 64 {
		s.writeErr(w, r, http.StatusBadRequest, "invalid_filter", "service or category is too long")
		return
	}
	if meta.State == "ok" {
		q := sc.query()
		q.Subject, q.Site, q.Service, q.Category = subj, siteFilter, svcFilter, catFilter
		q.GroupBy, q.Search, q.Limit, q.Offset = out.GroupBy, search, limit, offset
		rows, groups, total, err := s.Store.Destinations(r.Context(), q)
		if err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		out.Groups, out.Total = groups, total
		for _, d := range rows {
			ports := d.Ports
			if ports == nil {
				ports = []int32{}
			}
			var owner string
			var asnNum uint32
			if ip, perr := netip.ParseAddr(d.Key); perr == nil && (d.Kind == "ip" || d.Kind == "domain") {
				if o, found := asn.Default().Lookup(ip); found {
					owner, asnNum = o.Org, o.ASN
				}
			}
			out.Rows = append(out.Rows, destOut{Owner: owner, ASN: asnNum, Key: d.Key, Kind: d.Kind, Service: d.Service, Confidence: d.Confidence, Category: d.Category, Origin: d.Origin, Sources: srcList(d.Sources), Connections: d.Connections,
				Share: share(d.Connections, total), Bytes: bytesIf(d), RouterConnections: d.RouterConns, Users: d.Users, Nodes: d.Nodes, LastSeen: d.LastSeen.UTC(), Ports: ports})
		}
		if total == 0 && search == "" {
			out.Meta.State, out.Meta.Reason = "no_data", "no_events"
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// --- users ----------------------------------------------------------------------

type userOut struct {
	Key          string    `json:"key"`
	PanelID      string    `json:"panel_id"`
	PanelName    string    `json:"panel_name"`
	Label        string    `json:"label"`
	Note         string    `json:"note,omitempty"`
	Connections  int       `json:"connections"`
	Share        float64   `json:"share"`
	Destinations int       `json:"destinations"`
	Nodes        int       `json:"nodes"`
	UDPShare     float64   `json:"udp_share"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

func userKeyString(r store.UserRow) string {
	switch {
	case r.Internal:
		return r.PanelID + "|system"
	case r.UserID != "":
		return r.PanelID + "|" + r.UserID
	default:
		return r.PanelID + "|raw|" + r.Email
	}
}

func parseUserKey(k string) (store.UserKey, bool) {
	parts := strings.SplitN(k, "|", 3)
	if len(parts) < 2 {
		return store.UserKey{}, false
	}
	if _, err := uuid.Parse(parts[0]); err != nil {
		return store.UserKey{}, false
	}
	uk := store.UserKey{PanelID: parts[0]}
	switch {
	case len(parts) == 2 && parts[1] == "system":
		uk.Internal = true
	case len(parts) == 2:
		if _, err := uuid.Parse(parts[1]); err != nil {
			return store.UserKey{}, false
		}
		uk.UserID = parts[1]
	case len(parts) == 3 && parts[1] == "raw" && len(parts[2]) <= 128 && parts[2] != "":
		uk.Email = parts[2]
	default:
		return store.UserKey{}, false
	}
	return uk, true
}

func (s *Server) analyticsUsers(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	sc, ok := s.resolveScope(w, r, a)
	if !ok {
		return
	}
	nodes, err := s.Store.NodesInScope(r.Context(), sc.ids, sc.nodeIDs)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	out := struct {
		Meta  aMeta     `json:"meta"`
		Rows  []userOut `json:"rows"`
		Total int       `json:"total_connections"`
	}{Meta: s.metaFor(r, sc, nodes), Rows: []userOut{}}
	if out.Meta.State == "ok" {
		rows, total, err := s.Store.UsersAnalytics(r.Context(), sc.query())
		if err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		out.Total = total
		for _, u := range rows {
			l, note := s.label(a, u.PanelID, u.Name, u.Email, u.Internal)
			out.Rows = append(out.Rows, userOut{Key: userKeyString(u), PanelID: u.PanelID, PanelName: sc.names[u.PanelID], Label: l, Note: note,
				Connections: u.Connections, Share: share(u.Connections, total), Destinations: u.Destinations, Nodes: u.Nodes,
				UDPShare: share(u.UDP, u.Connections), FirstSeen: u.First.UTC(), LastSeen: u.Last.UTC()})
		}
		if total == 0 {
			out.Meta.State, out.Meta.Reason = "no_data", "no_events"
		}
	}
	writeJSON(w, http.StatusOK, out)
}

type namedOut struct {
	Key     string  `json:"key"`
	Service string  `json:"service,omitempty"`
	Count   int     `json:"count"`
	Share   float64 `json:"share"`
}

func named(in []store.NamedCount, total int) []namedOut {
	out := make([]namedOut, 0, len(in))
	for _, n := range in {
		out = append(out, namedOut{Key: n.Key, Service: n.Service, Count: n.Count, Share: share(n.Count, total)})
	}
	return out
}

func (s *Server) analyticsUserDetail(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	uk, ok := parseUserKey(r.URL.Query().Get("key"))
	if !ok {
		s.writeErr(w, r, http.StatusBadRequest, "invalid_key", "invalid user key")
		return
	}
	// The panel in the key must be one the caller can see, and it narrows the scope to that panel.
	q := r.URL.Query()
	q.Set("panel_ids", uk.PanelID)
	r.URL.RawQuery = q.Encode()
	sc, ok := s.resolveScope(w, r, a)
	if !ok {
		return
	}
	if len(sc.ids) == 0 {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "user not found")
		return
	}
	d, err := s.Store.UserDetail(r.Context(), sc.query(), uk)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	// Name the subject the same way the list does.
	name, email := "", uk.Email
	if uk.UserID != "" {
		if rows, _, err := s.Store.UsersAnalytics(r.Context(), sc.query()); err == nil {
			for _, u := range rows {
				if u.UserID == uk.UserID {
					name = u.Name
				}
			}
		}
	}
	l, note := s.label(a, uk.PanelID, name, email, uk.Internal)
	byTS := map[int64]store.Bucket{}
	for _, b := range d.Buckets {
		byTS[b.TS.Unix()] = b
	}
	timeline := []demo.TimelinePoint{}
	for ts := sc.from.Truncate(sc.gran); ts.Before(sc.to); ts = ts.Add(sc.gran) {
		b := byTS[ts.Unix()]
		timeline = append(timeline, demo.TimelinePoint{TS: ts.Unix(), TCP: b.TCP, UDP: b.UDP})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"meta": s.metaFor(r, sc, nil),
		"key":  r.URL.Query().Get("key"), "panel_id": uk.PanelID, "panel_name": sc.names[uk.PanelID],
		"label": l, "note": note, "total": d.Total, "tcp": d.TCP, "udp": d.UDP,
		"timeline": timeline, "hosts": named(d.Hosts, d.Total), "ports": named(d.Ports, d.Total), "nodes": named(d.Nodes, d.Total),
	})
}

// --- nodes ----------------------------------------------------------------------

type nodeOut struct {
	NodeID       string     `json:"node_id"`
	Name         string     `json:"name"`
	PanelID      string     `json:"panel_id"`
	PanelName    string     `json:"panel_name"`
	Agent        string     `json:"agent"` // none | live | stale
	LastSeen     *time.Time `json:"last_seen"`
	LastEventAt  *time.Time `json:"last_event_at"`
	Connections  int        `json:"connections"`
	Share        float64    `json:"share"`
	Users        int        `json:"users"`
	Destinations int        `json:"destinations"`
	UDPShare     float64    `json:"udp_share"`
}

func (s *Server) analyticsNodes(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	sc, ok := s.resolveScope(w, r, a)
	if !ok {
		return
	}
	rows, err := s.Store.NodesAnalytics(r.Context(), sc.query())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	seen := make([]store.NodeSeen, 0, len(rows))
	total := 0
	for _, n := range rows {
		seen = append(seen, n.NodeSeen)
		total += n.Connections
	}
	out := struct {
		Meta  aMeta     `json:"meta"`
		Rows  []nodeOut `json:"rows"`
		Total int       `json:"total_connections"`
	}{Meta: s.metaFor(r, sc, seen), Rows: []nodeOut{}, Total: total}
	now := s.Now()
	for _, n := range rows {
		agent := "none"
		if n.HasAgent {
			agent = "live"
			if n.LastSeen == nil || now.Sub(*n.LastSeen) > agentStaleAfter {
				agent = "stale"
			}
		}
		out.Rows = append(out.Rows, nodeOut{NodeID: n.NodeID, Name: n.NodeName, PanelID: n.PanelID, PanelName: sc.names[n.PanelID], Agent: agent,
			LastSeen: n.LastSeen, LastEventAt: n.LastEvent, Connections: n.Connections, Share: share(n.Connections, total), Users: n.Users,
			Destinations: n.Destinations, UDPShare: share(n.UDP, n.Connections)})
	}
	writeJSON(w, http.StatusOK, out)
}
