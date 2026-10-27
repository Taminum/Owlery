package httpapi

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/dnsmap"
	"github.com/Taminum/Owlery/internal/netintel"
	"github.com/Taminum/Owlery/internal/store"
)

// DNS Map belongs to Network Intel, which is the owner's: it makes the server send DNS queries into the
// world, and what it holds is a picture of a domain that only its owner should be able to ask for.
func (s *Server) dnsGate(w http.ResponseWriter, r *http.Request, a auth.Actor) bool {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can use DNS Map")
		return false
	}
	return true
}

type dnsMapOut struct {
	store.DNSMap
	LastRun *store.DNSRunRow `json:"last_run"`
}

func (s *Server) dnsMapOut(r *http.Request, m store.DNSMap) dnsMapOut {
	out := dnsMapOut{DNSMap: m}
	if runs, err := s.Store.DNSRuns(r.Context(), m.ID, 1); err == nil && len(runs) > 0 {
		out.LastRun = &runs[0]
	}
	return out
}

func (s *Server) loadDNSMap(w http.ResponseWriter, r *http.Request, a auth.Actor) (store.DNSMap, bool) {
	if !s.dnsGate(w, r, a) {
		return store.DNSMap{}, false
	}
	m, err := s.Store.GetDNSMap(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "map not found")
		return m, false
	}
	return m, true
}

// dnsName normalises one name that belongs inside the domain: a domain, nothing else (no URL, address,
// CIDR or ASN), in ASCII, lower case.
func dnsName(raw, domain string) (string, bool) {
	tg, err := netintel.Parse(raw)
	if err != nil || tg.Kind != netintel.KindDomain {
		return "", false
	}
	n := tg.Value
	if n != domain && !strings.HasSuffix(n, "."+domain) {
		return "", false
	}
	return n, true
}

func (s *Server) listDNSMaps(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.dnsGate(w, r, a) {
		return
	}
	maps, err := s.Store.ListDNSMaps(r.Context())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	out := make([]dnsMapOut, 0, len(maps))
	for _, m := range maps {
		out = append(out, s.dnsMapOut(r, m))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "max_maps": store.MaxDNSMaps, "resolvers": []string{"1.1.1.1", "8.8.8.8"}, "retention_days": int(store.DNSRetention / (24 * time.Hour))})
}

func (s *Server) createDNSMap(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.dnsGate(w, r, a) {
		return
	}
	var in struct {
		Domain       string   `json:"domain"`
		ConfirmScope bool     `json:"confirm_scope"`
		ExtraNames   []string `json:"extra_names"`
		UseCT        bool     `json:"use_ct"`
		IntervalH    int      `json:"interval_hours"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	bad := func(code, msg string) { s.writeErr(w, r, http.StatusUnprocessableEntity, code, msg) }
	if !in.ConfirmScope {
		bad("scope_not_confirmed", "confirm the scope: this domain, public resolvers, the names you give or that are found")
		return
	}
	tg, err := netintel.Parse(in.Domain)
	if err != nil || tg.Kind != netintel.KindDomain {
		bad("invalid_domain", "a domain is needed")
		return
	}
	if strings.Count(tg.Value, ".") < 1 {
		bad("invalid_domain", "a domain with a zone is needed")
		return
	}
	if in.IntervalH == 0 {
		in.IntervalH = 24
	}
	if in.IntervalH < 1 || in.IntervalH > 168 {
		bad("invalid_interval", "interval_hours must be 1 to 168")
		return
	}
	var extra []string
	seen := map[string]bool{tg.Value: true}
	for _, raw := range in.ExtraNames {
		n, ok := dnsName(raw, tg.Value)
		if !ok {
			bad("invalid_name", "an extra name must be a domain inside "+tg.Value+": "+strings.TrimSpace(raw))
			return
		}
		if !seen[n] {
			seen[n] = true
			extra = append(extra, n)
		}
	}
	m, err := s.Store.CreateDNSMap(r.Context(), a.AccountID, tg.Value, tg.Display, extra, in.UseCT, in.IntervalH, s.Now().UTC())
	switch {
	case errors.Is(err, store.ErrConflict):
		s.writeErr(w, r, http.StatusConflict, "exists", "a map of this domain already exists")
		return
	case errors.Is(err, store.ErrLimit):
		s.writeErr(w, r, http.StatusConflict, "limit", "too many maps or extra names")
		return
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "intel.dns_map.create", "dns_map", m.ID, map[string]any{"domain": m.Domain, "use_ct": m.UseCT, "interval_hours": m.IntervalH})
	s.nudgeDNS()
	writeJSON(w, http.StatusCreated, s.dnsMapOut(r, m))
}

func (s *Server) getDNSMap(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	m, ok := s.loadDNSMap(w, r, a)
	if !ok {
		return
	}
	names, err := s.Store.DNSNames(r.Context(), m.ID)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"map": s.dnsMapOut(r, m), "names": names})
}

func (s *Server) patchDNSMap(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	m, ok := s.loadDNSMap(w, r, a)
	if !ok {
		return
	}
	var in struct {
		Enabled    *bool     `json:"enabled"`
		IntervalH  *int      `json:"interval_hours"`
		ExtraNames *[]string `json:"extra_names"`
		UseCT      *bool     `json:"use_ct"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	p := store.DNSMapPatch{Enabled: in.Enabled, IntervalH: in.IntervalH, UseCT: in.UseCT}
	if in.IntervalH != nil && (*in.IntervalH < 1 || *in.IntervalH > 168) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_interval", "interval_hours must be 1 to 168")
		return
	}
	if in.ExtraNames != nil {
		var names []string
		seen := map[string]bool{m.Domain: true}
		for _, raw := range *in.ExtraNames {
			n, ok := dnsName(raw, m.Domain)
			if !ok {
				s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_name", "an extra name must be a domain inside "+m.Domain+": "+strings.TrimSpace(raw))
				return
			}
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
		if names == nil {
			names = []string{}
		}
		p.ExtraNames = &names
	}
	upd, err := s.Store.PatchDNSMap(r.Context(), m.ID, p)
	switch {
	case errors.Is(err, store.ErrLimit):
		s.writeErr(w, r, http.StatusConflict, "limit", "too many extra names")
		return
	case err != nil:
		s.writeErr(w, r, http.StatusNotFound, "not_found", "map not found")
		return
	}
	s.audit(r, a, "", "intel.dns_map.update", "dns_map", m.ID, nil)
	writeJSON(w, http.StatusOK, s.dnsMapOut(r, upd))
}

func (s *Server) archiveDNSMap(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	m, ok := s.loadDNSMap(w, r, a)
	if !ok {
		return
	}
	if err := s.Store.ArchiveDNSMap(r.Context(), m.ID); err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "map not found")
		return
	}
	s.audit(r, a, "", "intel.dns_map.archive", "dns_map", m.ID, map[string]any{"domain": m.Domain})
	w.WriteHeader(http.StatusNoContent)
}

// refreshDNSMap asks for a run now. The run itself is the worker's: this answers 202 and the result
// appears in the map when it is done.
func (s *Server) refreshDNSMap(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	m, ok := s.loadDNSMap(w, r, a)
	if !ok {
		return
	}
	if !s.dnsLimit.Allow(m.ID) {
		w.Header().Set("Retry-After", "60")
		s.writeErr(w, r, http.StatusTooManyRequests, "rate_limited", "a refresh was requested a moment ago")
		return
	}
	switch err := s.Store.RequestDNSRun(r.Context(), m.ID, s.Now().UTC()); {
	case errors.Is(err, store.ErrRunning):
		s.writeErr(w, r, http.StatusConflict, "running", "a run of this map is already in progress")
		return
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "intel.dns_map.refresh", "dns_map", m.ID, nil)
	s.nudgeDNS()
	writeJSON(w, http.StatusAccepted, map[string]any{"requested": true})
}

func (s *Server) nudgeDNS() {
	if s.DNSWorker != nil {
		s.DNSWorker.Nudge()
	}
}

func queryLimit(w http.ResponseWriter, r *http.Request, s *Server, def, max int) (int, bool) {
	x := r.URL.Query().Get("limit")
	if x == "" {
		return def, true
	}
	n, err := strconv.Atoi(x)
	if err != nil || n < 1 || n > max {
		s.writeErr(w, r, http.StatusBadRequest, "invalid_limit", "limit must be 1 to "+strconv.Itoa(max))
		return 0, false
	}
	return n, true
}

var dnsTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true, "SOA": true, "TXT": true, "CAA": true, "DS": true, "DNSKEY": true}

func (s *Server) dnsRecords(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	m, ok := s.loadDNSMap(w, r, a)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit, ok := queryLimit(w, r, s, 100, 500)
	if !ok {
		return
	}
	f := store.DNSRecordFilter{Type: strings.ToUpper(q.Get("type")), Name: strings.ToLower(q.Get("name")), Q: strings.TrimSpace(q.Get("q")),
		AfterName: q.Get("after_name"), AfterType: strings.ToUpper(q.Get("after_type")), Limit: limit + 1}
	if (f.Type != "" && !dnsTypes[f.Type]) || len([]rune(f.Q)) > 100 || len(f.Name) > 253 || (f.AfterName != "" && !dnsmap.ValidName(f.AfterName)) {
		s.writeErr(w, r, http.StatusBadRequest, "invalid_filter", "invalid filter")
		return
	}
	rows, err := s.Store.DNSRecords(r.Context(), m.ID, f)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rows, "more": more})
}

func (s *Server) dnsChanges(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	m, ok := s.loadDNSMap(w, r, a)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit, ok := queryLimit(w, r, s, 50, 200)
	if !ok {
		return
	}
	f := store.DNSChangeFilter{Name: strings.ToLower(q.Get("name")), Type: strings.ToUpper(q.Get("type")), Kind: q.Get("kind"), BeforeID: q.Get("before_id"), Limit: limit + 1}
	if (f.Type != "" && f.Type != "*" && !dnsTypes[f.Type]) || (f.Kind != "" && !strings.HasPrefix(f.Kind, "dns.")) || len(f.Kind) > 40 || len(f.Name) > 253 {
		s.writeErr(w, r, http.StatusBadRequest, "invalid_filter", "invalid filter")
		return
	}
	for name, dst := range map[string]**time.Time{"from": &f.From, "to": &f.To, "before_ts": &f.BeforeTS} {
		if x := q.Get(name); x != "" {
			t, err := time.Parse(time.RFC3339Nano, x)
			if err != nil {
				s.writeErr(w, r, http.StatusBadRequest, "invalid_time", name+" must be RFC 3339")
				return
			}
			*dst = &t
		}
	}
	rows, err := s.Store.DNSChanges(r.Context(), m.ID, f)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rows, "more": more})
}

func (s *Server) dnsChecks(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	m, ok := s.loadDNSMap(w, r, a)
	if !ok {
		return
	}
	limit, ok := queryLimit(w, r, s, 20, 100)
	if !ok {
		return
	}
	runs, err := s.Store.DNSRuns(r.Context(), m.ID, limit)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": runs})
}

// --- graph ---------------------------------------------------------------------------------------

type graphNode struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"` // name | ip | mail | ns
	Label string `json:"label"`
	Group string `json:"group,omitempty"` // for a name: its first label under the apex, to cluster subdomains
	Prov  string `json:"provenance,omitempty"`
}

type graphEdge struct {
	From             string `json:"from"`
	To               string `json:"to"`
	Type             string `json:"type"` // A | AAAA | CNAME | MX | NS
	Label            string `json:"label,omitempty"`
	Unverified       bool   `json:"unverified,omitempty"`         // seen, but not confirmed by two resolvers
	NoLongerObserved bool   `json:"no_longer_observed,omitempty"` // was seen, and a complete confirmed answer later found it gone
}

// dnsGraph is the map's records drawn as nodes and typed edges. Every edge is a record that was observed:
// nothing is inferred about connections, hosting or ownership from a DNS link. TXT, SOA, CAA and DNSSEC
// records are in the table and the details, not the graph.
func (s *Server) dnsGraph(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	m, ok := s.loadDNSMap(w, r, a)
	if !ok {
		return
	}
	max := 150
	if x := r.URL.Query().Get("max_nodes"); x != "" {
		n, err := strconv.Atoi(x)
		if err != nil || n < 5 || n > 400 {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_limit", "max_nodes must be 5 to 400")
			return
		}
		max = n
	}
	names, err := s.Store.DNSNames(r.Context(), m.ID)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	recs, err := s.Store.DNSRecords(r.Context(), m.ID, store.DNSRecordFilter{Limit: 5000})
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	nodes, edges, total, truncated := buildGraph(m.Domain, names, recs, max)
	writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes, "edges": edges, "total_nodes": total, "truncated": truncated,
		"note": "records that were observed; a DNS link says nothing about hosting, ownership or live connections"})
}

func groupOf(domain, name string) string {
	if name == domain {
		return ""
	}
	rest := strings.TrimSuffix(name, "."+domain)
	if i := strings.LastIndex(rest, "."); i >= 0 {
		return rest[i+1:]
	}
	return rest
}

func buildGraph(domain string, names []store.DNSNameRow, recs []store.DNSRecordRow, max int) ([]graphNode, []graphEdge, int, bool) {
	prov := map[string]string{}
	order := map[string]int{}
	for i, n := range names {
		prov[n.Name] = n.Provenance
		order[n.Name] = i
	}
	// Names first, the apex at the head, then by how they were found and by name.
	sort.SliceStable(recs, func(i, j int) bool {
		a, b := recs[i], recs[j]
		if (a.Name == domain) != (b.Name == domain) {
			return a.Name == domain
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Type < b.Type
	})
	nodes := map[string]graphNode{}
	var keep []string
	addNode := func(n graphNode) bool {
		if _, ok := nodes[n.ID]; ok {
			return true
		}
		if len(nodes) >= max {
			return false
		}
		nodes[n.ID] = n
		keep = append(keep, n.ID)
		return true
	}
	nameNode := func(n string) graphNode {
		return graphNode{ID: "name:" + n, Kind: "name", Label: n, Group: groupOf(domain, n), Prov: prov[n]}
	}
	var edges []graphEdge
	totalIDs := map[string]bool{}
	for _, rec := range recs {
		if rec.Result == nil || *rec.Result != "answer" && !rec.NoLongerObserved {
			continue
		}
		var kind, prefix string
		switch rec.Type {
		case "A", "AAAA":
			kind, prefix = "ip", "ip:"
		case "CNAME":
			kind, prefix = "name", "name:"
		case "MX":
			kind, prefix = "mail", "mx:"
		case "NS":
			kind, prefix = "ns", "ns:"
		default:
			continue
		}
		from := "name:" + rec.Name
		totalIDs[from] = true
		for _, v := range rec.Values {
			target, label := v, ""
			if rec.Type == "MX" {
				if i := strings.IndexByte(v, ' '); i > 0 {
					label, target = "prio "+v[:i], v[i+1:]
				}
			}
			to := prefix + target
			totalIDs[to] = true
			if len(nodes) >= max && nodes[from].ID == "" {
				continue
			}
			if !addNode(nameNode(rec.Name)) {
				continue
			}
			tn := graphNode{ID: to, Kind: kind, Label: target}
			if kind == "name" {
				tn = nameNode(target)
			}
			if !addNode(tn) {
				continue
			}
			edges = append(edges, graphEdge{From: from, To: to, Type: rec.Type, Label: label, Unverified: !rec.Confirmed, NoLongerObserved: rec.NoLongerObserved})
		}
	}
	out := make([]graphNode, 0, len(keep))
	for _, id := range keep {
		out = append(out, nodes[id])
	}
	if edges == nil {
		edges = []graphEdge{}
	}
	return out, edges, len(totalIDs), len(totalIDs) > len(out)
}
