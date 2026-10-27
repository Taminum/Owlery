package httpapi

import (
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Taminum/RemnaScope/internal/asn"
	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/geoip"
	"github.com/Taminum/RemnaScope/internal/store"
)

// subjectFrom reads ?subject=user:<panel>|<id> | raw:<panel>|<email> | device:<panel>|<ip>.
// A subject of a panel outside the caller's scope is refused exactly like any other panel.
func (s *Server) subjectFrom(w http.ResponseWriter, r *http.Request, sc aScope) (store.Subject, bool) {
	raw := r.URL.Query().Get("subject")
	if raw == "" {
		return store.Subject{}, true
	}
	bad := func() (store.Subject, bool) {
		s.writeErr(w, r, http.StatusBadRequest, "invalid_subject", "subject must be user:<panel>|<id>, raw:<panel>|<id>, device:<panel>|<ip> or path:<panel>|<inbound>")
		return store.Subject{}, false
	}
	kind, rest, ok := strings.Cut(raw, ":")
	panel, id, ok2 := strings.Cut(rest, "|")
	if !ok || !ok2 || len(id) == 0 || len(id) > 64 {
		return bad()
	}
	if _, err := uuid.Parse(panel); err != nil {
		return bad()
	}
	switch kind {
	case "user":
		if _, err := uuid.Parse(id); err != nil {
			return bad()
		}
	case "device":
		if _, err := netip.ParseAddr(id); err != nil {
			return bad()
		}
	case "awg":
		if _, err := netip.ParseAddr(id); err != nil && id != "*" {
			return bad()
		}
	case "raw", "path":
		for _, c := range id {
			if c < 0x20 || c == 0x7f {
				return bad()
			}
		}
	default:
		return bad()
	}
	if !contains(sc.ids, panel) {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "subject not found")
		return store.Subject{}, false
	}
	return store.Subject{Kind: kind, PanelID: panel, ID: id}, true
}

// mixedMeta is the meta of views that combine node logs and router records.
func (s *Server) mixedMeta(r *http.Request, sc aScope) (aMeta, bool) {
	nodes, err := s.Store.NodesInScope(r.Context(), sc.ids, sc.nodeIDs)
	if err != nil {
		return aMeta{}, false
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
	return meta, true
}

func paging(w http.ResponseWriter, r *http.Request, s *Server, max int) (limit, offset int, ok bool) {
	limit = 50
	qs := r.URL.Query()
	if v := qs.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > max {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_paging", "limit must be 1 to "+strconv.Itoa(max))
			return 0, 0, false
		}
		limit = n
	}
	if v := qs.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 100000 {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_paging", "offset must be 0 or more")
			return 0, 0, false
		}
		offset = n
	}
	return limit, offset, true
}

type siteOut struct {
	Site              string    `json:"site"`
	Service           string    `json:"service,omitempty"`
	Confidence        string    `json:"confidence,omitempty"`
	Category          string    `json:"category"`
	Classified        bool      `json:"classified"`
	Origin            string    `json:"origin,omitempty"`
	Sources           []string  `json:"sources"` // where its connections came from: node | router | awg
	Connections       int       `json:"connections"`
	Visits            int       `json:"visits"`
	Share             float64   `json:"share"`
	Users             int       `json:"users"`
	Devices           int       `json:"devices"`
	Hosts             int       `json:"hosts"`
	Bytes             *int64    `json:"bytes"`
	RouterConnections int       `json:"router_connections"`
	RU                bool      `json:"ru_zone"`
	Blocked           int       `json:"blocked"`
	Warp              int       `json:"warp"`
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
}

type categoryOut struct {
	Category          string  `json:"category"`
	Classified        bool    `json:"classified"`
	Sites             int     `json:"sites"`
	Connections       int     `json:"connections"`
	Visits            int     `json:"visits"`
	Share             float64 `json:"share"`
	Users             int     `json:"users"`
	Bytes             *int64  `json:"bytes"`
	RouterConnections int     `json:"router_connections"`
}

func bytesPtr(n int64, routerConns int) *int64 {
	if routerConns == 0 {
		return nil
	}
	return &n
}

func (s *Server) analyticsSites(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	sc, ok := s.resolveScope(w, r, a)
	if !ok {
		return
	}
	qs := r.URL.Query()
	meta, ok := s.mixedMeta(r, sc)
	if !ok {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	limit, offset, ok := paging(w, r, s, 100)
	if !ok {
		return
	}
	search := strings.TrimSpace(qs.Get("q"))
	category := strings.TrimSpace(qs.Get("category"))
	zone := qs.Get("zone")
	newOnly := qs.Get("new") == "1"
	sortBy, desc := qs.Get("sort"), qs.Get("dir") != "asc"
	if _, known := store.SiteSorts[sortBy]; sortBy != "" && !known {
		s.writeErr(w, r, http.StatusBadRequest, "invalid_sort", "unknown sort column")
		return
	}
	if zone != "" && zone != "ru" && zone != "other" {
		s.writeErr(w, r, http.StatusBadRequest, "invalid_zone", "zone must be ru or other")
		return
	}
	if len(search) > 100 || len(category) > 64 {
		s.writeErr(w, r, http.StatusBadRequest, "invalid_search", "search or category is too long")
		return
	}
	subj, ok := s.subjectFrom(w, r, sc)
	if !ok {
		return
	}
	out := struct {
		Meta       aMeta         `json:"meta"`
		Rows       []siteOut     `json:"rows"`
		Categories []categoryOut `json:"categories"`
		Groups     int           `json:"groups"`
		Total      int           `json:"total_connections"`
		Limit      int           `json:"limit"`
		Offset     int           `json:"offset"`
	}{Meta: meta, Rows: []siteOut{}, Categories: []categoryOut{}, Limit: limit, Offset: offset}
	if meta.State == "ok" {
		q := sc.query()
		q.Subject, q.Search, q.Category, q.Zone, q.NewOnly, q.Limit, q.Offset = subj, search, category, zone, newOnly, limit, offset
		q.Sort, q.Desc = sortBy, desc
		qc := q
		qc.Search, qc.Category = "", ""
		var cats []store.CategoryRow
		var catErr error
		done := make(chan struct{})
		go func() { defer close(done); cats, catErr = s.Store.Categories(r.Context(), qc) }()
		rows, groups, total, err := s.Store.Sites(r.Context(), q)
		<-done
		if err == nil {
			err = catErr
		}
		if err != nil {
			if r.Context().Err() != nil {
				return // the browser gave up (a newer filter was chosen): nobody is listening
			}
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		out.Groups, out.Total = groups, total
		for _, x := range rows {
			out.Rows = append(out.Rows, siteOut{Site: x.Site, Service: x.Service, Confidence: x.Confidence, Category: catLabel(x.Category), Classified: x.Category != "", Origin: x.Origin, Sources: srcList(x.Sources),
				Connections: x.Connections, Visits: x.Visits, Share: share(x.Connections, total), Users: x.Users, Devices: x.Devices, Hosts: x.Hosts,
				Bytes: bytesPtr(x.Bytes, x.RouterConns), RouterConnections: x.RouterConns, RU: x.RU, Blocked: x.Blocked, Warp: x.Warp, FirstSeen: x.First.UTC(), LastSeen: x.Last.UTC()})
		}
		all := 0
		for _, c := range cats {
			all += c.Connections
		}
		for _, c := range cats {
			out.Categories = append(out.Categories, categoryOut{Category: c.Category, Classified: c.Category != store.UncategorisedLabel, Sites: c.Sites,
				Connections: c.Connections, Visits: c.Visits, Share: share(c.Connections, all), Users: c.Users, Bytes: bytesPtr(c.Bytes, c.RouterConns), RouterConnections: c.RouterConns})
		}
		if all == 0 && search == "" && category == "" {
			out.Meta.State, out.Meta.Reason = "no_data", "no_events"
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func catLabel(c string) string {
	if c == "" {
		return store.UncategorisedLabel
	}
	return c
}

type siteWhoOut struct {
	Kind        string    `json:"kind"` // user | device | raw | awg
	Label       string    `json:"label"`
	Note        string    `json:"note,omitempty"`
	PanelName   string    `json:"panel_name"`
	Subject     string    `json:"subject"`
	Connections int       `json:"connections"`
	Visits      int       `json:"visits"`
	Bytes       *int64    `json:"bytes"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

type siteHostOut struct {
	Host              string    `json:"host"`
	Connections       int       `json:"connections"`
	Share             float64   `json:"share"`
	Users             int       `json:"users"`
	Bytes             *int64    `json:"bytes"`
	RouterConnections int       `json:"router_connections"`
	LastSeen          time.Time `json:"last_seen"`
}

func (s *Server) analyticsSiteDetail(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	sc, ok := s.resolveScope(w, r, a)
	if !ok {
		return
	}
	site := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("site")))
	if site == "" || len(site) > 253 {
		s.writeErr(w, r, http.StatusBadRequest, "invalid_site", "site is required")
		return
	}
	meta, ok := s.mixedMeta(r, sc)
	if !ok {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	subj, ok := s.subjectFrom(w, r, sc)
	if !ok {
		return
	}
	out := struct {
		Meta        aMeta            `json:"meta"`
		Site        string           `json:"site"`
		Service     string           `json:"service,omitempty"`
		Category    string           `json:"category"`
		Classified  bool             `json:"classified"`
		Origin      string           `json:"origin,omitempty"`
		Auto        *store.AutoInfo  `json:"auto,omitempty"`
		Connections int              `json:"connections"`
		Visits      int              `json:"visits"`
		Users       int              `json:"users"`
		Bytes       *int64           `json:"bytes"`
		FirstSeen   *time.Time       `json:"first_seen"`
		LastSeen    *time.Time       `json:"last_seen"`
		Who         []siteWhoOut     `json:"who"`
		Hosts       []siteHostOut    `json:"hosts"`
		Timeline    []map[string]any `json:"timeline"`
	}{Meta: meta, Site: site, Category: store.UncategorisedLabel, Who: []siteWhoOut{}, Hosts: []siteHostOut{}, Timeline: []map[string]any{}}
	if meta.State == "ok" {
		q := sc.query()
		q.Subject = subj
		d, err := s.Store.SiteDetailFor(r.Context(), q, site)
		if err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		out.Service, out.Classified = d.Service, d.Category != ""
		out.Category = catLabel(d.Category)
		out.Origin, out.Auto = d.Origin, d.Auto
		out.Connections, out.Visits, out.Users, out.Bytes = d.Connections, d.Visits, d.Users, bytesPtr(d.Bytes, d.RouterConns)
		if d.Connections > 0 {
			f, l := d.First.UTC(), d.Last.UTC()
			out.FirstSeen, out.LastSeen = &f, &l
		}
		for _, u := range d.Who {
			o := siteWhoOut{Connections: u.Connections, Visits: u.Visits, FirstSeen: u.First.UTC(), LastSeen: u.Last.UTC(), PanelName: sc.names[u.PanelID]}
			if u.Bytes > 0 || u.Device != "" {
				b := u.Bytes
				o.Bytes = &b
			}
			switch {
			case u.AWG != "":
				// An AmneziaWG device is not a panel user or a LAN device: it has no subject to narrow the views to.
				o.Kind = "awg"
				o.Label = u.DeviceName
				if o.Label == "" {
					o.Label = strings.TrimPrefix(u.AWG, "awg:")
				}
			case u.Device != "":
				o.Kind, o.Subject = "device", "device:"+u.PanelID+"|"+u.Device
				o.Label = u.Device
				if u.DeviceName != "" {
					o.Label = u.DeviceName + " (" + u.Device + ")"
				}
			case u.UserID != "":
				o.Kind, o.Subject = "user", "user:"+u.PanelID+"|"+u.UserID
				o.Label, o.Note = s.label(a, u.PanelID, u.DisplayName, u.Email, false)
			default:
				o.Kind, o.Subject = "raw", "raw:"+u.PanelID+"|"+u.Email
				o.Label, o.Note = s.label(a, u.PanelID, "", u.Email, false)
			}
			out.Who = append(out.Who, o)
		}
		for _, h := range d.Hosts {
			sh := 0.0
			if d.Connections > 0 {
				sh = float64(h.Connections) * 100 / float64(d.Connections)
			}
			out.Hosts = append(out.Hosts, siteHostOut{Host: h.Host, Connections: h.Connections, Share: sh, Users: h.Users, Bytes: bytesPtr(h.Bytes, h.RouterConns),
				RouterConnections: h.RouterConns, LastSeen: h.Last.UTC()})
		}
		for _, p := range d.Timeline {
			out.Timeline = append(out.Timeline, map[string]any{"ts": p.TS.Unix(), "connections": p.Connections})
		}
		if d.Connections == 0 {
			out.Meta.State, out.Meta.Reason = "no_data", "no_events"
		}
	}
	writeJSON(w, http.StatusOK, out)
}

type subjectOut struct {
	Subject     string `json:"subject"`
	Kind        string `json:"kind"`
	Label       string `json:"label"`
	PanelName   string `json:"panel_name"`
	Connections int    `json:"connections"`
}

// analyticsSubjects lists who can be picked in the filter: panel users and router devices.
func (s *Server) analyticsSubjects(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	sc, ok := s.resolveScope(w, r, a)
	if !ok {
		return
	}
	out := struct {
		Subjects []subjectOut `json:"subjects"`
	}{Subjects: []subjectOut{}}
	if len(sc.ids) > 0 {
		rows, err := s.Store.Subjects(r.Context(), sc.query())
		if err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		for _, x := range rows {
			o := subjectOut{Subject: x.Kind + ":" + x.PanelID + "|" + x.ID, Kind: x.Kind, PanelName: sc.names[x.PanelID], Connections: x.Connections}
			switch x.Kind {
			case "device":
				o.Label = x.ID
				if x.Name != "" {
					o.Label = x.Name + " (" + x.ID + ")"
				}
			case "path":
				o.Label = pathLabel(x.ID)
			case "awg":
				switch {
				case x.ID == "*":
					o.Label = "Все устройства AmneziaWG"
				case x.Name != "" && x.Name != x.ID:
					o.Label = x.Name + " (" + x.ID + ")"
				default:
					o.Label = x.ID
				}
			case "user":
				o.Label, _ = s.label(a, x.PanelID, x.Name, x.ID, false)
			default:
				o.Label, _ = s.label(a, x.PanelID, "", x.ID, false)
			}
			out.Subjects = append(out.Subjects, o)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// pathLabel names a node inbound for people. The CDN entrance is the one set up for mobile
// networks (client -> CDN -> nginx -> Xray XHTTP on the node); the others are direct Reality.
func pathLabel(tag string) string {
	switch tag {
	case "XHTTP-TW":
		return "Мобильный CDN (XHTTP-TW)"
	default:
		return "Прямой вход (" + tag + ")"
	}
}

// analyticsActivity lays the range's traffic out by weekday and hour for a heat map.
func (s *Server) analyticsActivity(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	sc, ok := s.resolveScope(w, r, a)
	if !ok {
		return
	}
	off := 0
	if v := r.URL.Query().Get("tz_offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < -840 || n > 840 {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_tz", "tz_offset is minutes east of UTC, from -840 to 840")
			return
		}
		off = n
	}
	meta, ok := s.mixedMeta(r, sc)
	if !ok {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	subj, ok := s.subjectFrom(w, r, sc)
	if !ok {
		return
	}
	out := struct {
		Meta  aMeta   `json:"meta"`
		Grid  [][]int `json:"grid"`
		Max   int     `json:"max"`
		Total int     `json:"total"`
	}{Meta: meta, Grid: make([][]int, 7)}
	for i := range out.Grid {
		out.Grid[i] = make([]int, 24)
	}
	if meta.State == "ok" {
		q := sc.query()
		q.Subject = subj
		act, err := s.Store.ActivityGrid(r.Context(), q, off)
		if err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		for d := range act.Grid {
			copy(out.Grid[d], act.Grid[d][:])
		}
		out.Max, out.Total = act.Max, act.Sum
		if act.Sum == 0 {
			out.Meta.State, out.Meta.Reason = "no_data", "no_events"
		}
	}
	writeJSON(w, http.StatusOK, out)
}

type countryOut struct {
	Code        string  `json:"code"`
	Name        string  `json:"name"`
	Connections int     `json:"connections"`
	Share       float64 `json:"share"`
	Users       int     `json:"users"`
	Sites       int     `json:"sites"`
	Bytes       *int64  `json:"bytes"`
}

// analyticsCountries places connections by the country of the destination IP. The share is of the
// connections that could be placed; the rest are reported as counts so nothing is hidden.
func (s *Server) analyticsCountries(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	sc, ok := s.resolveScope(w, r, a)
	if !ok {
		return
	}
	meta, ok := s.mixedMeta(r, sc)
	if !ok {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	subj, ok := s.subjectFrom(w, r, sc)
	if !ok {
		return
	}
	limit, _, ok := paging(w, r, s, 100)
	if !ok {
		return
	}
	out := struct {
		Meta    aMeta        `json:"meta"`
		Rows    []countryOut `json:"rows"`
		Located int          `json:"located"`
		NoIP    int          `json:"no_ip"`
		Unknown int          `json:"unknown"`
		Total   int          `json:"total_connections"`
	}{Meta: meta, Rows: []countryOut{}}
	if meta.State == "ok" {
		q := sc.query()
		q.Subject = subj
		rows, err := s.Store.Countries(r.Context(), q)
		if err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		for _, x := range rows {
			out.Total += x.Connections
			switch x.Code {
			case "":
				out.NoIP += x.Connections
			case store.UnknownCountry:
				out.Unknown += x.Connections
			default:
				out.Located += x.Connections
			}
		}
		for _, x := range rows {
			if x.Code == "" || x.Code == store.UnknownCountry || len(out.Rows) >= limit {
				continue
			}
			out.Rows = append(out.Rows, countryOut{Code: x.Code, Name: geoip.Name(x.Code), Connections: x.Connections, Share: share(x.Connections, out.Located),
				Users: x.Users, Sites: x.Sites, Bytes: bytesPtr(x.Bytes, x.RouterConns)})
		}
		if out.Total == 0 {
			out.Meta.State, out.Meta.Reason = "no_data", "no_events"
		}
	}
	writeJSON(w, http.StatusOK, out)
}

type networkOut struct {
	ASN         uint32   `json:"asn"`
	Org         string   `json:"org"`
	Connections int      `json:"connections"`
	Share       float64  `json:"share"`
	IPs         int      `json:"ips"`
	Bytes       *int64   `json:"bytes"`
	Examples    []string `json:"examples"`
}

// analyticsNetworks groups the connections that have no domain (a bare IP in the log) by the
// organisation that owns the address range. It is the owner of the range, not what the person
// did there, and it is labelled that way.
func (s *Server) analyticsNetworks(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	sc, ok := s.resolveScope(w, r, a)
	if !ok {
		return
	}
	meta, ok := s.mixedMeta(r, sc)
	if !ok {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	subj, ok := s.subjectFrom(w, r, sc)
	if !ok {
		return
	}
	limit, _, ok := paging(w, r, s, 100)
	if !ok {
		return
	}
	out := struct {
		Meta    aMeta        `json:"meta"`
		Rows    []networkOut `json:"rows"`
		IPOnly  int          `json:"ip_only"` // connections that are a bare IP
		Matched int          `json:"matched"` // of those, the ones whose owner is known
		Unknown int          `json:"unknown"`
	}{Meta: meta, Rows: []networkOut{}}
	if meta.State == "ok" {
		q := sc.query()
		q.Subject = subj
		ips, err := s.Store.IPOnlyDestinations(r.Context(), q)
		if err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		type agg struct {
			row   networkOut
			rconn int
			b     int64
		}
		by := map[uint32]*agg{}
		db := asn.Default()
		for _, x := range ips {
			out.IPOnly += x.Connections
			ip, err := netip.ParseAddr(x.IP)
			if err != nil {
				out.Unknown += x.Connections
				continue
			}
			o, found := db.Lookup(ip)
			if !found {
				out.Unknown += x.Connections
				continue
			}
			out.Matched += x.Connections
			g := by[o.ASN]
			if g == nil {
				g = &agg{row: networkOut{ASN: o.ASN, Org: o.Org, Examples: []string{}}}
				by[o.ASN] = g
			}
			g.row.Connections += x.Connections
			g.row.IPs++
			g.rconn += x.RouterConns
			g.b += x.Bytes
			if len(g.row.Examples) < 3 {
				g.row.Examples = append(g.row.Examples, x.IP)
			}
		}
		for _, g := range by {
			g.row.Share = share(g.row.Connections, out.Matched)
			g.row.Bytes = bytesPtr(g.b, g.rconn)
			out.Rows = append(out.Rows, g.row)
		}
		sort.Slice(out.Rows, func(i, j int) bool {
			if out.Rows[i].Connections != out.Rows[j].Connections {
				return out.Rows[i].Connections > out.Rows[j].Connections
			}
			return out.Rows[i].ASN < out.Rows[j].ASN
		})
		if len(out.Rows) > limit {
			out.Rows = out.Rows[:limit]
		}
		if out.IPOnly == 0 {
			out.Meta.State, out.Meta.Reason = "no_data", "no_events"
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// srcList keeps a list of sources in a fixed order and never null in JSON.
func srcList(in []string) []string {
	out := []string{}
	for _, want := range []string{"node", "router", "awg"} {
		for _, s := range in {
			if s == want {
				out = append(out, s)
				break
			}
		}
	}
	return out
}
