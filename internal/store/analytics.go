package store

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AnalyticsQuery is the scope shared by every analyzer query. Panel ids must already be
// authorised and non-demo; each statement is restricted to them again here.
type AnalyticsQuery struct {
	PanelIDs    []string
	NodeIDs     []string
	From, To    time.Time
	Search      string
	GroupBy     string // host | ip | service
	Limit       int
	Offset      int
	Granularity time.Duration
	Subject     Subject // narrows to one person or device (queries built on eventsCTE)
	Site        string  // only hosts of this site (group_by=host)
	Category    string  // only traffic of this category (host-level rule)
	Service     string  // only traffic of this service (host-level rule)
	Zone        string  // "" | "ru" (.ru .su .рф) | "other": only for the sites view
	NewOnly     bool    // only sites that nobody in scope had visited before the range started
}

func (q AnalyticsQuery) args() []any {
	return []any{uuids(q.PanelIDs), uuids(q.NodeIDs), q.From, q.To}
}

const aScope = `e.panel_id = ANY($1::uuid[]) AND (cardinality($2::uuid[]) = 0 OR e.node_id = ANY($2::uuid[])) AND e.ts >= $3 AND e.ts < $4`

// likeEscape makes user text safe to put inside an ILIKE pattern.
func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

type DestRow struct {
	Key         string
	Kind        string // domain | ip | service
	Service     string
	Confidence  string
	Connections int
	Users       int
	Nodes       int
	LastSeen    time.Time
	Ports       []int32
	Category    string
	Origin      string   // see OriginOf
	Bytes       int64    // router-counted bytes; only meaningful when RouterConns > 0
	RouterConns int      // connections that came from a router agent (they carry a domain and bytes)
	Sources     []string // where the connections came from: node | router | awg
}

// Destinations groups accepted connections by destination host, IP, site or service.
// Service and category come from versioned domain rules and nothing else: an IP is never
// mapped to a service. Counts are connection_count (log lines and router records), bytes only
// exist for router records.
func (s *Store) Destinations(ctx context.Context, q AnalyticsQuery) (rows []DestRow, groups, total int, err error) {
	if q.Limit <= 0 || q.Limit > 200 {
		q.Limit = 50
	}
	args := q.args7()
	args = append(args, "%"+likeEscape(q.Search)+"%", q.Limit, q.Offset, q.Site, q.Service, q.Category)

	// $8 search, $9 limit, $10 offset, $11 site, $12 service, $13 category ('' = no filter).
	// Service and category are always those of the HOST (the most specific rule), so a drill-down
	// category -> service -> site -> host adds up at every level. A site row shows the rule of the
	// site itself.
	const svcExpr = `COALESCE(h.service, CASE WHEN ev.host IS NULL THEN 'IP без домена' ELSE 'Не определён' END)`
	const catExpr = `COALESCE(h.category, CASE WHEN ev.host IS NULL THEN 'IP без домена' ELSE '` + UncategorisedLabel + `' END)`
	var keyExpr, kind, where string
	showSite := false
	switch q.GroupBy {
	case "ip":
		keyExpr, kind, where = `ev.ip`, "'ip'", `ev.ip IS NOT NULL`
	case "service":
		keyExpr, kind, where = svcExpr, "'service'", `TRUE`
	case "category":
		keyExpr, kind, where = catExpr, "'category'", `TRUE`
	case "site":
		keyExpr, kind, where = `ev.site`, "'site'", `ev.site IS NOT NULL AND ev.site !~ '^[0-9]+(\.[0-9]+){3}$' AND position(':' IN ev.site) = 0`
		showSite = true
	default:
		keyExpr, kind, where = `COALESCE(ev.host, ev.ip)`, `CASE WHEN ev.host IS NOT NULL THEN 'domain' ELSE 'ip' END`, `TRUE`
	}
	shown := `h`
	if showSite {
		shown = `st`
	}
	sql := `
WITH ` + eventsCTE + `, hosts AS (SELECT DISTINCT host AS name FROM ev WHERE host IS NOT NULL),
hcls AS (SELECT n.name, r.service, r.confidence, r.category, r.source, r.score FROM hosts n ` + ruleMatch("n.name") + `),
sites AS (SELECT DISTINCT site AS name FROM ev WHERE site IS NOT NULL),
scls AS (SELECT n.name, r.service, r.confidence, r.category, r.source, r.score FROM sites n ` + ruleMatch("n.name") + `), agg AS (
  SELECT ` + keyExpr + ` AS key, ` + kind + ` AS kind, max(` + shown + `.service) AS service, min(` + shown + `.confidence) AS confidence, max(` + shown + `.category) AS category, max(` + shown + `.source) AS source, min(` + shown + `.score) AS score,
         sum(ev.w)::bigint AS conns, count(DISTINCT ev.ukey) AS users, count(DISTINCT ev.node_id) AS nodes, max(ev.ts) AS last_seen,
         array_agg(DISTINCT ev.port) AS ports, COALESCE(sum(ev.bytes), 0) AS bytes, count(*) FILTER (WHERE ev.rtr) AS rconns, array_agg(DISTINCT ev.src) AS srcs
  FROM ev LEFT JOIN hcls h ON h.name = ev.host LEFT JOIN scls st ON st.name = ev.site
  WHERE ` + where + ` AND ($11::text = '' OR ev.site = $11::text)
    AND ($12::text = '' OR ` + svcExpr + ` = $12::text) AND ($13::text = '' OR ` + catExpr + ` = $13::text)
  GROUP BY 1, 2
)
SELECT key, kind, COALESCE(service,''), COALESCE(confidence,''), COALESCE(category,''), COALESCE(source,''), COALESCE(score,0), conns, users, nodes, last_seen, ports, bytes, rconns, srcs,
       count(*) OVER () AS groups, sum(conns) OVER () AS total
FROM agg WHERE key ILIKE $8 ESCAPE ''
ORDER BY conns DESC, key LIMIT $9 OFFSET $10`
	rs, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rs.Close()
	for rs.Next() {
		var r DestRow
		var g, t int64
		var src string
		var score float64
		if err := rs.Scan(&r.Key, &r.Kind, &r.Service, &r.Confidence, &r.Category, &src, &score, &r.Connections, &r.Users, &r.Nodes, &r.LastSeen, &r.Ports, &r.Bytes, &r.RouterConns, &r.Sources, &g, &t); err != nil {
			return nil, 0, 0, err
		}
		r.Origin = OriginOf(src, score)
		groups, total = int(g), int(t)
		switch q.GroupBy {
		case "service":
			r.Service = r.Key
		case "category":
			r.Category = r.Key
		}
		if len(r.Ports) > 8 {
			r.Ports = r.Ports[:8]
		}
		rows = append(rows, r)
	}
	if rows == nil {
		rows = []DestRow{}
	}
	return rows, groups, total, rs.Err()
}

type UserRow struct {
	PanelID      string
	UserID       string // empty when unresolved or internal
	Email        string
	Internal     bool
	Name         string
	Connections  int
	Destinations int
	Nodes        int
	UDP          int
	First, Last  time.Time
}

func (s *Store) UsersAnalytics(ctx context.Context, q AnalyticsQuery) ([]UserRow, int, error) {
	rs, err := s.pool.Query(ctx, `SELECT e.panel_id, e.user_id, COALESCE(e.xray_email,''), e.internal, COALESCE(u.display_name,''),
			count(*), count(DISTINCT COALESCE(e.destination_host, host(e.destination_ip))), count(DISTINCT e.node_id),
			count(*) FILTER (WHERE e.protocol='udp'), min(e.ts), max(e.ts), sum(count(*)) OVER ()
		FROM connection_events e LEFT JOIN users u ON u.id=e.user_id AND u.panel_id=e.panel_id
		WHERE `+aScope+` GROUP BY e.panel_id, e.user_id, e.xray_email, e.internal, u.display_name
		ORDER BY count(*) DESC, 1, 3 LIMIT 200`, q.args()...)
	if err != nil {
		return nil, 0, err
	}
	defer rs.Close()
	var out []UserRow
	total := 0
	for rs.Next() {
		var r UserRow
		var pid uuid.UUID
		var uid *uuid.UUID
		var t int64
		if err := rs.Scan(&pid, &uid, &r.Email, &r.Internal, &r.Name, &r.Connections, &r.Destinations, &r.Nodes, &r.UDP, &r.First, &r.Last, &t); err != nil {
			return nil, 0, err
		}
		r.PanelID = pid.String()
		if uid != nil {
			r.UserID = uid.String()
		}
		total = int(t)
		out = append(out, r)
	}
	if out == nil {
		out = []UserRow{}
	}
	return out, total, rs.Err()
}

// UserKey identifies who an analyzer row is about: a panel user, an unresolved raw id,
// or the node's own system traffic. It is always interpreted inside one panel.
type UserKey struct {
	PanelID  string
	UserID   string // uuid of the panel user
	Email    string // unresolved raw id
	Internal bool
}

type NamedCount struct {
	Key     string
	Service string
	Count   int
}

type UserDetail struct {
	Total    int
	TCP, UDP int
	Buckets  []Bucket
	Hosts    []NamedCount
	Ports    []NamedCount
	Nodes    []NamedCount
}

func (k UserKey) cond() (string, []any) {
	switch {
	case k.Internal:
		return `(e.internal AND $5::text IS NULL)`, []any{nil}
	case k.UserID != "":
		id, _ := uuid.Parse(k.UserID)
		return `e.user_id = $5::uuid`, []any{id}
	default:
		return `(e.user_id IS NULL AND NOT e.internal AND COALESCE(e.xray_email,'') = $5::text)`, []any{k.Email}
	}
}

func (s *Store) UserDetail(ctx context.Context, q AnalyticsQuery, k UserKey) (UserDetail, error) {
	var d UserDetail
	pid, err := uuid.Parse(k.PanelID)
	if err != nil {
		return d, ErrNotFound
	}
	q.PanelIDs = []string{pid.String()}
	cond, extra := k.cond()
	base := append(q.args(), extra...) // $5 is always the key parameter
	gran := q.Granularity
	if gran < time.Minute {
		gran = time.Minute
	}
	where := aScope + ` AND ` + cond

	if err := s.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE e.protocol='tcp'), count(*) FILTER (WHERE e.protocol='udp') FROM connection_events e WHERE `+where, base...).Scan(&d.Total, &d.TCP, &d.UDP); err != nil {
		return d, err
	}
	bs, err := s.pool.Query(ctx, `SELECT date_bin(make_interval(secs => $6), e.ts, $7::timestamptz) AS b,
			count(*) FILTER (WHERE e.protocol='tcp'), count(*) FILTER (WHERE e.protocol='udp')
		FROM connection_events e WHERE `+where+` GROUP BY b ORDER BY b`, append(append([]any{}, base...), gran.Seconds(), q.From.Truncate(gran))...)
	if err != nil {
		return d, err
	}
	for bs.Next() {
		var b Bucket
		if err := bs.Scan(&b.TS, &b.TCP, &b.UDP); err != nil {
			bs.Close()
			return d, err
		}
		d.Buckets = append(d.Buckets, b)
	}
	bs.Close()

	top := func(sql string) ([]NamedCount, error) {
		rs, err := s.pool.Query(ctx, sql, base...)
		if err != nil {
			return nil, err
		}
		defer rs.Close()
		var out []NamedCount
		for rs.Next() {
			var n NamedCount
			if err := rs.Scan(&n.Key, &n.Service, &n.Count); err != nil {
				return nil, err
			}
			out = append(out, n)
		}
		return out, rs.Err()
	}
	if d.Hosts, err = top(`WITH ev AS (SELECT COALESCE(e.destination_host, host(e.destination_ip)) AS k, e.destination_host AS h FROM connection_events e WHERE ` + where + `),
		g AS (SELECT k, h, count(*) AS c FROM ev GROUP BY k, h ORDER BY c DESC, k LIMIT 15)
		SELECT g.k, COALESCE((SELECT sr.service FROM service_rules sr WHERE sr.enabled AND g.h IS NOT NULL AND (g.h = sr.pattern OR g.h LIKE '%.' || sr.pattern)
		                      ORDER BY length(sr.pattern) DESC LIMIT 1), ''), g.c FROM g ORDER BY g.c DESC, g.k`); err != nil {
		return d, err
	}
	if d.Ports, err = top(`SELECT e.destination_port::text, '', count(*) FROM connection_events e WHERE ` + where + ` GROUP BY 1 ORDER BY 3 DESC, 1 LIMIT 8`); err != nil {
		return d, err
	}
	if d.Nodes, err = top(`SELECT nd.name, '', count(*) FROM connection_events e JOIN nodes nd ON nd.id=e.node_id AND nd.panel_id=e.panel_id WHERE ` + where + ` GROUP BY 1 ORDER BY 3 DESC, 1`); err != nil {
		return d, err
	}
	return d, nil
}

type NodeAnalytics struct {
	NodeSeen
	Connections  int
	TCP, UDP     int
	Users        int
	Destinations int
	LastEvent    *time.Time
}

func (s *Store) NodesAnalytics(ctx context.Context, q AnalyticsQuery) ([]NodeAnalytics, error) {
	nodes, err := s.NodesInScope(ctx, q.PanelIDs, q.NodeIDs)
	if err != nil {
		return nil, err
	}
	rs, err := s.pool.Query(ctx, `SELECT e.node_id, count(*), count(*) FILTER (WHERE e.protocol='tcp'), count(*) FILTER (WHERE e.protocol='udp'),
			count(DISTINCT COALESCE(e.user_id::text, 'raw:' || COALESCE(e.xray_email,'-'))), count(DISTINCT COALESCE(e.destination_host, host(e.destination_ip))), max(e.ts)
		FROM connection_events e WHERE `+aScope+` GROUP BY e.node_id`, q.args()...)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	type agg struct {
		c, tcp, udp, u, d int
		last              time.Time
	}
	by := map[string]agg{}
	for rs.Next() {
		var id uuid.UUID
		var a agg
		if err := rs.Scan(&id, &a.c, &a.tcp, &a.udp, &a.u, &a.d, &a.last); err != nil {
			return nil, err
		}
		by[id.String()] = a
	}
	out := make([]NodeAnalytics, 0, len(nodes))
	for _, n := range nodes {
		na := NodeAnalytics{NodeSeen: n}
		if a, ok := by[n.NodeID]; ok {
			l := a.last
			na.Connections, na.TCP, na.UDP, na.Users, na.Destinations, na.LastEvent = a.c, a.tcp, a.udp, a.u, a.d, &l
		}
		out = append(out, na)
	}
	return out, rs.Err()
}
