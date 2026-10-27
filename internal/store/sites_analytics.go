package store

import (
	"cmp"
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// visits counts a connection as the start of a new visit when the same person (or device) had
// not touched the same site for SessionGap before it.
// c carries only the columns the summaries read: the window sort below runs over every event of the range, and
// the full rows (hundreds of bytes each) made it spill to disk.
func visitsCTE() string {
	return `, c AS (
  SELECT ev.site, ev.w, ev.src, ev.ukey, ev.dev, ev.host, ev.ip, ev.bytes, ev.rtr, ev.ts, lag(ev.ts) OVER (PARTITION BY ev.ukey, ev.site ORDER BY ev.ts) AS prev
  FROM ev WHERE ev.site IS NOT NULL AND ev.site !~ '^[0-9]+(\.[0-9]+){3}$' AND position(':' IN ev.site) = 0
), sites AS (SELECT DISTINCT site AS name FROM c),
cls AS MATERIALIZED (SELECT s.name, r.service, r.confidence, r.category, r.source, r.score FROM sites s ` + ruleMatch("s.name") + `)`
}

const isVisit = `(c.prev IS NULL OR c.ts - c.prev > make_interval(secs => 1800))`

type SiteRow struct {
	Site        string
	Service     string
	Confidence  string
	Category    string
	Origin      string // OriginRule | OriginManual | OriginAuto | OriginGuess, empty when not classified
	Connections int
	Visits      int
	Users       int
	Devices     int
	Hosts       int
	Bytes       int64
	RouterConns int
	First, Last time.Time
	Sources     []string // where its connections came from: node | router | awg
	RU          bool     // the site is in a Russian zone (.ru, .su, .рф)
	Blocked     int      // node log lines for this site that the node sent to BLOCK
	Warp        int      // ... and to WARP
}

// ruZone matches the Russian country-code zones. It is a property of the domain name only.
const ruZone = `~ '\.(ru|su|xn--p1ai)$'`

// Sites summarises traffic per site (registrable domain). Connections without a domain have no
// site and are not part of this view.
func (s *Store) Sites(ctx context.Context, q AnalyticsQuery) (rows []SiteRow, groups, total int, err error) {
	if q.Limit <= 0 || q.Limit > 200 {
		q.Limit = 50
	}
	all, err := s.allSites(ctx, q)
	if err != nil {
		return nil, 0, 0, err
	}
	needle := strings.ToLower(strings.TrimSpace(q.Search))
	var list []SiteRow
	for _, r := range all {
		if needle != "" && !strings.Contains(strings.ToLower(r.Site), needle) && !strings.Contains(strings.ToLower(r.Service), needle) {
			continue
		}
		if q.Category != "" {
			cat := r.Category
			if cat == "" {
				cat = UncategorisedLabel
			}
			if cat != q.Category {
				continue
			}
		}
		if q.Zone != "" && (q.Zone == "ru") != r.RU {
			continue
		}
		list = append(list, r)
		total += r.Connections
	}
	groups = len(list)
	sortSites(list, q.Sort, q.Desc)
	if q.Offset >= len(list) {
		return []SiteRow{}, groups, total, nil
	}
	end := q.Offset + q.Limit
	if end > len(list) {
		end = len(list)
	}
	return list[q.Offset:end], groups, total, nil
}

// SiteSorts are the columns the Sites table can be ordered by.
var SiteSorts = map[string]func(a, b *SiteRow) int{
	"site":        func(a, b *SiteRow) int { return strings.Compare(strings.ToLower(a.Site), strings.ToLower(b.Site)) },
	"category":    func(a, b *SiteRow) int { return strings.Compare(a.Category, b.Category) },
	"visits":      func(a, b *SiteRow) int { return a.Visits - b.Visits },
	"connections": func(a, b *SiteRow) int { return a.Connections - b.Connections },
	"users":       func(a, b *SiteRow) int { return a.Users - b.Users },
	"devices":     func(a, b *SiteRow) int { return a.Devices - b.Devices },
	"hosts":       func(a, b *SiteRow) int { return a.Hosts - b.Hosts },
	"bytes":       func(a, b *SiteRow) int { return cmp.Compare(a.Bytes, b.Bytes) },
	"blocked":     func(a, b *SiteRow) int { return a.Blocked - b.Blocked },
	"warp":        func(a, b *SiteRow) int { return a.Warp - b.Warp },
	"last":        func(a, b *SiteRow) int { return a.Last.Compare(b.Last) },
}

func sortSites(list []SiteRow, by string, desc bool) {
	f, ok := SiteSorts[by]
	if !ok {
		f, desc = SiteSorts["connections"], true
	}
	sort.SliceStable(list, func(i, j int) bool {
		if c := f(&list[i], &list[j]); c != 0 {
			if desc {
				return c > 0
			}
			return c < 0
		}
		return list[i].Site < list[j].Site
	})
}

type sitesEntry struct {
	rows []SiteRow
	at   time.Time
}

var sitesCache = struct {
	sync.Mutex
	m map[string]sitesEntry
}{m: map[string]sitesEntry{}}

// dropAnalyticsCache forgets the cached Sites and category summaries; they depend on the rules, so any rule change calls it.
func dropAnalyticsCache() {
	sitesCache.Lock()
	sitesCache.m = map[string]sitesEntry{}
	sitesCache.Unlock()
	catCache.Lock()
	catCache.m = map[string]catEntry{}
	catCache.Unlock()
	memo.Lock()
	memo.m = map[string]memoEntry{}
	memo.Unlock()
}

// allSites is every site of the scope and range with its figures, not narrowed by search, category or zone, and kept
// for catCacheTTL: filtering, ordering and paging are done on this list, so none of them touches the events again.
func (s *Store) allSites(ctx context.Context, q AnalyticsQuery) ([]SiteRow, error) {
	key := fmt.Sprint(append(q.args7(), q.NewOnly)...)
	sitesCache.Lock()
	if e, ok := sitesCache.m[key]; ok && time.Since(e.at) < catCacheTTL {
		sitesCache.Unlock()
		return e.rows, nil
	}
	sitesCache.Unlock()
	rows, err := s.sites(ctx, q)
	if err != nil {
		return nil, err
	}
	sitesCache.Lock()
	if len(sitesCache.m) > 64 {
		sitesCache.m = map[string]sitesEntry{}
	}
	sitesCache.m[key] = sitesEntry{rows: rows, at: time.Now()}
	sitesCache.Unlock()
	return rows, nil
}

func (s *Store) sites(ctx context.Context, q AnalyticsQuery) ([]SiteRow, error) {
	args := append(q.args7(), q.NewOnly)
	// What the nodes did with the traffic comes from their own log lines. It is counted apart from
	// the unioned events: for a user a router agent stands for, the nodes' copy is hidden from the
	// counts above (it would be counted twice) but still says what the node did with it.
	sql := `WITH ` + eventsCTE + visitsCTE() + `, oc AS (
  SELECT e.site, count(*) FILTER (WHERE e.outbound_tag = 'BLOCK') AS blocked, count(*) FILTER (WHERE e.outbound_tag = 'warp-out') AS warp
  FROM connection_events e WHERE ` + aScope + ` AND e.site IS NOT NULL
    AND ($5::text = '' OR ($5 = 'user' AND e.panel_id = $6::uuid AND e.user_id::text = $7::text)
         OR ($5 = 'raw' AND e.panel_id = $6::uuid AND e.user_id IS NULL AND e.xray_email = $7::text)
         OR ($5 = 'path' AND e.panel_id = $6::uuid AND e.inbound_tag = $7::text))
  GROUP BY e.site
), fs AS (
  SELECT x.site, min(x.ts) AS first_ever FROM (
    SELECT e.site, e.ts FROM connection_events e WHERE $8::bool AND e.panel_id = ANY($1::uuid[]) AND e.site IS NOT NULL
    UNION ALL
    SELECT d.site, d.started_at FROM device_connections d WHERE $8::bool AND d.panel_id = ANY($1::uuid[]) AND d.site IS NOT NULL
  ) x GROUP BY x.site
), agg AS (
  SELECT c.site, sum(c.w)::bigint AS conns, count(*) FILTER (WHERE ` + isVisit + ` AND c.src <> 'awg') AS visits, count(DISTINCT c.ukey) AS users,
         count(DISTINCT c.dev) FILTER (WHERE c.dev IS NOT NULL) AS devices, count(DISTINCT COALESCE(c.host, c.ip)) AS hosts,
         COALESCE(sum(c.bytes), 0) AS bytes, count(*) FILTER (WHERE c.rtr) AS rconns, min(c.ts) AS first, max(c.ts) AS last, array_agg(DISTINCT c.src) AS srcs
  FROM c GROUP BY c.site
)
SELECT a.site, COALESCE(k.service,''), COALESCE(k.confidence,''), COALESCE(k.category,''), COALESCE(k.source,''), COALESCE(k.score,0), a.conns, a.visits, a.users, a.devices, a.hosts, a.bytes, a.rconns, a.first, a.last, a.srcs,
       a.site ` + ruZone + `, COALESCE(o.blocked, 0), COALESCE(o.warp, 0)
FROM agg a JOIN cls k ON k.name = a.site LEFT JOIN oc o ON o.site = a.site LEFT JOIN fs ON fs.site = a.site
WHERE (NOT $8::bool OR fs.first_ever >= $3::timestamptz)
ORDER BY a.conns DESC, a.site`
	rs, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	rows := []SiteRow{}
	for rs.Next() {
		var r SiteRow
		var src string
		var score float64
		if err := rs.Scan(&r.Site, &r.Service, &r.Confidence, &r.Category, &src, &score, &r.Connections, &r.Visits, &r.Users, &r.Devices, &r.Hosts, &r.Bytes, &r.RouterConns, &r.First, &r.Last, &r.Sources, &r.RU, &r.Blocked, &r.Warp); err != nil {
			return nil, err
		}
		r.Origin = OriginOf(src, score)
		rows = append(rows, r)
	}
	return rows, rs.Err()
}

type CategoryRow struct {
	Category    string
	Sites       int
	Connections int
	Visits      int
	Users       int
	Bytes       int64
	RouterConns int
}

// Categories summarises the same traffic by category; sites no rule knows are grouped under
// UncategorisedLabel.
//
// The result is kept for catCacheTTL per scope, range and subject: changing the category filter or
// the page on the Sites screen asks for the same summary again and must not recompute it.
func (s *Store) Categories(ctx context.Context, q AnalyticsQuery) ([]CategoryRow, error) {
	key := fmt.Sprint(q.args7()...)
	catCache.Lock()
	if e, ok := catCache.m[key]; ok && time.Since(e.at) < catCacheTTL {
		catCache.Unlock()
		return e.rows, nil
	}
	catCache.Unlock()
	rows, err := s.categories(ctx, q)
	if err != nil {
		return nil, err
	}
	catCache.Lock()
	if len(catCache.m) > 64 {
		catCache.m = map[string]catEntry{}
	}
	catCache.m[key] = catEntry{rows: rows, at: time.Now()}
	catCache.Unlock()
	return rows, nil
}

// A few minutes old is fine for a summary of days of traffic, and it is what makes paging and filtering instant.
var catCacheTTL = 5 * time.Minute

type catEntry struct {
	rows []CategoryRow
	at   time.Time
}

var catCache = struct {
	sync.Mutex
	m map[string]catEntry
}{m: map[string]catEntry{}}

func (s *Store) categories(ctx context.Context, q AnalyticsQuery) ([]CategoryRow, error) {
	sql := `WITH ` + eventsCTE + visitsCTE() + `
SELECT COALESCE(k.category, '` + UncategorisedLabel + `'), count(DISTINCT c.site), sum(c.w)::bigint, count(*) FILTER (WHERE ` + isVisit + ` AND c.src <> 'awg'),
       count(DISTINCT c.ukey), COALESCE(sum(c.bytes), 0), count(*) FILTER (WHERE c.rtr)
FROM c JOIN cls k ON k.name = c.site GROUP BY 1 ORDER BY sum(c.w) DESC, 1`
	rs, err := s.pool.Query(ctx, sql, q.args7()...)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := []CategoryRow{}
	for rs.Next() {
		var r CategoryRow
		if err := rs.Scan(&r.Category, &r.Sites, &r.Connections, &r.Visits, &r.Users, &r.Bytes, &r.RouterConns); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rs.Err()
}

type SiteUser struct {
	PanelID     string
	UserID      string // panel user uuid, empty for devices and unresolved ids
	Email       string // id as the node logged it, for unresolved users
	DisplayName string
	Device      string // LAN IP when the row is a device
	AWG         string // 'awg:<address in the tunnel>' when the row is an AmneziaWG device
	DeviceName  string
	Connections int
	Visits      int
	Bytes       int64
	First, Last time.Time
}

type SiteHost struct {
	Host        string
	Connections int
	Users       int
	Bytes       int64
	RouterConns int
	Last        time.Time
}

type SiteDetail struct {
	Site        string
	Service     string
	Category    string
	Origin      string
	Auto        *AutoInfo
	Connections int
	Visits      int
	Users       int
	Bytes       int64
	RouterConns int
	First, Last time.Time
	Who         []SiteUser
	Hosts       []SiteHost // the hierarchy below the site: its subdomains
	Timeline    []DevicePoint
}

// SiteDetailFor returns who went to one site, which of its hosts, and when.
func (s *Store) SiteDetailFor(ctx context.Context, q AnalyticsQuery, site string) (SiteDetail, error) {
	d := SiteDetail{Site: site, Who: []SiteUser{}, Hosts: []SiteHost{}, Timeline: []DevicePoint{}}
	base := append(q.args7(), site)
	// $8 = the site. The visit window is computed over this site's events only.
	pre := `WITH ` + eventsCTE + `, c AS (
  SELECT ev.*, lag(ev.ts) OVER (PARTITION BY ev.ukey ORDER BY ev.ts) AS prev FROM ev WHERE ev.site = $8::text
)`
	err := s.pool.QueryRow(ctx, pre+`
SELECT COALESCE(sum(c.w), 0)::bigint, count(*) FILTER (WHERE `+isVisit+` AND c.src <> 'awg'), count(DISTINCT c.ukey), COALESCE(sum(c.bytes), 0), count(*) FILTER (WHERE c.rtr), min(c.ts), max(c.ts)
FROM c`, base...).Scan(&d.Connections, &d.Visits, &d.Users, &d.Bytes, &d.RouterConns, new(*time.Time), new(*time.Time))
	if err != nil {
		return d, err
	}
	var first, last *time.Time
	if err := s.pool.QueryRow(ctx, pre+`SELECT min(c.ts), max(c.ts) FROM c`, base...).Scan(&first, &last); err != nil {
		return d, err
	}
	if first != nil {
		d.First, d.Last = *first, *last
	}
	var svc, cat, src *string
	var score *float64
	if err := s.pool.QueryRow(ctx, `SELECT r.service, r.category, r.source, r.score FROM (SELECT $1::text AS name) s `+ruleMatch("s.name"), site).Scan(&svc, &cat, &src, &score); err == nil {
		if src != nil {
			sc := 0.0
			if score != nil {
				sc = *score
			}
			d.Origin = OriginOf(*src, sc)
			if d.Origin == OriginAuto || d.Origin == OriginGuess {
				d.Auto = s.AutoInfoFor(ctx, site)
			}
		}
		if svc != nil {
			d.Service = *svc
		}
		if cat != nil {
			d.Category = *cat
		}
	}

	ws, err := s.pool.Query(ctx, pre+`
SELECT c.panel_id, c.uid, COALESCE(c.email, ''), COALESCE(u.display_name, ''), COALESCE(c.dev, ''), COALESCE(max(c.dname), ''), COALESCE(CASE WHEN c.src = 'awg' THEN c.ukey END, ''),
       COALESCE(sum(c.w), 0)::bigint, count(*) FILTER (WHERE `+isVisit+` AND c.src <> 'awg'), COALESCE(sum(c.bytes), 0), min(c.ts), max(c.ts)
FROM c LEFT JOIN users u ON u.id = c.uid AND u.panel_id = c.panel_id
GROUP BY c.panel_id, c.uid, c.email, u.display_name, c.dev, CASE WHEN c.src = 'awg' THEN c.ukey END ORDER BY sum(c.w) DESC, 1, 3, 5, 7 LIMIT 100`, base...)
	if err != nil {
		return d, err
	}
	defer ws.Close()
	for ws.Next() {
		var u SiteUser
		var pid uuid.UUID
		var uid *uuid.UUID
		if err := ws.Scan(&pid, &uid, &u.Email, &u.DisplayName, &u.Device, &u.DeviceName, &u.AWG, &u.Connections, &u.Visits, &u.Bytes, &u.First, &u.Last); err != nil {
			return d, err
		}
		u.PanelID = pid.String()
		if uid != nil {
			u.UserID = uid.String()
		}
		d.Who = append(d.Who, u)
	}
	if err := ws.Err(); err != nil {
		return d, err
	}

	hs, err := s.pool.Query(ctx, pre+`
SELECT COALESCE(c.host, c.ip), sum(c.w)::bigint, count(DISTINCT c.ukey), COALESCE(sum(c.bytes), 0), count(*) FILTER (WHERE c.rtr), max(c.ts)
FROM c GROUP BY 1 ORDER BY sum(c.w) DESC, 1 LIMIT 100`, base...)
	if err != nil {
		return d, err
	}
	defer hs.Close()
	for hs.Next() {
		var h SiteHost
		if err := hs.Scan(&h.Host, &h.Connections, &h.Users, &h.Bytes, &h.RouterConns, &h.Last); err != nil {
			return d, err
		}
		d.Hosts = append(d.Hosts, h)
	}
	if err := hs.Err(); err != nil {
		return d, err
	}

	gran := q.Granularity
	if gran <= 0 {
		gran = time.Hour
	}
	ts, err := s.pool.Query(ctx, pre+`
SELECT to_timestamp(floor(extract(epoch FROM c.ts) / $9) * $9) AS b, COALESCE(sum(c.w), 0)::bigint, COALESCE(sum(c.bytes), 0), 0::bigint
FROM c GROUP BY 1 ORDER BY 1`, append(base, gran.Seconds())...)
	if err != nil {
		return d, err
	}
	defer ts.Close()
	for ts.Next() {
		var p DevicePoint
		if err := ts.Scan(&p.TS, &p.Connections, &p.Up, &p.Down); err != nil {
			return d, err
		}
		d.Timeline = append(d.Timeline, p)
	}
	return d, ts.Err()
}

type SubjectRow struct {
	Kind        string // user | raw | device | path
	PanelID     string
	ID          string
	Name        string // display name, device name or ""
	Connections int
}

// Subjects lists the people and devices that have traffic in the range, for the filter.
func (s *Store) Subjects(ctx context.Context, q AnalyticsQuery) ([]SubjectRow, error) {
	return memoized("subjects", q, nil, func() ([]SubjectRow, error) { return s.subjects(ctx, q) })
}

func (s *Store) subjects(ctx context.Context, q AnalyticsQuery) ([]SubjectRow, error) {
	rs, err := s.pool.Query(ctx, `WITH `+eventsCTE+`
SELECT CASE WHEN ev.dev IS NOT NULL THEN 'device' WHEN ev.uid IS NOT NULL THEN 'user' ELSE 'raw' END,
       ev.panel_id, COALESCE(ev.dev, ev.uid::text, ev.email, ''), COALESCE(max(ev.dname), max(u.display_name), ''), count(*)
FROM ev LEFT JOIN users u ON u.id = ev.uid AND u.panel_id = ev.panel_id
WHERE ev.email IS DISTINCT FROM '' AND ev.src <> 'awg' GROUP BY 1, 2, 3
UNION ALL
SELECT 'path', ev.panel_id, ev.inb, '', count(*) FROM ev WHERE ev.inb IS NOT NULL AND ev.inb NOT LIKE 'xray.system.%' GROUP BY 2, 3
UNION ALL
SELECT 'awg', ev.panel_id, substr(ev.ukey, 5), COALESCE(max(ev.dname), ''), COALESCE(sum(ev.w), 0)::bigint FROM ev WHERE ev.src = 'awg' GROUP BY 2, 3
UNION ALL
SELECT 'awg', ev.panel_id, '*', '', COALESCE(sum(ev.w), 0)::bigint FROM ev WHERE ev.src = 'awg' GROUP BY 2
ORDER BY 5 DESC LIMIT 300`, q.args7()...)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := []SubjectRow{}
	for rs.Next() {
		var r SubjectRow
		var pid uuid.UUID
		if err := rs.Scan(&r.Kind, &pid, &r.ID, &r.Name, &r.Connections); err != nil {
			return nil, err
		}
		r.PanelID = pid.String()
		if r.ID == "" {
			continue
		}
		out = append(out, r)
	}
	return out, rs.Err()
}

// Activity is the traffic of the range laid out by weekday and hour, in the viewer's time zone.
type Activity struct {
	Grid [7][24]int // [weekday 0=Monday][hour]
	Max  int
	Sum  int
}

// ActivityGrid counts connections by weekday and local hour. offsetMin is how far the viewer's
// clock is ahead of UTC.
func (s *Store) ActivityGrid(ctx context.Context, q AnalyticsQuery, offsetMin int) (Activity, error) {
	var a Activity
	rs, err := s.pool.Query(ctx, `WITH `+eventsCTE+`
SELECT (extract(isodow FROM ev.ts + make_interval(mins => $8)) - 1)::int, extract(hour FROM ev.ts + make_interval(mins => $8))::int, COALESCE(sum(ev.w), 0)::bigint
FROM ev GROUP BY 1, 2`, append(q.args7(), offsetMin)...)
	if err != nil {
		return a, err
	}
	defer rs.Close()
	for rs.Next() {
		var d, h, n int
		if err := rs.Scan(&d, &h, &n); err != nil {
			return a, err
		}
		if d >= 0 && d < 7 && h >= 0 && h < 24 {
			a.Grid[d][h] = n
			a.Sum += n
			a.Max = max(a.Max, n)
		}
	}
	return a, rs.Err()
}

type CountryRow struct {
	Code        string // two letters; "" = the line had no IP, "ZZ" = private or unknown address
	Connections int
	Users       int
	Sites       int
	Bytes       int64
	RouterConns int
}

// Countries groups connections by the country of the destination address. Only lines that carry
// an IP can be placed: domain-only lines (most clients' node logs) are counted apart, not guessed.
func (s *Store) Countries(ctx context.Context, q AnalyticsQuery) ([]CountryRow, error) {
	rs, err := s.pool.Query(ctx, `WITH `+eventsCTE+`
SELECT COALESCE(ev.country, ''), COALESCE(sum(ev.w), 0)::bigint, count(DISTINCT ev.ukey), count(DISTINCT ev.site) FILTER (WHERE ev.site IS NOT NULL),
       COALESCE(sum(ev.bytes), 0), count(*) FILTER (WHERE ev.rtr)
FROM ev GROUP BY 1 ORDER BY 2 DESC, 1`, q.args7()...)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := []CountryRow{}
	for rs.Next() {
		var r CountryRow
		if err := rs.Scan(&r.Code, &r.Connections, &r.Users, &r.Sites, &r.Bytes, &r.RouterConns); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rs.Err()
}

type IPRow struct {
	IP          string
	Connections int
	Users       int
	Bytes       int64
	RouterConns int
	Last        time.Time
}

// MaxNetworkIPs bounds how many distinct addresses one request reads.
const MaxNetworkIPs = 100000

// IPOnlyDestinations lists the addresses of connections that carry no domain at all (the rows the
// log gives as a bare IP), busiest first. The caller groups them by network owner.
func (s *Store) IPOnlyDestinations(ctx context.Context, q AnalyticsQuery) ([]IPRow, error) {
	rs, err := s.pool.Query(ctx, `WITH `+eventsCTE+`
SELECT ev.ip, COALESCE(sum(ev.w), 0)::bigint, count(DISTINCT ev.ukey), COALESCE(sum(ev.bytes), 0), count(*) FILTER (WHERE ev.rtr), max(ev.ts)
FROM ev WHERE ev.host IS NULL AND ev.ip IS NOT NULL GROUP BY ev.ip ORDER BY sum(ev.w) DESC LIMIT `+itoa(MaxNetworkIPs), q.args7()...)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := []IPRow{}
	for rs.Next() {
		var r IPRow
		if err := rs.Scan(&r.IP, &r.Connections, &r.Users, &r.Bytes, &r.RouterConns, &r.Last); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rs.Err()
}
