package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// TimelineEntry is one line of the feed: a visit (the connections of one person to one site with no gap
// longer than SessionGap), or, in the raw view, one connection.
type TimelineEntry struct {
	Site        string
	Service     string
	Host        string // the host seen first (a visit) or the host of the connection (raw)
	Hosts       int    // different hosts inside the entry
	Start, End  time.Time
	Connections int
	Bytes       int64
	Src         string // node | router | awg
	PanelID     string
	NodeName    string
	UserID      string
	Email       string
	DisplayName string
	Device      string // the LAN device's IP
	DeviceName  string
	AWG         string // 'awg:<tunnel ip>'
	AWGName     string
}

type TimelineTotals struct {
	Visits      int
	Connections int
	Sites       int
	Last        *time.Time
}

// Timeline lists, newest first, what was opened at the sites that match `search` (a part of the domain, of a
// host, or of the service name). Only domains are known: the logs hold no pages. before (zero for none) pages
// back in time by the start of the last entry already shown.
func (s *Store) Timeline(ctx context.Context, q AnalyticsQuery, search string, raw bool, src string, before time.Time, limit int) ([]TimelineEntry, bool, TimelineTotals, error) {
	var tot TimelineTotals
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var bf any
	if !before.IsZero() {
		bf = before
	}
	base := append(q.args7(), escapedLike(search), src)
	// $8 = the pattern, $9 = the source (or empty), $10 = before, $11 = limit.
	pre := `WITH ` + eventsCTE + `, m AS (
  SELECT DISTINCT ev.site FROM ev WHERE ev.site IS NOT NULL AND ev.site !~ '^[0-9]+(\.[0-9]+){3}$' AND position(':' IN ev.site) = 0 AND (ev.site ILIKE $8 OR ev.host ILIKE $8)
  UNION
  SELECT s.name FROM (SELECT DISTINCT ev.site AS name FROM ev WHERE ev.site IS NOT NULL AND ev.site !~ '^[0-9]+(\.[0-9]+){3}$' AND position(':' IN ev.site) = 0) s ` + ruleMatch("s.name") + ` WHERE r.service ILIKE $8
), c AS (
  SELECT ev.*, lag(ev.ts) OVER (PARTITION BY ev.ukey, ev.site ORDER BY ev.ts) AS prev FROM ev WHERE ev.site IN (SELECT site FROM m) AND ($9::text = '' OR ev.src = $9)
)`
	if err := s.pool.QueryRow(ctx, pre+`
SELECT count(*) FILTER (WHERE `+isVisit+`)::int, COALESCE(sum(c.w), 0)::int, count(DISTINCT c.site)::int, max(c.ts) FROM c`, base...).Scan(&tot.Visits, &tot.Connections, &tot.Sites, &tot.Last); err != nil {
		return nil, false, tot, err
	}
	if tot.Connections == 0 {
		return []TimelineEntry{}, false, tot, nil
	}

	var grouped string
	if raw {
		grouped = `g AS (
  SELECT c.site, COALESCE(c.host, c.ip) AS host, 1 AS hosts, c.ts AS st, c.ts AS en, c.w::bigint AS conns, COALESCE(c.bytes, 0) AS bytes, c.src, c.panel_id, c.node_id AS nid, c.uid, c.email, c.dev, c.dname, c.ukey
  FROM c
)`
	} else {
		grouped = `v AS (
  SELECT c.*, sum(CASE WHEN ` + isVisit + ` THEN 1 ELSE 0 END) OVER (PARTITION BY c.ukey, c.site ORDER BY c.ts) AS vn FROM c
), g AS (
  SELECT v.site, (array_agg(COALESCE(v.host, v.ip) ORDER BY v.ts))[1] AS host, count(DISTINCT COALESCE(v.host, v.ip))::int AS hosts, min(v.ts) AS st, max(v.ts) AS en,
         sum(v.w)::bigint AS conns, COALESCE(sum(v.bytes), 0)::bigint AS bytes, min(v.src) AS src, v.panel_id, (array_agg(v.node_id))[1] AS nid, (array_agg(v.uid))[1] AS uid,
         max(v.email) AS email, max(v.dev) AS dev, max(v.dname) AS dname, v.ukey
  FROM v GROUP BY v.site, v.ukey, v.vn, v.panel_id
)`
	}
	rows, err := s.pool.Query(ctx, pre+`, `+grouped+`
SELECT g.site, COALESCE(r.service, ''), g.host, g.hosts, g.st, g.en, g.conns, g.bytes, g.src, g.panel_id, COALESCE(n.name, ''), g.uid, COALESCE(g.email, ''), COALESCE(u.display_name, ''),
       COALESCE(g.dev, ''), COALESCE(g.dname, ''), CASE WHEN g.src = 'awg' THEN g.ukey ELSE '' END
FROM g LEFT JOIN users u ON u.id = g.uid AND u.panel_id = g.panel_id LEFT JOIN nodes n ON n.id = g.nid `+ruleMatch("g.site")+`
WHERE $10::timestamptz IS NULL OR g.st < $10
ORDER BY g.st DESC, g.site, g.ukey LIMIT $11`, append(base, bf, limit+1)...)
	if err != nil {
		return nil, false, tot, err
	}
	defer rows.Close()
	out := []TimelineEntry{}
	for rows.Next() {
		var e TimelineEntry
		var pid uuid.UUID
		var uid *uuid.UUID
		if err := rows.Scan(&e.Site, &e.Service, &e.Host, &e.Hosts, &e.Start, &e.End, &e.Connections, &e.Bytes, &e.Src, &pid, &e.NodeName, &uid, &e.Email, &e.DisplayName, &e.Device, &e.DeviceName, &e.AWG); err != nil {
			return nil, false, tot, err
		}
		e.PanelID = pid.String()
		if uid != nil {
			e.UserID = uid.String()
		}
		if e.AWG != "" {
			e.AWGName = e.DeviceName
			e.Device, e.DeviceName = "", ""
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, false, tot, err
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, tot, nil
}
