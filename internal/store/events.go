package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// EventsQuery selects connection events. Panel ids must already be authorised by the caller;
// every statement below is additionally restricted to them.
type EventsQuery struct {
	PanelIDs    []string
	NodeIDs     []string // empty = every node of the panels
	From, To    time.Time
	Granularity time.Duration
	Top         int
	Exact       bool // count from the events even where half-hour sums exist
}

type Bucket struct {
	TS       time.Time
	TCP, UDP int
}

type CountRow struct {
	Key      string
	Label    string
	PanelID  string
	UserID   string
	Internal bool
	Count    int
}

type RecentEvent struct {
	TS       time.Time
	PanelID  string
	NodeName string
	User     string
	Email    string
	Internal bool
	Protocol string
	Host     string
	IP       string
}

type NodeSeen struct {
	NodeID, NodeName, PanelID string
	HasAgent                  bool
	LastSeen                  *time.Time
}

type GapRow struct {
	NodeID, NodeName, PanelID string
	From, To                  time.Time
	Reason                    string
	Lines                     int64
}

type EventsOverview struct {
	Buckets         []Bucket
	TCP, UDP        int
	UniqueHosts     int
	UniqueIPs       int
	Hosts           []CountRow
	IPs             []CountRow
	Ports           []CountRow
	Users           []CountRow
	Recent          []RecentEvent
	Nodes           []NodeSeen
	NodesWithEvents int
	LastEventAt     *time.Time
	Gaps            []GapRow
}

func uuids(ids []string) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(ids))
	for _, s := range ids {
		if u, err := uuid.Parse(s); err == nil {
			out = append(out, u)
		}
	}
	return out
}

// NodesInScope lists the live nodes of the given panels (optionally narrowed) with their agent state.
func (s *Store) NodesInScope(ctx context.Context, panelIDs, nodeIDs []string) ([]NodeSeen, error) {
	rows, err := s.pool.Query(ctx, `SELECT n.id, n.name, n.panel_id, a.id IS NOT NULL, a.last_seen
		FROM nodes n LEFT JOIN agents a ON a.node_id=n.id AND a.panel_id=n.panel_id AND a.status <> 'revoked' AND a.kind = 'node'
		WHERE n.panel_id = ANY($1::uuid[]) AND n.removed_at IS NULL AND (cardinality($2::uuid[]) = 0 OR n.id = ANY($2::uuid[]))
		ORDER BY lower(n.name)`, uuids(panelIDs), uuids(nodeIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NodeSeen
	for rows.Next() {
		var n NodeSeen
		var id, pid uuid.UUID
		if err := rows.Scan(&id, &n.NodeName, &pid, &n.HasAgent, &n.LastSeen); err != nil {
			return nil, err
		}
		n.NodeID, n.PanelID = id.String(), pid.String()
		out = append(out, n)
	}
	return out, rows.Err()
}

const eventScope = `e.panel_id = ANY($1::uuid[]) AND (cardinality($2::uuid[]) = 0 OR e.node_id = ANY($2::uuid[])) AND e.ts >= $3 AND e.ts < $4`

// EventsOverview aggregates the events in the window. Counts are accepted log lines
// (connection_count); they say nothing about bytes.
//
// A window of several hours or more is answered from the half-hour sums (event_rollup) when they reach back far enough:
// the page then reads a few thousand rows instead of every event of the day seven times over. Such a window starts on a
// half-hour, so it may hold up to half an hour more than was asked. Short windows, and long ones the sums do not cover
// yet, are counted from the events as before.
func (s *Store) EventsOverview(ctx context.Context, q EventsQuery) (EventsOverview, error) {
	var ov EventsOverview
	if q.Top <= 0 {
		q.Top = 5
	}
	if q.Granularity < time.Minute {
		q.Granularity = time.Minute
	}
	rolled := false
	if !q.Exact && q.To.Sub(q.From) >= rollupMinSpan && q.Granularity >= RollupStep {
		var err error
		if rolled, err = s.rollupCovers(ctx, q.From, q.To); err != nil {
			return ov, err
		}
	}
	var err error
	if rolled {
		err = s.overviewRolled(ctx, q, &ov)
	} else {
		err = s.overviewRaw(ctx, q, &ov)
	}
	if err != nil {
		return ov, err
	}
	p, n := uuids(q.PanelIDs), uuids(q.NodeIDs)

	// recent: the last hour first, which is a handful of rows; the whole window only when that hour was quiet
	from := q.From
	if hour := q.To.Add(-time.Hour); hour.After(from) {
		from = hour
	}
	if ov.Recent, err = s.recentEvents(ctx, p, n, from, q.To); err != nil {
		return ov, err
	}
	if len(ov.Recent) < 10 && from.After(q.From) {
		if ov.Recent, err = s.recentEvents(ctx, p, n, q.From, q.To); err != nil {
			return ov, err
		}
	}
	if len(ov.Recent) > 0 {
		t := ov.Recent[0].TS
		ov.LastEventAt = &t
	}

	// reported gaps in the window
	gs, err := s.pool.Query(ctx, `SELECT g.node_id, nd.name, g.panel_id, COALESCE(g.from_ts, g.reported_at), COALESCE(g.to_ts, g.reported_at), g.reason, COALESCE(g.lines,0)
		FROM agent_gaps g JOIN nodes nd ON nd.id=g.node_id AND nd.panel_id=g.panel_id
		WHERE g.panel_id = ANY($1::uuid[]) AND (cardinality($2::uuid[]) = 0 OR g.node_id = ANY($2::uuid[]))
		  AND COALESCE(g.to_ts, g.reported_at) >= $3 AND COALESCE(g.from_ts, g.reported_at) < $4 ORDER BY 4 DESC LIMIT 20`, p, n, q.From, q.To)
	if err != nil {
		return ov, err
	}
	defer gs.Close()
	for gs.Next() {
		var g GapRow
		var nid, pid uuid.UUID
		if err := gs.Scan(&nid, &g.NodeName, &pid, &g.From, &g.To, &g.Reason, &g.Lines); err != nil {
			return ov, err
		}
		g.NodeID, g.PanelID = nid.String(), pid.String()
		ov.Gaps = append(ov.Gaps, g)
	}
	return ov, gs.Err()
}

func (s *Store) recentEvents(ctx context.Context, p, n []uuid.UUID, from, to time.Time) ([]RecentEvent, error) {
	rec, err := s.pool.Query(ctx, `SELECT e.ts, e.panel_id, nd.name, COALESCE(u.display_name,''), COALESCE(e.xray_email,''), e.internal, e.protocol,
			COALESCE(e.destination_host,''), COALESCE(host(e.destination_ip),'')
		FROM connection_events e JOIN nodes nd ON nd.id=e.node_id AND nd.panel_id=e.panel_id
		LEFT JOIN users u ON u.id=e.user_id AND u.panel_id=e.panel_id
		WHERE `+eventScope+` ORDER BY e.ts DESC, e.event_id LIMIT 10`, p, n, from, to)
	if err != nil {
		return nil, err
	}
	defer rec.Close()
	var out []RecentEvent
	for rec.Next() {
		var r RecentEvent
		var pid uuid.UUID
		if err := rec.Scan(&r.TS, &pid, &r.NodeName, &r.User, &r.Email, &r.Internal, &r.Protocol, &r.Host, &r.IP); err != nil {
			return nil, err
		}
		r.PanelID = pid.String()
		out = append(out, r)
	}
	return out, rec.Err()
}

// overviewRaw counts the window from the events themselves.
func (s *Store) overviewRaw(ctx context.Context, q EventsQuery, ov *EventsOverview) error {
	p, n := uuids(q.PanelIDs), uuids(q.NodeIDs)
	origin := q.From.Truncate(q.Granularity)

	rows, err := s.pool.Query(ctx, `SELECT date_bin(make_interval(secs => $5), e.ts, $6::timestamptz) AS b,
			count(*) FILTER (WHERE e.protocol='tcp'), count(*) FILTER (WHERE e.protocol='udp')
		FROM connection_events e WHERE `+eventScope+` GROUP BY b ORDER BY b`, p, n, q.From, q.To, q.Granularity.Seconds(), origin)
	if err != nil {
		return err
	}
	if err := scanBuckets(rows, ov); err != nil {
		return err
	}

	if err := s.pool.QueryRow(ctx, `SELECT count(DISTINCT e.destination_host), count(DISTINCT e.destination_ip), count(DISTINCT e.node_id)
		FROM connection_events e WHERE `+eventScope, p, n, q.From, q.To).Scan(&ov.UniqueHosts, &ov.UniqueIPs, &ov.NodesWithEvents); err != nil {
		return err
	}

	top := func(expr, notNull string) ([]CountRow, error) {
		rs, err := s.pool.Query(ctx, `SELECT `+expr+`::text AS k, count(*) FROM connection_events e WHERE `+eventScope+` AND `+notNull+`
			GROUP BY k ORDER BY count(*) DESC, k LIMIT $5`, p, n, q.From, q.To, q.Top)
		if err != nil {
			return nil, err
		}
		return scanCountRows(rs)
	}
	if ov.Hosts, err = top(`e.destination_host`, `e.destination_host IS NOT NULL`); err != nil {
		return err
	}
	if ov.IPs, err = top(`host(e.destination_ip)`, `e.destination_ip IS NOT NULL`); err != nil {
		return err
	}
	if ov.Ports, err = top(`e.destination_port`, `TRUE`); err != nil {
		return err
	}

	// users: resolved through the panel's own user table, or kept as an unresolved raw id
	urs, err := s.pool.Query(ctx, `SELECT e.panel_id, e.user_id, COALESCE(e.xray_email,''), e.internal, COALESCE(u.display_name,''), count(*)
		FROM connection_events e LEFT JOIN users u ON u.id=e.user_id AND u.panel_id=e.panel_id
		WHERE `+eventScope+` GROUP BY e.panel_id, e.user_id, e.xray_email, e.internal, u.display_name ORDER BY count(*) DESC LIMIT 12`, p, n, q.From, q.To)
	if err != nil {
		return err
	}
	ov.Users, err = scanUserRows(urs)
	return err
}

func scanBuckets(rows pgx.Rows, ov *EventsOverview) error {
	defer rows.Close()
	for rows.Next() {
		var b Bucket
		if err := rows.Scan(&b.TS, &b.TCP, &b.UDP); err != nil {
			return err
		}
		ov.Buckets = append(ov.Buckets, b)
		ov.TCP += b.TCP
		ov.UDP += b.UDP
	}
	return rows.Err()
}

func scanCountRows(rs pgx.Rows) ([]CountRow, error) {
	defer rs.Close()
	var out []CountRow
	for rs.Next() {
		var r CountRow
		if err := rs.Scan(&r.Key, &r.Count); err != nil {
			return nil, err
		}
		r.Label = r.Key
		out = append(out, r)
	}
	return out, rs.Err()
}

// scanUserRows reads (panel, user id or null, logged id, internal, display name, count).
func scanUserRows(rs pgx.Rows) ([]CountRow, error) {
	defer rs.Close()
	var out []CountRow
	for rs.Next() {
		var r CountRow
		var pid uuid.UUID
		var uid *uuid.UUID
		var email, name string
		if err := rs.Scan(&pid, &uid, &email, &r.Internal, &name, &r.Count); err != nil {
			return nil, err
		}
		r.PanelID = pid.String()
		switch {
		case r.Internal:
			r.Key, r.Label = r.PanelID+"|system", ""
		case uid != nil:
			r.UserID, r.Key, r.Label = uid.String(), uid.String(), name
		default: // the raw id is only a hint; the caller words it
			r.Key, r.Label = r.PanelID+"|raw|"+email, email
		}
		out = append(out, r)
	}
	return out, rs.Err()
}
