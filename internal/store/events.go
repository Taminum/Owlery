package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// EventsQuery selects connection events. Panel ids must already be authorised by the caller;
// every statement below is additionally restricted to them.
type EventsQuery struct {
	PanelIDs    []string
	NodeIDs     []string // empty = every node of the panels
	From, To    time.Time
	Granularity time.Duration
	Top         int
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
func (s *Store) EventsOverview(ctx context.Context, q EventsQuery) (EventsOverview, error) {
	var ov EventsOverview
	p, n := uuids(q.PanelIDs), uuids(q.NodeIDs)
	top := q.Top
	if top <= 0 {
		top = 5
	}
	gran := q.Granularity
	if gran < time.Minute {
		gran = time.Minute
	}
	origin := q.From.Truncate(gran)

	// timeline
	rows, err := s.pool.Query(ctx, `SELECT date_bin(make_interval(secs => $5), e.ts, $6::timestamptz) AS b,
			count(*) FILTER (WHERE e.protocol='tcp'), count(*) FILTER (WHERE e.protocol='udp')
		FROM connection_events e WHERE `+eventScope+` GROUP BY b ORDER BY b`, p, n, q.From, q.To, gran.Seconds(), origin)
	if err != nil {
		return ov, err
	}
	for rows.Next() {
		var b Bucket
		if err := rows.Scan(&b.TS, &b.TCP, &b.UDP); err != nil {
			rows.Close()
			return ov, err
		}
		ov.Buckets = append(ov.Buckets, b)
		ov.TCP += b.TCP
		ov.UDP += b.UDP
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ov, err
	}

	var last *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT count(DISTINCT e.destination_host), count(DISTINCT e.destination_ip), count(DISTINCT e.node_id), max(e.ts)
		FROM connection_events e WHERE `+eventScope, p, n, q.From, q.To).Scan(&ov.UniqueHosts, &ov.UniqueIPs, &ov.NodesWithEvents, &last); err != nil {
		return ov, err
	}
	ov.LastEventAt = last

	top3 := func(expr, notNull string) ([]CountRow, error) {
		rs, err := s.pool.Query(ctx, `SELECT `+expr+`::text AS k, count(*) FROM connection_events e WHERE `+eventScope+` AND `+notNull+`
			GROUP BY k ORDER BY count(*) DESC, k LIMIT $5`, p, n, q.From, q.To, top)
		if err != nil {
			return nil, err
		}
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
	if ov.Hosts, err = top3(`e.destination_host`, `e.destination_host IS NOT NULL`); err != nil {
		return ov, err
	}
	if ov.IPs, err = top3(`host(e.destination_ip)`, `e.destination_ip IS NOT NULL`); err != nil {
		return ov, err
	}
	if ov.Ports, err = top3(`e.destination_port`, `TRUE`); err != nil {
		return ov, err
	}

	// users: resolved through the panel's own user table, or kept as an unresolved raw id
	urs, err := s.pool.Query(ctx, `SELECT e.panel_id, e.user_id, COALESCE(e.xray_email,''), e.internal, COALESCE(u.display_name,''), count(*)
		FROM connection_events e LEFT JOIN users u ON u.id=e.user_id AND u.panel_id=e.panel_id
		WHERE `+eventScope+` GROUP BY e.panel_id, e.user_id, e.xray_email, e.internal, u.display_name ORDER BY count(*) DESC LIMIT 12`, p, n, q.From, q.To)
	if err != nil {
		return ov, err
	}
	for urs.Next() {
		var r CountRow
		var pid uuid.UUID
		var uid *uuid.UUID
		var email, name string
		if err := urs.Scan(&pid, &uid, &email, &r.Internal, &name, &r.Count); err != nil {
			urs.Close()
			return ov, err
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
		ov.Users = append(ov.Users, r)
	}
	urs.Close()
	if err := urs.Err(); err != nil {
		return ov, err
	}

	// recent
	rec, err := s.pool.Query(ctx, `SELECT e.ts, e.panel_id, nd.name, COALESCE(u.display_name,''), COALESCE(e.xray_email,''), e.internal, e.protocol,
			COALESCE(e.destination_host,''), COALESCE(host(e.destination_ip),'')
		FROM connection_events e JOIN nodes nd ON nd.id=e.node_id AND nd.panel_id=e.panel_id
		LEFT JOIN users u ON u.id=e.user_id AND u.panel_id=e.panel_id
		WHERE `+eventScope+` ORDER BY e.ts DESC, e.event_id LIMIT 10`, p, n, q.From, q.To)
	if err != nil {
		return ov, err
	}
	for rec.Next() {
		var r RecentEvent
		var pid uuid.UUID
		if err := rec.Scan(&r.TS, &pid, &r.NodeName, &r.User, &r.Email, &r.Internal, &r.Protocol, &r.Host, &r.IP); err != nil {
			rec.Close()
			return ov, err
		}
		r.PanelID = pid.String()
		ov.Recent = append(ov.Recent, r)
	}
	rec.Close()
	if err := rec.Err(); err != nil {
		return ov, err
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
