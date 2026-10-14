package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Sources of traffic_samples. A delta is only ever computed between samples of one source, so
// counters with different meanings are never subtracted from each other.
const (
	SrcNodeUsed     = "panel_api:node_used"
	SrcUserLifetime = "panel_api:user_lifetime"
	SrcUserUsed     = "panel_api:user_used"
)

// Counter is one cumulative counter read from the panel. Direction is not known: the panel's
// list endpoints give a total, so samples are stored as direction "total".
type Counter struct {
	RemoteUUID string
	Bytes      int64
	Source     string
}

// RecordNodeCounters and RecordUserCounters store one snapshot per entity at observedAt.
// Entities are matched by the panel's own identifier; one that is not known yet is skipped.
// Repeating the same snapshot is harmless.
func (s *Store) RecordNodeCounters(ctx context.Context, panelID string, observedAt time.Time, cs []Counter) (int, error) {
	return s.recordCounters(ctx, panelID, observedAt, cs, `nodes`, `node_id`)
}

func (s *Store) RecordUserCounters(ctx context.Context, panelID string, observedAt time.Time, cs []Counter) (int, error) {
	return s.recordCounters(ctx, panelID, observedAt, cs, `users`, `user_id`)
}

func (s *Store) recordCounters(ctx context.Context, panelID string, observedAt time.Time, cs []Counter, table, col string) (int, error) {
	if len(cs) == 0 {
		return 0, nil
	}
	pid, err := ParseID(panelID)
	if err != nil {
		return 0, err
	}
	ids := make([]string, len(cs))
	bytes := make([]int64, len(cs))
	srcs := make([]string, len(cs))
	for i, c := range cs {
		ids[i], bytes[i], srcs[i] = c.RemoteUUID, c.Bytes, c.Source
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO traffic_samples (panel_id, `+col+`, direction, bytes_total, observed_at, source)
		SELECT $1, t.id, 'total', v.b, $2, v.src
		FROM unnest($3::text[], $4::bigint[], $5::text[]) AS v(rid, b, src)
		JOIN `+table+` t ON t.panel_id = $1 AND t.remote_uuid = v.rid AND t.removed_at IS NULL
		ON CONFLICT DO NOTHING`, pid, observedAt, ids, bytes, srcs)
	return int(tag.RowsAffected()), err
}

// PurgeExpiredTraffic deletes samples past each panel's retention window.
func (s *Store) PurgeExpiredTraffic(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM traffic_samples t USING panels p
		WHERE t.panel_id = p.id AND t.observed_at < $1::timestamptz - make_interval(days => p.retention_days)`, now)
	return tag.RowsAffected(), err
}

// deltas turns cumulative samples into traffic since the previous sample of the same entity and
// source. A counter that went down was reset by the panel: the traffic since the reset is the
// new value, so the delta is that value and never negative. A first sample has no predecessor
// and counts as zero, because what happened before it is unknown. Predecessors are looked up in
// the day before the range so the first in-range sample is not lost.
const deltasCTE = `
s AS (
  SELECT panel_id, node_id, user_id, source, observed_at, bytes_total,
         lag(bytes_total) OVER w AS prev
  FROM traffic_samples
  WHERE panel_id = ANY($1::uuid[]) AND cardinality($2::uuid[]) >= 0 AND observed_at >= $3::timestamptz - interval '1 day' AND observed_at < $4
  WINDOW w AS (PARTITION BY panel_id, node_id, user_id, source ORDER BY observed_at)
), d AS (
  SELECT panel_id, node_id, user_id, source, observed_at, bytes_total,
         CASE WHEN prev IS NULL THEN 0 WHEN bytes_total >= prev THEN bytes_total - prev ELSE bytes_total END AS delta,
         (prev IS NOT NULL AND bytes_total < prev) AS reset
  FROM s WHERE observed_at >= $3
)`

type TrafficNode struct {
	NodeID  string
	Name    string
	Bytes   int64
	Resets  int
	Current int64 // the node's counter at its latest sample
	Last    time.Time
	Samples int
}

// TrafficByNode sums per-node deltas of the node counters, for every node of the panels
// (nodes with no samples are listed with zero and no timestamp).
func (s *Store) TrafficByNode(ctx context.Context, q AnalyticsQuery) ([]TrafficNode, error) {
	rs, err := s.pool.Query(ctx, `WITH `+deltasCTE+`
SELECT n.id, n.name, COALESCE(sum(d.delta), 0), count(*) FILTER (WHERE d.reset), COALESCE((array_agg(d.bytes_total ORDER BY d.observed_at DESC))[1], 0),
       max(d.observed_at), count(d.observed_at)
FROM nodes n LEFT JOIN d ON d.node_id = n.id AND d.source = '`+SrcNodeUsed+`'
WHERE n.panel_id = ANY($1::uuid[]) AND n.removed_at IS NULL AND (cardinality($2::uuid[]) = 0 OR n.id = ANY($2::uuid[]))
GROUP BY n.id, n.name ORDER BY COALESCE(sum(d.delta), 0) DESC, lower(n.name)`, q.args()...)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := []TrafficNode{}
	for rs.Next() {
		var r TrafficNode
		var id uuid.UUID
		var last *time.Time
		if err := rs.Scan(&id, &r.Name, &r.Bytes, &r.Resets, &r.Current, &last, &r.Samples); err != nil {
			return nil, err
		}
		r.NodeID = id.String()
		if last != nil {
			r.Last = *last
		}
		out = append(out, r)
	}
	return out, rs.Err()
}

type TrafficUser struct {
	PanelID  string
	RemoteID string
	Name     string
	Bytes    int64
	Resets   int
	Source   string
}

// TrafficByUser sums per-user deltas. The lifetime counter is used when the panel sends it, the
// period counter otherwise; both are never added together for one user.
func (s *Store) TrafficByUser(ctx context.Context, q AnalyticsQuery, limit int) ([]TrafficUser, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rs, err := s.pool.Query(ctx, `WITH `+deltasCTE+`, pick AS (
  SELECT DISTINCT ON (d.panel_id, d.user_id) d.panel_id, d.user_id, d.source
  FROM d WHERE d.user_id IS NOT NULL
  ORDER BY d.panel_id, d.user_id, (d.source = '`+SrcUserLifetime+`') DESC
)
SELECT u.panel_id, u.remote_uuid, COALESCE(u.display_name, ''), COALESCE(sum(d.delta), 0), count(*) FILTER (WHERE d.reset), p.source
FROM pick p JOIN d ON d.panel_id = p.panel_id AND d.user_id = p.user_id AND d.source = p.source
JOIN users u ON u.id = p.user_id AND u.panel_id = p.panel_id
GROUP BY u.panel_id, u.remote_uuid, u.display_name, p.source
ORDER BY sum(d.delta) DESC, u.remote_uuid LIMIT $5`, append(q.args(), limit)...)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := []TrafficUser{}
	for rs.Next() {
		var r TrafficUser
		var pid uuid.UUID
		if err := rs.Scan(&pid, &r.RemoteID, &r.Name, &r.Bytes, &r.Resets, &r.Source); err != nil {
			return nil, err
		}
		r.PanelID = pid.String()
		out = append(out, r)
	}
	return out, rs.Err()
}

type TrafficPoint struct {
	TS    time.Time
	Bytes int64
}

type TrafficSummary struct {
	NodeBytes   int64 // sum of node deltas in the range
	UserBytes   int64 // sum of the picked per-user deltas (all users, not only the top)
	Resets      int
	Samples     int
	First, Last *time.Time
	Timeline    []TrafficPoint
}

// TrafficSummaryFor returns the totals and a timeline of node-counter deltas by bucket.
func (s *Store) TrafficSummaryFor(ctx context.Context, q AnalyticsQuery) (TrafficSummary, error) {
	var sum TrafficSummary
	err := s.pool.QueryRow(ctx, `WITH `+deltasCTE+`
SELECT COALESCE(sum(delta) FILTER (WHERE source = '`+SrcNodeUsed+`' AND node_id IS NOT NULL AND (cardinality($2::uuid[]) = 0 OR node_id = ANY($2::uuid[]))), 0),
       count(*) FILTER (WHERE reset AND source = '`+SrcNodeUsed+`'), count(*), min(observed_at), max(observed_at)
FROM d`, q.args()...).Scan(&sum.NodeBytes, &sum.Resets, &sum.Samples, &sum.First, &sum.Last)
	if err != nil {
		return sum, err
	}
	err = s.pool.QueryRow(ctx, `WITH `+deltasCTE+`, pick AS (
  SELECT DISTINCT ON (d.panel_id, d.user_id) d.panel_id, d.user_id, d.source
  FROM d WHERE d.user_id IS NOT NULL
  ORDER BY d.panel_id, d.user_id, (d.source = '`+SrcUserLifetime+`') DESC
)
SELECT COALESCE(sum(d.delta), 0) FROM pick p JOIN d ON d.panel_id = p.panel_id AND d.user_id = p.user_id AND d.source = p.source`, q.args()...).Scan(&sum.UserBytes)
	if err != nil {
		return sum, err
	}
	gran := q.Granularity
	if gran <= 0 {
		gran = time.Hour
	}
	rs, err := s.pool.Query(ctx, `WITH `+deltasCTE+`
SELECT to_timestamp(floor(extract(epoch FROM observed_at) / $5) * $5) AS b, sum(delta)
FROM d WHERE source = '`+SrcNodeUsed+`' AND node_id IS NOT NULL AND (cardinality($2::uuid[]) = 0 OR node_id = ANY($2::uuid[]))
GROUP BY 1 ORDER BY 1`, append(q.args(), gran.Seconds())...)
	if err != nil {
		return sum, err
	}
	defer rs.Close()
	sum.Timeline = []TrafficPoint{}
	for rs.Next() {
		var p TrafficPoint
		if err := rs.Scan(&p.TS, &p.Bytes); err != nil {
			return sum, err
		}
		sum.Timeline = append(sum.Timeline, p)
	}
	return sum, rs.Err()
}
