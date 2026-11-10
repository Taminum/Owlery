package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The overview page counts a day of connection events seven ways. On a server whose disk is slow and whose memory holds
// a fraction of the events that took seconds, or tens of seconds when the day was not in memory. event_rollup keeps the
// same counts ready, by half-hour: how many events of each protocol, to each host, address and port, and of each user,
// every node saw. A day is then a few thousand small rows.
//
// It is kept by RollupTick, once a minute:
//   - the last three hours are recounted every time, so the current half-hour is at most a minute behind and lines an
//     agent sends late are picked up;
//   - a batch that brings events older than that marks their half-hours (event_rollup_dirty), and those are recounted;
//   - the past is filled backwards, six hours a tick, until the oldest event is reached.
//
// The sums are a second copy of what the events say, never a source: any half-hour can be recounted from the events
// at any time, and a window they do not cover yet is counted from the events.

// RollupStep is the width of one sum.
const RollupStep = 30 * time.Minute

const (
	rollupMinSpan  = 6 * time.Hour  // shorter windows are counted from the events: they are small and in memory
	rollupLive     = 6              // half-hours recounted on every tick, the current one included
	rollupBackfill = 6 * time.Hour  // how much of the past one tick fills
	rollupCatchUp  = 12 * time.Hour // how much one tick recounts after the server was away
	rollupDirtyMax = 24             // late half-hours recounted per tick
)

// rollupAll is what filled_from becomes once the filling has reached the oldest event: from then on the sums hold
// everything there is, however far back a window starts (the events before it are gone, or never were).
var rollupAll = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// What a row counts. The user key is 's' for the node's own traffic, 'u:<user id>' for a known user and
// 'r:<id as logged>' for one the panel does not know.
const (
	rollProto = 1
	rollHost  = 2
	rollIP    = 3
	rollPort  = 4
	rollUser  = 5
)

const rollupFill = `INSERT INTO event_rollup (panel_id, node_id, bucket, kind, key, n)
	SELECT $1, x.node_id, x.b, x.kind, x.key, count(*) FROM (
		SELECT e.node_id, date_bin(interval '30 minutes', e.ts, TIMESTAMPTZ '2000-01-01 00:00:00+00') AS b, v.kind, v.key
		FROM connection_events e CROSS JOIN LATERAL (VALUES
			(1, e.protocol), (2, e.destination_host), (3, host(e.destination_ip)), (4, e.destination_port::text),
			(5, CASE WHEN e.internal THEN 's' WHEN e.user_id IS NOT NULL THEN 'u:' || e.user_id::text ELSE 'r:' || COALESCE(e.xray_email, '') END)
		) v(kind, key)
		WHERE e.panel_id = $1 AND e.ts >= $2 AND e.ts < $3 AND v.key IS NOT NULL
	) x GROUP BY x.node_id, x.b, x.kind, x.key`

// rollupRange recounts the half-hours of [from, to) from the events. Both ends must lie on a half-hour.
func (s *Store) rollupRange(ctx context.Context, from, to time.Time) error {
	if !to.After(from) {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM event_rollup WHERE bucket >= $1 AND bucket < $2`, from, to); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT id FROM panels`)
	if err != nil {
		return err
	}
	panels, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	for _, p := range panels { // one panel at a time: that is what the (panel, time) index serves
		if _, err := tx.Exec(ctx, rollupFill, p, from, to); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// RollupTick keeps the sums up to date and reports whether there is more of the past left to fill.
func (s *Store) RollupTick(ctx context.Context, now time.Time) (more bool, err error) {
	cur := now.UTC().Truncate(RollupStep)
	liveFrom := cur.Add(-(rollupLive - 1) * RollupStep)

	var filledFrom, freshTo time.Time
	err = s.pool.QueryRow(ctx, `SELECT filled_from, fresh_to FROM event_rollup_state`).Scan(&filledFrom, &freshTo)
	first := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !first {
		return false, err
	}

	// the recent past; after time away, everything since the last tick, a stretch at a time
	from, to := liveFrom, cur.Add(RollupStep)
	if !first && freshTo.Before(from) {
		from = freshTo.Add(-RollupStep)
		if to.Sub(from) > rollupCatchUp {
			to = from.Add(rollupCatchUp)
		}
	}
	if err := s.rollupRange(ctx, from, to); err != nil {
		return false, err
	}
	if first {
		filledFrom = liveFrom
		_, err = s.pool.Exec(ctx, `INSERT INTO event_rollup_state (filled_from, fresh_to) VALUES ($1, $2)`, filledFrom, to)
	} else {
		_, err = s.pool.Exec(ctx, `UPDATE event_rollup_state SET fresh_to = $1`, to)
	}
	if err != nil {
		return false, err
	}

	// half-hours that late lines landed in
	rows, err := s.pool.Query(ctx, `SELECT bucket FROM event_rollup_dirty ORDER BY bucket LIMIT $1`, rollupDirtyMax)
	if err != nil {
		return false, err
	}
	dirty, err := pgx.CollectRows(rows, pgx.RowTo[time.Time])
	if err != nil {
		return false, err
	}
	for _, b := range dirty {
		if !b.Before(filledFrom) { // an older one is counted when the filling reaches it
			if err := s.rollupRange(ctx, b, b.Add(RollupStep)); err != nil {
				return false, err
			}
		}
		if _, err := s.pool.Exec(ctx, `DELETE FROM event_rollup_dirty WHERE bucket = $1`, b); err != nil {
			return false, err
		}
	}

	// the past, backwards
	var oldest *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT min(m.ts) FROM panels p CROSS JOIN LATERAL (SELECT min(e.ts) AS ts FROM connection_events e WHERE e.panel_id = p.id) m`).Scan(&oldest); err != nil {
		return false, err
	}
	if !filledFrom.After(rollupAll) {
		return false, nil
	}
	done := func() (bool, error) {
		_, err := s.pool.Exec(ctx, `UPDATE event_rollup_state SET filled_from = $1`, rollupAll)
		return false, err
	}
	if oldest == nil {
		return done()
	}
	floor := oldest.UTC().Truncate(RollupStep)
	if !filledFrom.After(floor) {
		return done()
	}
	a := filledFrom.Add(-rollupBackfill)
	if a.Before(floor) {
		a = floor
	}
	if err := s.rollupRange(ctx, a, filledFrom); err != nil {
		return false, err
	}
	if !a.After(floor) {
		return done()
	}
	if _, err := s.pool.Exec(ctx, `UPDATE event_rollup_state SET filled_from = $1`, a); err != nil {
		return false, err
	}
	return true, nil
}

// rollupCovers says whether the sums hold everything from the half-hour `from` falls in up to `to`.
func (s *Store) rollupCovers(ctx context.Context, from, to time.Time) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT filled_from <= $1 AND fresh_to > $2 FROM event_rollup_state`, from.UTC().Truncate(RollupStep), to.UTC().Truncate(RollupStep)).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return ok, err
}

const rollScope = `r.panel_id = ANY($1::uuid[]) AND (cardinality($2::uuid[]) = 0 OR r.node_id = ANY($2::uuid[])) AND r.bucket >= $3 AND r.bucket < $4`

// overviewRolled answers the same questions as overviewRaw from the half-hour sums.
func (s *Store) overviewRolled(ctx context.Context, q EventsQuery, ov *EventsOverview) error {
	p, n := uuids(q.PanelIDs), uuids(q.NodeIDs)
	from := q.From.UTC().Truncate(RollupStep)
	origin := q.From.Truncate(q.Granularity)

	rows, err := s.pool.Query(ctx, `SELECT date_bin(make_interval(secs => $5), r.bucket, $6::timestamptz) AS b,
			COALESCE(sum(r.n) FILTER (WHERE r.key = 'tcp'), 0)::bigint, COALESCE(sum(r.n) FILTER (WHERE r.key = 'udp'), 0)::bigint
		FROM event_rollup r WHERE `+rollScope+` AND r.kind = 1 GROUP BY b ORDER BY b`, p, n, from, q.To, q.Granularity.Seconds(), origin)
	if err != nil {
		return err
	}
	if err := scanBuckets(rows, ov); err != nil {
		return err
	}

	if err := s.pool.QueryRow(ctx, `SELECT count(DISTINCT r.key) FILTER (WHERE r.kind = 2), count(DISTINCT r.key) FILTER (WHERE r.kind = 3), count(DISTINCT r.node_id) FILTER (WHERE r.kind = 1)
		FROM event_rollup r WHERE `+rollScope+` AND r.kind IN (1, 2, 3)`, p, n, from, q.To).Scan(&ov.UniqueHosts, &ov.UniqueIPs, &ov.NodesWithEvents); err != nil {
		return err
	}

	top := func(kind int) ([]CountRow, error) {
		rs, err := s.pool.Query(ctx, `SELECT r.key, sum(r.n)::bigint FROM event_rollup r WHERE `+rollScope+` AND r.kind = $5
			GROUP BY r.key ORDER BY sum(r.n) DESC, r.key LIMIT $6`, p, n, from, q.To, kind, q.Top)
		if err != nil {
			return nil, err
		}
		return scanCountRows(rs)
	}
	if ov.Hosts, err = top(rollHost); err != nil {
		return err
	}
	if ov.IPs, err = top(rollIP); err != nil {
		return err
	}
	if ov.Ports, err = top(rollPort); err != nil {
		return err
	}

	urs, err := s.pool.Query(ctx, `SELECT x.panel_id, CASE WHEN x.key LIKE 'u:%' THEN substr(x.key, 3)::uuid END, CASE WHEN x.key LIKE 'r:%' THEN substr(x.key, 3) ELSE '' END, x.key = 's', COALESCE(u.display_name, ''), x.c FROM (
			SELECT r.panel_id, r.key, sum(r.n)::bigint AS c FROM event_rollup r WHERE `+rollScope+` AND r.kind = 5 GROUP BY r.panel_id, r.key
		) x LEFT JOIN users u ON x.key LIKE 'u:%' AND u.id::text = substr(x.key, 3) AND u.panel_id = x.panel_id
		ORDER BY x.c DESC, x.key LIMIT 12`, p, n, from, q.To)
	if err != nil {
		return err
	}
	ov.Users, err = scanUserRows(urs)
	return err
}

// lateBuckets are the half-hours of the given times that lie before what every tick recounts.
func lateBuckets(ts []time.Time, now time.Time) []time.Time {
	edge := now.Truncate(RollupStep).Add(-(rollupLive - 2) * RollupStep) // one half-hour of margin
	seen := map[time.Time]bool{}
	var out []time.Time
	for _, t := range ts {
		if b := t.UTC().Truncate(RollupStep); b.Before(edge) && !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	return out
}
