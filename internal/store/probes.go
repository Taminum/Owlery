package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// MaxProbeTargets bounds how many targets a panel can have, so probing cannot be turned into a
// way to make the server dial arbitrarily many hosts.
const MaxProbeTargets = 20

// ErrLimit means a bounded collection is full.
var ErrLimit = errLimit{}

type errLimit struct{}

func (errLimit) Error() string { return "store: limit reached" }

type ProbeTarget struct {
	ID      string `json:"id"`
	PanelID string `json:"panel_id"`
	Name    string `json:"name"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Mode    string `json:"mode"` // tcp | tls
	SNI     string `json:"sni,omitempty"`
	Enabled bool   `json:"enabled"`
}

type ProbeResult struct {
	TS        time.Time
	OK        bool
	ConnectMS *int
	TLSMS     *int
	Error     string
}

func (s *Store) CreateProbeTarget(ctx context.Context, t ProbeTarget) (ProbeTarget, error) {
	pid, err := ParseID(t.PanelID)
	if err != nil {
		return ProbeTarget{}, ErrNotFound
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM probe_targets WHERE panel_id=$1`, pid).Scan(&n); err != nil {
		return ProbeTarget{}, err
	}
	if n >= MaxProbeTargets {
		return ProbeTarget{}, ErrLimit
	}
	var id uuid.UUID
	err = s.pool.QueryRow(ctx, `INSERT INTO probe_targets (panel_id, name, host, port, mode, sni) VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')) RETURNING id`,
		pid, t.Name, t.Host, t.Port, t.Mode, t.SNI).Scan(&id)
	if IsUniqueViolation(err) {
		return ProbeTarget{}, ErrConflict
	}
	if err != nil {
		return ProbeTarget{}, err
	}
	t.ID, t.Enabled = id.String(), true
	return t, nil
}

func (s *Store) ProbeTarget(ctx context.Context, id string) (ProbeTarget, error) {
	u, err := ParseID(id)
	if err != nil {
		return ProbeTarget{}, ErrNotFound
	}
	var t ProbeTarget
	var pid uuid.UUID
	err = s.pool.QueryRow(ctx, `SELECT id, panel_id, name, host, port, mode, COALESCE(sni,''), enabled FROM probe_targets WHERE id=$1`, u).
		Scan(&u, &pid, &t.Name, &t.Host, &t.Port, &t.Mode, &t.SNI, &t.Enabled)
	if err != nil {
		return ProbeTarget{}, ErrNotFound
	}
	t.ID, t.PanelID = u.String(), pid.String()
	return t, nil
}

func (s *Store) DeleteProbeTarget(ctx context.Context, id string) error {
	u, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM probe_targets WHERE id=$1`, u)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// AllProbeTargets returns every enabled target of non-demo panels, for the prober.
func (s *Store) AllProbeTargets(ctx context.Context) ([]ProbeTarget, error) {
	return s.probeTargets(ctx, nil)
}

// ProbeTargetsOf returns the targets of the given panels, enabled or not.
func (s *Store) ProbeTargetsOf(ctx context.Context, panelIDs []string) ([]ProbeTarget, error) {
	return s.probeTargets(ctx, panelIDs)
}

func (s *Store) probeTargets(ctx context.Context, panelIDs []string) ([]ProbeTarget, error) {
	var ids any
	if panelIDs != nil {
		ids = uuids(panelIDs)
	}
	rs, err := s.pool.Query(ctx, `SELECT t.id, t.panel_id, t.name, t.host, t.port, t.mode, COALESCE(t.sni,''), t.enabled
		FROM probe_targets t JOIN panels p ON p.id = t.panel_id
		WHERE NOT p.demo AND ($1::uuid[] IS NULL OR t.panel_id = ANY($1::uuid[])) AND ($1::uuid[] IS NOT NULL OR t.enabled)
		ORDER BY lower(t.name)`, ids)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := []ProbeTarget{}
	for rs.Next() {
		var t ProbeTarget
		var id, pid uuid.UUID
		if err := rs.Scan(&id, &pid, &t.Name, &t.Host, &t.Port, &t.Mode, &t.SNI, &t.Enabled); err != nil {
			return nil, err
		}
		t.ID, t.PanelID = id.String(), pid.String()
		out = append(out, t)
	}
	return out, rs.Err()
}

func (s *Store) RecordProbe(ctx context.Context, targetID string, r ProbeResult) error {
	u, err := ParseID(targetID)
	if err != nil {
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO probe_results (target_id, ts, ok, connect_ms, tls_ms, error) VALUES ($1,$2,$3,$4,$5,NULLIF($6,''))
		ON CONFLICT DO NOTHING`, u, r.TS, r.OK, r.ConnectMS, r.TLSMS, r.Error)
	return err
}

func (s *Store) PurgeProbeResults(ctx context.Context, olderThan time.Time) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM probe_results WHERE ts < $1`, olderThan)
	return err
}

type ProbeSummary struct {
	Last       *ProbeResult
	Samples1h  int
	Failed1h   int
	P50Connect *int // over the last hour, successes only
	P50TLS     *int
	Recent     []bool // newest first, up to 3: whether each of the last probes worked
}

// ProbeSummaries reads the latest results and the last hour for each target.
func (s *Store) ProbeSummaries(ctx context.Context, ids []string, now time.Time) (map[string]ProbeSummary, error) {
	out := map[string]ProbeSummary{}
	if len(ids) == 0 {
		return out, nil
	}
	rs, err := s.pool.Query(ctx, `SELECT target_id, count(*), count(*) FILTER (WHERE NOT ok),
			percentile_disc(0.5) WITHIN GROUP (ORDER BY connect_ms) FILTER (WHERE ok), percentile_disc(0.5) WITHIN GROUP (ORDER BY tls_ms) FILTER (WHERE ok AND tls_ms IS NOT NULL)
		FROM probe_results WHERE target_id = ANY($1::uuid[]) AND ts > $2 GROUP BY 1`, uuids(ids), now.Add(-time.Hour))
	if err != nil {
		return nil, err
	}
	for rs.Next() {
		var id uuid.UUID
		var sm ProbeSummary
		if err := rs.Scan(&id, &sm.Samples1h, &sm.Failed1h, &sm.P50Connect, &sm.P50TLS); err != nil {
			rs.Close()
			return nil, err
		}
		out[id.String()] = sm
	}
	rs.Close()
	ls, err := s.pool.Query(ctx, `SELECT target_id, ts, ok, connect_ms, tls_ms, COALESCE(error,'') FROM (
			SELECT *, row_number() OVER (PARTITION BY target_id ORDER BY ts DESC) AS rn FROM probe_results WHERE target_id = ANY($1::uuid[]) AND ts > $2) x
		WHERE rn <= 3 ORDER BY target_id, ts DESC`, uuids(ids), now.Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	defer ls.Close()
	for ls.Next() {
		var id uuid.UUID
		var r ProbeResult
		if err := ls.Scan(&id, &r.TS, &r.OK, &r.ConnectMS, &r.TLSMS, &r.Error); err != nil {
			return nil, err
		}
		sm := out[id.String()]
		if sm.Last == nil {
			rr := r
			sm.Last = &rr
		}
		sm.Recent = append(sm.Recent, r.OK)
		out[id.String()] = sm
	}
	return out, ls.Err()
}

type ProbePoint struct {
	TS      time.Time
	Ms      *int // median handshake (or connect) time of the successes in the bucket
	Samples int
	Failed  int
}

// ProbeSeries buckets one target's results for a chart.
func (s *Store) ProbeSeries(ctx context.Context, targetID string, from, to time.Time, bucket time.Duration) ([]ProbePoint, error) {
	u, err := ParseID(targetID)
	if err != nil {
		return nil, ErrNotFound
	}
	rs, err := s.pool.Query(ctx, `SELECT to_timestamp(floor(extract(epoch FROM ts) / $4) * $4) AS b, count(*), count(*) FILTER (WHERE NOT ok),
			percentile_disc(0.5) WITHIN GROUP (ORDER BY COALESCE(tls_ms, connect_ms)) FILTER (WHERE ok)
		FROM probe_results WHERE target_id=$1 AND ts >= $2 AND ts < $3 GROUP BY 1 ORDER BY 1`, u, from, to, bucket.Seconds())
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := []ProbePoint{}
	for rs.Next() {
		var p ProbePoint
		if err := rs.Scan(&p.TS, &p.Samples, &p.Failed, &p.Ms); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rs.Err()
}

// ProbeState is what the alert evaluator needs about one target.
type ProbeState struct {
	TargetID string
	PanelID  string
	Name     string
	Recent   []bool // newest first, up to the last three results
	LastErr  string
}

func (s *Store) ProbeStates(ctx context.Context, now time.Time) ([]ProbeState, error) {
	targets, err := s.AllProbeTargets(ctx)
	if err != nil || len(targets) == 0 {
		return nil, err
	}
	ids := make([]string, len(targets))
	for i, t := range targets {
		ids[i] = t.ID
	}
	sums, err := s.ProbeSummaries(ctx, ids, now)
	if err != nil {
		return nil, err
	}
	out := make([]ProbeState, 0, len(targets))
	for _, t := range targets {
		sm := sums[t.ID]
		ps := ProbeState{TargetID: t.ID, PanelID: t.PanelID, Name: t.Name, Recent: sm.Recent}
		if sm.Last != nil {
			ps.LastErr = sm.Last.Error
		}
		out = append(out, ps)
	}
	return out, nil
}
