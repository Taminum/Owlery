package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Taminum/Owlery/internal/dnsmap"
)

const (
	MaxDNSMaps       = 20
	MaxDNSExtraNames = 40
	// DNSRetention is how long DNS changes and run records are kept. It is separate from the Security retention.
	DNSRetention = 180 * 24 * time.Hour
	// VolatileChanges is how many changes of one record set in a week make it "volatile": CDN, round-robin or propagation.
	VolatileChanges = 3
)

type DNSMap struct {
	ID           string     `json:"id"`
	Domain       string     `json:"domain"`
	Display      string     `json:"display"`
	Enabled      bool       `json:"enabled"`
	IntervalH    int        `json:"interval_hours"`
	ExtraNames   []string   `json:"extra_names"`
	UseCT        bool       `json:"use_ct"`
	CreatedAt    time.Time  `json:"created_at"`
	LastRunAt    *time.Time `json:"last_run_at"`
	NextRunAt    *time.Time `json:"next_run_at"`
	LastStatus   *string    `json:"last_status"`
	BaselineDone bool       `json:"baseline_done"`
}

const dnsMapCols = `id, domain, display, enabled, interval_hours, extra_names, use_ct, created_at, last_run_at, next_run_at, last_status, baseline_done`

func scanDNSMap(r pgx.Row) (DNSMap, error) {
	var m DNSMap
	var id uuid.UUID
	err := r.Scan(&id, &m.Domain, &m.Display, &m.Enabled, &m.IntervalH, &m.ExtraNames, &m.UseCT, &m.CreatedAt, &m.LastRunAt, &m.NextRunAt, &m.LastStatus, &m.BaselineDone)
	if errors.Is(err, pgx.ErrNoRows) {
		return m, ErrNotFound
	}
	m.ID = id.String()
	if m.ExtraNames == nil {
		m.ExtraNames = []string{}
	}
	return m, err
}

// CreateDNSMap records a study of one domain. The owner has confirmed its scope; the first run is due at once.
func (s *Store) CreateDNSMap(ctx context.Context, createdBy, domain, display string, extra []string, useCT bool, intervalH int, now time.Time) (DNSMap, error) {
	if len(extra) > MaxDNSExtraNames {
		return DNSMap{}, ErrLimit
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM dns_maps WHERE archived_at IS NULL`).Scan(&n); err != nil {
		return DNSMap{}, err
	}
	if n >= MaxDNSMaps {
		return DNSMap{}, ErrLimit
	}
	var by *uuid.UUID
	if u, err := uuid.Parse(createdBy); err == nil {
		by = &u
	}
	if extra == nil {
		extra = []string{}
	}
	m, err := scanDNSMap(s.pool.QueryRow(ctx, `INSERT INTO dns_maps (domain, display, created_by, scope_confirmed_at, interval_hours, extra_names, use_ct)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING `+dnsMapCols, domain, display, by, now, intervalH, extra, useCT))
	if IsUniqueViolation(err) {
		return DNSMap{}, ErrConflict
	}
	return m, err
}

func (s *Store) ListDNSMaps(ctx context.Context) ([]DNSMap, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+dnsMapCols+` FROM dns_maps WHERE archived_at IS NULL ORDER BY lower(domain)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DNSMap{}
	for rows.Next() {
		m, err := scanDNSMap(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) GetDNSMap(ctx context.Context, id string) (DNSMap, error) {
	u, err := ParseID(id)
	if err != nil {
		return DNSMap{}, ErrNotFound
	}
	return scanDNSMap(s.pool.QueryRow(ctx, `SELECT `+dnsMapCols+` FROM dns_maps WHERE id=$1 AND archived_at IS NULL`, u))
}

type DNSMapPatch struct {
	Enabled    *bool
	IntervalH  *int
	ExtraNames *[]string
	UseCT      *bool
}

func (s *Store) PatchDNSMap(ctx context.Context, id string, p DNSMapPatch) (DNSMap, error) {
	u, err := ParseID(id)
	if err != nil {
		return DNSMap{}, ErrNotFound
	}
	if p.ExtraNames != nil && len(*p.ExtraNames) > MaxDNSExtraNames {
		return DNSMap{}, ErrLimit
	}
	return scanDNSMap(s.pool.QueryRow(ctx, `UPDATE dns_maps SET enabled=COALESCE($2, enabled), interval_hours=COALESCE($3, interval_hours),
			extra_names=COALESCE($4, extra_names), use_ct=COALESCE($5, use_ct),
			next_run_at = CASE WHEN $2 IS TRUE AND NOT enabled THEN NULL ELSE next_run_at END
		WHERE id=$1 AND archived_at IS NULL RETURNING `+dnsMapCols, u, p.Enabled, p.IntervalH, p.ExtraNames, p.UseCT))
}

// ArchiveDNSMap hides a map and keeps its history.
func (s *Store) ArchiveDNSMap(ctx context.Context, id string) error {
	u, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE dns_maps SET archived_at=now(), enabled=false WHERE id=$1 AND archived_at IS NULL`, u)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ErrRunning means a run of this map is already in progress.
var ErrRunning = errors.New("store: a run is already in progress")

// RequestDNSRun makes a map due now; the worker picks it up. A map that is mid-run answers ErrRunning.
func (s *Store) RequestDNSRun(ctx context.Context, id string, now time.Time) error {
	u, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	var running bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM dns_check_runs WHERE map_id=$1 AND status='running' AND started_at > $2)`, u, now.Add(-10*time.Minute)).Scan(&running); err != nil {
		return err
	}
	if running {
		return ErrRunning
	}
	tag, err := s.pool.Exec(ctx, `UPDATE dns_maps SET next_run_at=NULL WHERE id=$1 AND archived_at IS NULL`, u)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// DueDNSMaps lists the enabled maps whose time has come and that are not mid-run.
func (s *Store) DueDNSMaps(ctx context.Context, now time.Time, limit int) ([]DNSMap, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+dnsMapCols+` FROM dns_maps m WHERE enabled AND archived_at IS NULL AND (next_run_at IS NULL OR next_run_at <= $1)
		AND NOT EXISTS (SELECT 1 FROM dns_check_runs r WHERE r.map_id=m.id AND r.status='running' AND r.started_at > $2)
		ORDER BY next_run_at NULLS FIRST LIMIT $3`, now, now.Add(-10*time.Minute), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DNSMap
	for rows.Next() {
		m, err := scanDNSMap(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// StartDNSRun records that a run began. The run row is the durable status: a run that never finishes is
// swept to "failed" the next time the worker starts.
func (s *Store) StartDNSRun(ctx context.Context, mapID, trigger string, now time.Time) (string, error) {
	u, err := ParseID(mapID)
	if err != nil {
		return "", ErrNotFound
	}
	var id uuid.UUID
	err = s.pool.QueryRow(ctx, `INSERT INTO dns_check_runs (map_id, trigger, started_at, status) VALUES ($1,$2,$3,'running') RETURNING id`, u, trigger, now).Scan(&id)
	return id.String(), err
}

// SweepDNSRuns marks runs left "running" by a process that died as failed.
func (s *Store) SweepDNSRuns(ctx context.Context, now time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE dns_check_runs SET status='failed', finished_at=$1, error='interrupted' WHERE status='running' AND started_at < $2`, now, now.Add(-10*time.Minute))
	return err
}

func jsonOf(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("null")
	}
	return b
}

func valuesOf(b []byte) []string {
	var v []string
	_ = json.Unmarshal(b, &v)
	return v
}

// FinishDNSRun stores what a run observed, the changes it explains, and when the next run is due. All of it
// is one step: a run that is stored is stored completely.
//
// What it will not do is let a poor observation replace a good one. A record set's settled state moves only
// when both resolvers agreed on the new one (or when nothing was known yet); a timeout, a server failure, a
// refusal, a disagreement or a single resolver's word only updates "last observed" and the views.
func (s *Store) FinishDNSRun(ctx context.Context, mapID, runID string, res dnsmap.RunResult, now, next time.Time) error {
	mid, err := ParseID(mapID)
	if err != nil {
		return ErrNotFound
	}
	rid, err := ParseID(runID)
	if err != nil {
		return ErrNotFound
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var baseline bool
		var lastStatus *string
		if err := tx.QueryRow(ctx, `SELECT baseline_done, last_status FROM dns_maps WHERE id=$1 FOR UPDATE`, mid).Scan(&baseline, &lastStatus); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		prev := map[dnsmap.Key]dnsmap.State{}
		rows, err := tx.Query(ctx, `SELECT name, type, result, values FROM dns_records WHERE map_id=$1 AND result IS NOT NULL`, mid)
		if err != nil {
			return err
		}
		for rows.Next() {
			var name, typ, result string
			var vals []byte
			if err := rows.Scan(&name, &typ, &result, &vals); err != nil {
				rows.Close()
				return err
			}
			prev[dnsmap.Key{Name: name, Type: typ}] = dnsmap.State{Values: valuesOf(vals), Result: result}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		obs := make([]dnsmap.Obs, 0, len(res.Recs))
		for _, r := range res.Recs {
			obs = append(obs, r.Obs)
		}
		changes := dnsmap.Diff(prev, obs, !baseline)

		for _, n := range res.Names {
			if _, err := tx.Exec(ctx, `INSERT INTO dns_map_names (map_id, name, provenance, first_seen, last_seen) VALUES ($1,$2,$3,$4,$4)
				ON CONFLICT (map_id, name) DO UPDATE SET last_seen=EXCLUDED.last_seen`, mid, n.Name, n.Provenance, now); err != nil {
				return err
			}
		}
		for _, r := range res.Recs {
			settled := dnsmap.Settled(r.Result)
			take := settled && r.Confirmed
			old, known := prev[dnsmap.Key{Name: r.Name, Type: r.Type}]
			switch {
			case !known && !take && !settled:
				// Never settled and still not: the row only records that it was asked.
				if _, err := tx.Exec(ctx, `INSERT INTO dns_records (map_id, name, type, last_result, views, first_seen, last_checked, confirmed)
					VALUES ($1,$2,$3,$4,$5,$6,$6,false)
					ON CONFLICT (map_id, name, type) DO UPDATE SET last_result=EXCLUDED.last_result, views=EXCLUDED.views, last_checked=EXCLUDED.last_checked, confirmed=false`,
					mid, r.Name, r.Type, r.Result, jsonOf(r.Views), now); err != nil {
					return err
				}
			case !known || take:
				present := r.Result == dnsmap.OutcomeAnswer
				changed := known && (old.Result != r.Result || strings.Join(old.Values, "\n") != strings.Join(r.Values, "\n"))
				gone := known && old.Result == dnsmap.OutcomeAnswer && !present
				var changedAt *time.Time
				if changed {
					changedAt = &now
				}
				var seen *time.Time
				if present {
					seen = &now
				}
				if _, err := tx.Exec(ctx, `INSERT INTO dns_records (map_id, name, type, result, values, ttl, confirmed, last_result, views, first_seen, last_seen, last_checked, last_changed, no_longer_observed)
					VALUES ($1,$2,$3,$4,$5,$6,$7,$4,$8,$9,$10,$9,$11,$12)
					ON CONFLICT (map_id, name, type) DO UPDATE SET result=EXCLUDED.result, values=EXCLUDED.values, ttl=EXCLUDED.ttl, confirmed=EXCLUDED.confirmed,
						last_result=EXCLUDED.last_result, views=EXCLUDED.views, last_checked=EXCLUDED.last_checked,
						last_seen=COALESCE(EXCLUDED.last_seen, dns_records.last_seen), last_changed=COALESCE(EXCLUDED.last_changed, dns_records.last_changed),
						no_longer_observed=EXCLUDED.no_longer_observed`,
					mid, r.Name, r.Type, r.Result, jsonOf(nilToEmpty(r.Values)), int(r.TTL), r.Confirmed, jsonOf(r.Views), now, seen, changedAt, gone); err != nil {
					return err
				}
			default:
				if _, err := tx.Exec(ctx, `UPDATE dns_records SET last_result=$4, views=$5, last_checked=$6, confirmed=$7 WHERE map_id=$1 AND name=$2 AND type=$3`,
					mid, r.Name, r.Type, r.Result, jsonOf(r.Views), now, r.Confirmed); err != nil {
					return err
				}
			}
		}

		for _, c := range changes {
			var recent int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM dns_changes WHERE map_id=$1 AND name=$2 AND type=$3 AND observed_at > $4`, mid, c.Name, c.Type, now.Add(-7*24*time.Hour)).Scan(&recent); err != nil {
				return err
			}
			if err := insertDNSChange(ctx, tx, mid, rid, c.Name, c.Type, c.Kind, c.Before, c.After, now, recent+1 >= VolatileChanges); err != nil {
				return err
			}
		}
		// The check itself: a run that could not settle even the basics, and the run that recovers from it.
		switch {
		case res.Status == "failed" && (lastStatus == nil || *lastStatus != "failed"):
			if err := insertDNSChange(ctx, tx, mid, rid, "", "*", dnsmap.ChangeCheckFailed, nil, nil, now, false); err != nil {
				return err
			}
		case res.Status != "failed" && lastStatus != nil && *lastStatus == "failed":
			if err := insertDNSChange(ctx, tx, mid, rid, "", "*", dnsmap.ChangeCheckRecover, nil, nil, now, false); err != nil {
				return err
			}
		}

		if _, err := tx.Exec(ctx, `UPDATE dns_check_runs SET status=$2, finished_at=$3, coverage=$4, auth=$5, mismatch=$6 WHERE id=$1`,
			rid, res.Status, now, jsonOf(res.Coverage), jsonOf(nilAuth(res.Auth)), nilStrings(res.Mismatch)); err != nil {
			return err
		}
		// The map is "baselined" once a run settled something about the apex; until then nothing is explained.
		settledApex := false
		for _, r := range res.Recs {
			if len(res.Names) > 0 && r.Name == res.Names[0].Name && r.Confirmed && dnsmap.Settled(r.Result) {
				settledApex = true
			}
		}
		_, err = tx.Exec(ctx, `UPDATE dns_maps SET last_run_at=$2, last_status=$3, next_run_at=$4, baseline_done = baseline_done OR $5 WHERE id=$1`,
			mid, now, res.Status, next, settledApex && res.Status != "failed")
		return err
	})
}

func nilToEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func nilStrings(v []string) []string { return nilToEmpty(v) }

func nilAuth(v []dnsmap.AuthServer) []dnsmap.AuthServer {
	if v == nil {
		return []dnsmap.AuthServer{}
	}
	return v
}

func insertDNSChange(ctx context.Context, tx pgx.Tx, mid, rid uuid.UUID, name, typ, kind string, before, after []string, now time.Time, volatile bool) error {
	key := fmt.Sprintf("%s|%s|%s|%s", rid, name, typ, kind)
	_, err := tx.Exec(ctx, `INSERT INTO dns_changes (map_id, run_id, name, type, kind, before, after, observed_at, volatile, dedupe_key)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (map_id, dedupe_key) DO NOTHING`,
		mid, rid, name, typ, kind, jsonOf(nilToEmpty(before)), jsonOf(nilToEmpty(after)), now, volatile, key)
	return err
}

// FailDNSRun ends a run that could not be carried out at all (not even a result could be built).
func (s *Store) FailDNSRun(ctx context.Context, mapID, runID, reason string, now, next time.Time) error {
	rid, err := ParseID(runID)
	if err != nil {
		return ErrNotFound
	}
	if _, err := s.pool.Exec(ctx, `UPDATE dns_check_runs SET status='failed', finished_at=$2, error=$3 WHERE id=$1`, rid, now, reason); err != nil {
		return err
	}
	mid, err := ParseID(mapID)
	if err != nil {
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `UPDATE dns_maps SET last_run_at=$2, next_run_at=$3 WHERE id=$1`, mid, now, next)
	return err
}

// --- reads ---------------------------------------------------------------------------------------

type DNSRecordRow struct {
	Name             string          `json:"name"`
	Type             string          `json:"type"`
	Result           *string         `json:"result"`
	Values           []string        `json:"values"`
	TTL              int             `json:"ttl"`
	Confirmed        bool            `json:"confirmed"`
	LastResult       string          `json:"last_result"`
	Views            json.RawMessage `json:"views"`
	FirstSeen        time.Time       `json:"first_seen"`
	LastSeen         *time.Time      `json:"last_seen"`
	LastChecked      time.Time       `json:"last_checked"`
	LastChanged      *time.Time      `json:"last_changed"`
	NoLongerObserved bool            `json:"no_longer_observed"`
}

type DNSRecordFilter struct {
	Type, Name, Q        string
	AfterName, AfterType string
	Limit                int
}

// DNSRecords returns a map's record sets in name and type order, with a keyset cursor.
func (s *Store) DNSRecords(ctx context.Context, mapID string, f DNSRecordFilter) ([]DNSRecordRow, error) {
	u, err := ParseID(mapID)
	if err != nil {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT name, type, result, values, ttl, confirmed, last_result, views, first_seen, last_seen, last_checked, last_changed, no_longer_observed
		FROM dns_records WHERE map_id=$1 AND ($2='' OR type=$2) AND ($3='' OR name=$3)
		  AND ($4='' OR name ILIKE $4 ESCAPE '\' OR type ILIKE $4 ESCAPE '\' OR values::text ILIKE $4 ESCAPE '\')
		  AND ($5='' OR (name, type) > ($5, $6))
		ORDER BY name, type LIMIT $7`, u, f.Type, f.Name, likePattern(f.Q), f.AfterName, f.AfterType, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DNSRecordRow{}
	for rows.Next() {
		var r DNSRecordRow
		var vals, views []byte
		if err := rows.Scan(&r.Name, &r.Type, &r.Result, &vals, &r.TTL, &r.Confirmed, &r.LastResult, &views, &r.FirstSeen, &r.LastSeen, &r.LastChecked, &r.LastChanged, &r.NoLongerObserved); err != nil {
			return nil, err
		}
		r.Values, r.Views = nilToEmpty(valuesOf(vals)), views
		out = append(out, r)
	}
	return out, rows.Err()
}

func likePattern(q string) string {
	if q == "" {
		return ""
	}
	return "%" + likeEscape(q) + "%"
}

type DNSNameRow struct {
	Name       string    `json:"name"`
	Provenance string    `json:"provenance"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

func (s *Store) DNSNames(ctx context.Context, mapID string) ([]DNSNameRow, error) {
	u, err := ParseID(mapID)
	if err != nil {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT name, provenance, first_seen, last_seen FROM dns_map_names WHERE map_id=$1 ORDER BY name`, u)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DNSNameRow{}
	for rows.Next() {
		var n DNSNameRow
		if err := rows.Scan(&n.Name, &n.Provenance, &n.FirstSeen, &n.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

type DNSChangeRow struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Kind       string    `json:"kind"`
	Before     []string  `json:"before"`
	After      []string  `json:"after"`
	ObservedAt time.Time `json:"observed_at"`
	Volatile   bool      `json:"volatile"`
}

type DNSChangeFilter struct {
	Name, Type, Kind   string
	From, To, BeforeTS *time.Time
	BeforeID           string
	Limit              int
}

func (s *Store) DNSChanges(ctx context.Context, mapID string, f DNSChangeFilter) ([]DNSChangeRow, error) {
	u, err := ParseID(mapID)
	if err != nil {
		return nil, ErrNotFound
	}
	bid := uuid.Max
	if x, err := uuid.Parse(f.BeforeID); err == nil {
		bid = x
	}
	rows, err := s.pool.Query(ctx, `SELECT id, name, type, kind, before, after, observed_at, volatile FROM dns_changes
		WHERE map_id=$1 AND ($2='' OR name=$2) AND ($3='' OR type=$3) AND ($4='' OR kind=$4)
		  AND ($5::timestamptz IS NULL OR observed_at >= $5) AND ($6::timestamptz IS NULL OR observed_at < $6)
		  AND ($7::timestamptz IS NULL OR (observed_at, id) < ($7::timestamptz, $8::uuid))
		ORDER BY observed_at DESC, id DESC LIMIT $9`, u, f.Name, f.Type, f.Kind, f.From, f.To, f.BeforeTS, bid, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DNSChangeRow{}
	for rows.Next() {
		var c DNSChangeRow
		var id uuid.UUID
		var b, a []byte
		if err := rows.Scan(&id, &c.Name, &c.Type, &c.Kind, &b, &a, &c.ObservedAt, &c.Volatile); err != nil {
			return nil, err
		}
		c.ID, c.Before, c.After = id.String(), nilToEmpty(valuesOf(b)), nilToEmpty(valuesOf(a))
		out = append(out, c)
	}
	return out, rows.Err()
}

type DNSRunRow struct {
	ID         string          `json:"id"`
	Trigger    string          `json:"trigger"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt *time.Time      `json:"finished_at"`
	Status     string          `json:"status"`
	Coverage   json.RawMessage `json:"coverage"`
	Auth       json.RawMessage `json:"auth"`
	Mismatch   []string        `json:"mismatch"`
	Error      *string         `json:"error"`
}

func (s *Store) DNSRuns(ctx context.Context, mapID string, limit int) ([]DNSRunRow, error) {
	u, err := ParseID(mapID)
	if err != nil {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT id, trigger, started_at, finished_at, status, coverage, auth, mismatch, error FROM dns_check_runs WHERE map_id=$1 ORDER BY started_at DESC LIMIT $2`, u, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DNSRunRow{}
	for rows.Next() {
		var r DNSRunRow
		var id uuid.UUID
		var cov, auth []byte
		if err := rows.Scan(&id, &r.Trigger, &r.StartedAt, &r.FinishedAt, &r.Status, &cov, &auth, &r.Mismatch, &r.Error); err != nil {
			return nil, err
		}
		r.ID, r.Coverage, r.Auth = id.String(), cov, auth
		if r.Mismatch == nil {
			r.Mismatch = []string{}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PurgeDNS deletes DNS changes and run records older than the retention, in batches. The maps and the
// current record sets stay: they are the state, not the history.
func (s *Store) PurgeDNS(ctx context.Context, now time.Time) (int64, error) {
	cut := now.Add(-DNSRetention)
	var total int64
	for _, q := range []string{
		`DELETE FROM dns_changes WHERE ctid IN (SELECT ctid FROM dns_changes WHERE observed_at < $1 LIMIT 5000)`,
		`DELETE FROM dns_check_runs WHERE ctid IN (SELECT ctid FROM dns_check_runs WHERE started_at < $1 AND status <> 'running' LIMIT 5000)`,
	} {
		for {
			tag, err := s.pool.Exec(ctx, q, cut)
			if err != nil {
				return total, err
			}
			total += tag.RowsAffected()
			if tag.RowsAffected() < 5000 {
				break
			}
			select {
			case <-ctx.Done():
				return total, ctx.Err()
			default:
			}
		}
	}
	return total, nil
}

// --- what the alert evaluator reads --------------------------------------------------------------

type DNSAlertState struct {
	MapID     string
	Domain    string
	Failed    bool       // the last run could not settle even the apex's basic records
	Important int        // changes of the kinds that matter, from the last day, not counting volatile record sets
	Latest    *time.Time // the time of the latest of them
	Kinds     []string
}

func (s *Store) DNSAlertStates(ctx context.Context, now time.Time) ([]DNSAlertState, error) {
	rows, err := s.pool.Query(ctx, `SELECT m.id, m.domain, COALESCE(m.last_status = 'failed', false) FROM dns_maps m WHERE m.enabled AND m.archived_at IS NULL`)
	if err != nil {
		return nil, err
	}
	var out []DNSAlertState
	for rows.Next() {
		var st DNSAlertState
		var id uuid.UUID
		if err := rows.Scan(&id, &st.Domain, &st.Failed); err != nil {
			rows.Close()
			return nil, err
		}
		st.MapID = id.String()
		out = append(out, st)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		cr, err := s.pool.Query(ctx, `SELECT kind, observed_at FROM dns_changes WHERE map_id=$1 AND observed_at > $2 AND NOT volatile
			AND kind IN ('dns.ns_changed','dns.mx_changed','dns.spf_changed','dns.dmarc_changed','dns.record_removed','dns.value_changed') ORDER BY observed_at DESC`,
			out[i].MapID, now.Add(-24*time.Hour))
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for cr.Next() {
			var k string
			var at time.Time
			if err := cr.Scan(&k, &at); err != nil {
				cr.Close()
				return nil, err
			}
			out[i].Important++
			if out[i].Latest == nil {
				out[i].Latest = &at
			}
			if !seen[k] {
				seen[k] = true
				out[i].Kinds = append(out[i].Kinds, k)
			}
		}
		cr.Close()
	}
	return out, nil
}
