package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type AutoSettings struct {
	Enabled    bool      `json:"enabled"`
	Model      string    `json:"model"`
	BatchSize  int       `json:"batch_size"`
	DailyLimit int       `json:"daily_limit"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (s *Store) AutoSettings(ctx context.Context) (AutoSettings, error) {
	var a AutoSettings
	err := s.pool.QueryRow(ctx, `SELECT enabled, model, batch_size, daily_limit, updated_at FROM autoclassify_settings WHERE id`).
		Scan(&a.Enabled, &a.Model, &a.BatchSize, &a.DailyLimit, &a.UpdatedAt)
	return a, err
}

// SetAutoSettings stores the choices of the owner. The caller has validated them.
func (s *Store) SetAutoSettings(ctx context.Context, model string, batch, daily int, by string) (AutoSettings, error) {
	var u any
	if id, err := uuid.Parse(by); err == nil {
		u = id
	}
	if _, err := s.pool.Exec(ctx, `UPDATE autoclassify_settings SET model=$1, batch_size=$2, daily_limit=$3, updated_at=now(), updated_by=$4 WHERE id`, model, batch, daily, u); err != nil {
		return AutoSettings{}, err
	}
	return s.AutoSettings(ctx)
}

type UnknownSite struct {
	Site        string
	Connections int
}

// UnknownSites lists the registrable domains seen in the events of real panels that no rule (built-in,
// custom or automatic) classifies, busiest first. It reads the rules through the same match the
// analytics use, so "unknown" means exactly "shown as not classified".
func (s *Store) UnknownSites(ctx context.Context, limit int) ([]UnknownSite, error) {
	if limit <= 0 || limit > 20000 {
		limit = 3000
	}
	rs, err := s.pool.Query(ctx, `
SELECT x.site, x.c FROM (
  SELECT t.site, count(*) AS c FROM (
    SELECT e.site FROM connection_events e JOIN panels p ON p.id = e.panel_id WHERE NOT p.demo AND e.site IS NOT NULL
    UNION ALL
    SELECT d.site FROM device_connections d JOIN panels p ON p.id = d.panel_id WHERE NOT p.demo AND d.site IS NOT NULL
  ) t GROUP BY t.site
) x `+ruleMatch("x.site")+`
WHERE r.service IS NULL ORDER BY x.c DESC, x.site LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := []UnknownSite{}
	for rs.Next() {
		var u UnknownSite
		if err := rs.Scan(&u.Site, &u.Connections); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rs.Err()
}

type DryRun struct {
	ID         string     `json:"id"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	Model      string     `json:"model"`
	State      string     `json:"state"`
	Requested  int        `json:"requested"`
	Requests   int        `json:"requests"`
	TokensIn   int        `json:"tokens_in"`
	TokensOut  int        `json:"tokens_out"`
	ErrorCode  string     `json:"error_code,omitempty"`
}

type DryRunItem struct {
	Site         string  `json:"site"`
	Connections  int     `json:"connections"`
	PickedBy     string  `json:"picked_by"`
	Valid        bool    `json:"valid"`
	Undetermined bool    `json:"undetermined"`
	Category     string  `json:"category,omitempty"`
	Service      string  `json:"service,omitempty"`
	Confidence   float64 `json:"confidence"`
	Reason       string  `json:"reason,omitempty"`
	Issue        string  `json:"issue,omitempty"`
}

func (s *Store) CreateDryRun(ctx context.Context, model string, requested int, by string) (string, error) {
	var u any
	if id, err := uuid.Parse(by); err == nil {
		u = id
	}
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `INSERT INTO classify_dryrun_runs (model, requested, started_by) VALUES ($1,$2,$3) RETURNING id`, model, requested, u).Scan(&id)
	return id.String(), err
}

func (s *Store) AddDryRunItems(ctx context.Context, runID string, items []DryRunItem) error {
	id, err := ParseID(runID)
	if err != nil {
		return ErrNotFound
	}
	for _, it := range items {
		if _, err := s.pool.Exec(ctx, `INSERT INTO classify_dryrun_items (run_id, site, connections, picked_by, valid, undetermined, category, service, confidence, reason, issue)
			VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),NULLIF($8,''),$9,NULLIF($10,''),NULLIF($11,''))
			ON CONFLICT (run_id, site) DO UPDATE SET valid=EXCLUDED.valid, undetermined=EXCLUDED.undetermined, category=EXCLUDED.category,
			  service=EXCLUDED.service, confidence=EXCLUDED.confidence, reason=EXCLUDED.reason, issue=EXCLUDED.issue`,
			id, it.Site, it.Connections, it.PickedBy, it.Valid, it.Undetermined, it.Category, it.Service, it.Confidence, it.Reason, it.Issue); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) AddDryRunUsage(ctx context.Context, runID string, requests, in, out int) error {
	id, err := ParseID(runID)
	if err != nil {
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `UPDATE classify_dryrun_runs SET requests=requests+$2, tokens_in=tokens_in+$3, tokens_out=tokens_out+$4 WHERE id=$1`, id, requests, in, out)
	return err
}

func (s *Store) FinishDryRun(ctx context.Context, runID, state, errCode string) error {
	id, err := ParseID(runID)
	if err != nil {
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `UPDATE classify_dryrun_runs SET state=$2, error_code=NULLIF($3,''), finished_at=now() WHERE id=$1`, id, state, errCode)
	return err
}

// FailStaleDryRuns marks runs that were left "running" by a restart as failed.
func (s *Store) FailStaleDryRuns(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `UPDATE classify_dryrun_runs SET state='failed', error_code='interrupted', finished_at=now() WHERE state='running'`)
	return err
}

// LatestDryRun returns the newest run, or ErrNotFound.
func (s *Store) LatestDryRun(ctx context.Context) (DryRun, error) {
	var r DryRun
	var id uuid.UUID
	var code *string
	err := s.pool.QueryRow(ctx, `SELECT id, started_at, finished_at, model, state, requested, requests, tokens_in, tokens_out, error_code FROM classify_dryrun_runs ORDER BY started_at DESC LIMIT 1`).
		Scan(&id, &r.StartedAt, &r.FinishedAt, &r.Model, &r.State, &r.Requested, &r.Requests, &r.TokensIn, &r.TokensOut, &code)
	if err != nil {
		return r, ErrNotFound
	}
	r.ID = id.String()
	if code != nil {
		r.ErrorCode = *code
	}
	return r, nil
}

func (s *Store) DryRunItems(ctx context.Context, runID string) ([]DryRunItem, error) {
	id, err := ParseID(runID)
	if err != nil {
		return nil, ErrNotFound
	}
	rs, err := s.pool.Query(ctx, `SELECT site, connections, picked_by, valid, undetermined, COALESCE(category,''), COALESCE(service,''), COALESCE(confidence,0), COALESCE(reason,''), COALESCE(issue,'')
		FROM classify_dryrun_items WHERE run_id=$1 ORDER BY connections DESC, site`, id)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := []DryRunItem{}
	for rs.Next() {
		var it DryRunItem
		if err := rs.Scan(&it.Site, &it.Connections, &it.PickedBy, &it.Valid, &it.Undetermined, &it.Category, &it.Service, &it.Confidence, &it.Reason, &it.Issue); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rs.Err()
}
