package store

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// AlertRule is how one machine differs from the defaults for one resource alert.
type AlertRule struct {
	Rule      string `json:"rule"` // disk:<mount> | forecast | cpu | mem
	Enabled   bool   `json:"enabled"`
	Threshold *int   `json:"threshold,omitempty"` // percent, or days for forecast; nil: the default
}

var ruleName = regexp.MustCompile(`^(disk:.{1,64}|forecast|cpu|mem)$`)

// MaxAlertRules bounds the rules of one machine.
const MaxAlertRules = 40

// CleanAlertRules checks a machine's rules: the names, the thresholds and that each rule is there once.
func CleanAlertRules(in []AlertRule) ([]AlertRule, error) {
	if len(in) > MaxAlertRules {
		return nil, ErrBadBlockSettings
	}
	seen := map[string]bool{}
	out := make([]AlertRule, 0, len(in))
	for _, r := range in {
		r.Rule = strings.TrimSpace(r.Rule)
		if !ruleName.MatchString(r.Rule) || seen[r.Rule] {
			return nil, ErrBadBlockSettings
		}
		seen[r.Rule] = true
		if r.Threshold != nil {
			t := *r.Threshold
			max := 100
			if r.Rule == "forecast" {
				max = 365
			}
			if t < 1 || t > max {
				return nil, ErrBadBlockSettings
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// GetAlertRules lists a machine's rules.
func (s *Store) GetAlertRules(ctx context.Context, vpsID string) ([]AlertRule, error) {
	vid, err := ParseID(vpsID)
	if err != nil {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT rule, enabled, threshold FROM alert_rules WHERE vps_id=$1 ORDER BY rule`, vid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AlertRule{}
	for rows.Next() {
		var r AlertRule
		if err := rows.Scan(&r.Rule, &r.Enabled, &r.Threshold); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PutAlertRules replaces a machine's rules with the given ones.
func (s *Store) PutAlertRules(ctx context.Context, vpsID string, rules []AlertRule) error {
	vid, err := ParseID(vpsID)
	if err != nil {
		return ErrNotFound
	}
	rules, err = CleanAlertRules(rules)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `DELETE FROM alert_rules WHERE vps_id=$1`, vid); e != nil {
			return e
		}
		for _, r := range rules {
			if _, e := tx.Exec(ctx, `INSERT INTO alert_rules (vps_id, rule, enabled, threshold) VALUES ($1, $2, $3, $4)`, vid, r.Rule, r.Enabled, r.Threshold); e != nil {
				return e
			}
		}
		return nil
	})
}

// allAlertRules is every machine's rules by machine and rule name, for the evaluation.
func (s *Store) allAlertRules(ctx context.Context) (map[string]map[string]AlertRule, error) {
	rows, err := s.pool.Query(ctx, `SELECT vps_id::text, rule, enabled, threshold FROM alert_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]AlertRule{}
	for rows.Next() {
		var id string
		var r AlertRule
		if err := rows.Scan(&id, &r.Rule, &r.Enabled, &r.Threshold); err != nil {
			return nil, err
		}
		if out[id] == nil {
			out[id] = map[string]AlertRule{}
		}
		out[id][r.Rule] = r
	}
	return out, rows.Err()
}

// SnoozeAlert puts one alert off until the given time.
func (s *Store) SnoozeAlert(ctx context.Context, kind, subject string, until time.Time) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO alert_snoozes (kind, subject, until) VALUES ($1, $2, $3)
		ON CONFLICT (kind, subject) DO UPDATE SET until=$3, created_at=now()`, kind, subject, until)
	return err
}

// ActiveSnoozes lists the alerts put off now as "kind\x00subject", and forgets the ones whose time is up.
func (s *Store) ActiveSnoozes(ctx context.Context, now time.Time) (map[string]bool, error) {
	if _, err := s.pool.Exec(ctx, `DELETE FROM alert_snoozes WHERE until <= $1`, now); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT kind, subject FROM alert_snoozes WHERE until > $1`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var k, sub string
		if err := rows.Scan(&k, &sub); err != nil {
			return nil, err
		}
		out[k+"\x00"+sub] = true
	}
	return out, rows.Err()
}

// ResolveAlert closes one open alert by hand (it is put off); it says whether there was one.
func (s *Store) ResolveAlert(ctx context.Context, id string, now time.Time) (bool, error) {
	aid, err := ParseID(id)
	if err != nil {
		return false, ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE alerts SET resolved_at=$2 WHERE id=$1 AND resolved_at IS NULL`, aid, now)
	return tag.RowsAffected() == 1, err
}

// AlertByID reads one alert's kind and subject.
func (s *Store) AlertByID(ctx context.Context, id string) (kind, subject string, ok bool, err error) {
	aid, perr := ParseID(id)
	if perr != nil {
		return "", "", false, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT kind, subject FROM alerts WHERE id=$1`, aid)
	if err != nil {
		return "", "", false, err
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&kind, &subject); err != nil {
			return "", "", false, err
		}
		return kind, subject, true, nil
	}
	return "", "", false, rows.Err()
}
