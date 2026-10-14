package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CustomRuleVersion is above every built-in rule version, so a custom rule wins a tie on pattern
// length (see ruleMatch) and deleting it brings the built-in rule back.
const CustomRuleVersion = 1000

type Rule struct {
	ID         string     `json:"id"`
	Pattern    string     `json:"pattern"`
	Service    string     `json:"service"`
	Category   string     `json:"category"`
	Confidence string     `json:"confidence"`
	Source     string     `json:"source"`
	CreatedAt  *time.Time `json:"created_at"`
}

func (s *Store) ListCustomRules(ctx context.Context) ([]Rule, error) {
	rs, err := s.pool.Query(ctx, `SELECT id, pattern, service, COALESCE(category,''), confidence, source, created_at FROM service_rules
		WHERE source='custom' ORDER BY created_at DESC NULLS LAST, pattern`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := []Rule{}
	for rs.Next() {
		var r Rule
		var id uuid.UUID
		if err := rs.Scan(&id, &r.Pattern, &r.Service, &r.Category, &r.Confidence, &r.Source, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.ID = id.String()
		out = append(out, r)
	}
	return out, rs.Err()
}

// RuleCategories lists every category in use, for the picker.
func (s *Store) RuleCategories(ctx context.Context) ([]string, error) {
	rs, err := s.pool.Query(ctx, `SELECT DISTINCT category FROM service_rules WHERE enabled AND category IS NOT NULL ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := []string{}
	for rs.Next() {
		var c string
		if err := rs.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rs.Err()
}

// UpsertCustomRule adds or changes the custom rule for a pattern.
func (s *Store) UpsertCustomRule(ctx context.Context, pattern, service, category, confidence, createdBy string) (Rule, error) {
	var by any
	if id, err := uuid.Parse(createdBy); err == nil {
		by = id
	}
	var r Rule
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `INSERT INTO service_rules (rule_version, pattern, service, confidence, category, source, created_at, created_by)
		VALUES ($1,$2,$3,$4,$5,'custom',now(),$6)
		ON CONFLICT (rule_version, pattern) DO UPDATE SET service=EXCLUDED.service, confidence=EXCLUDED.confidence, category=EXCLUDED.category, enabled=true
		RETURNING id, pattern, service, COALESCE(category,''), confidence, source, created_at`, CustomRuleVersion, pattern, service, confidence, category, by).
		Scan(&id, &r.Pattern, &r.Service, &r.Category, &r.Confidence, &r.Source, &r.CreatedAt)
	r.ID = id.String()
	return r, err
}

// DeleteCustomRule removes a custom rule; built-in rules cannot be deleted this way.
func (s *Store) DeleteCustomRule(ctx context.Context, id string) (string, error) {
	u, err := ParseID(id)
	if err != nil {
		return "", ErrNotFound
	}
	var pattern string
	err = s.pool.QueryRow(ctx, `DELETE FROM service_rules WHERE id=$1 AND source='custom' RETURNING pattern`, u).Scan(&pattern)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return pattern, err
}
