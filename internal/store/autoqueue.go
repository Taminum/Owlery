package store

import (
	"context"
	"time"
)

// AutoRuleVersion is the lowest rule version: any built-in (1) or custom rule for the same pattern wins.
const AutoRuleVersion = 0

// Job states of classify_jobs.
const (
	JobPending      = "pending"
	JobRunning      = "running"
	JobRetry        = "retry"
	JobDone         = "done"
	JobUndetermined = "undetermined"
	JobFailed       = "failed"
	JobSkipped      = "skipped"
)

// MaxJobAttempts is how often a domain is tried before it is parked as failed.
const MaxJobAttempts = 5

type Candidate struct {
	Domain      string
	Connections int
}

// UnknownCandidates lists domains seen in events (since the given time, or ever if zero) that no rule
// classifies and that have no job yet, busiest first.
func (s *Store) UnknownCandidates(ctx context.Context, since time.Time, limit int) ([]Candidate, error) {
	rs, err := s.pool.Query(ctx, `
SELECT x.site, x.c FROM (
  SELECT t.site, count(*) AS c FROM (
    SELECT e.site FROM connection_events e JOIN panels p ON p.id = e.panel_id
      WHERE NOT p.demo AND e.site IS NOT NULL AND e.ts >= $1
    UNION ALL
    SELECT d.site FROM device_connections d JOIN panels p ON p.id = d.panel_id
      WHERE NOT p.demo AND d.site IS NOT NULL AND d.started_at >= $1
  ) t GROUP BY t.site
) x `+ruleMatch("x.site")+`
WHERE r.service IS NULL AND NOT EXISTS (SELECT 1 FROM classify_jobs j WHERE j.domain = x.site)
ORDER BY x.c DESC, x.site LIMIT $2`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []Candidate
	for rs.Next() {
		var c Candidate
		if err := rs.Scan(&c.Domain, &c.Connections); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rs.Err()
}

// EnqueueJobs adds domains to the queue; a domain that already has a job is left alone. Domains in
// skip are recorded as skipped so they are never offered again.
func (s *Store) EnqueueJobs(ctx context.Context, origin string, ready []Candidate, skip []string) (int, error) {
	n := 0
	for _, c := range ready {
		tag, err := s.pool.Exec(ctx, `INSERT INTO classify_jobs (domain, origin, priority) VALUES ($1,$2,$3) ON CONFLICT (domain) DO NOTHING`, c.Domain, origin, c.Connections)
		if err != nil {
			return n, err
		}
		n += int(tag.RowsAffected())
	}
	for _, d := range skip {
		if _, err := s.pool.Exec(ctx, `INSERT INTO classify_jobs (domain, origin, state, last_error_code, completed_at) VALUES ($1,$2,'skipped','ineligible',now()) ON CONFLICT (domain) DO NOTHING`, d, origin); err != nil {
			return n, err
		}
	}
	return n, nil
}

// RecoverJobs puts jobs left "running" by a crash back in the queue and returns parked failures to it
// once their waiting time is over. Safe to call from several instances.
func (s *Store) RecoverJobs(ctx context.Context, staleAfter time.Duration) error {
	if _, err := s.pool.Exec(ctx, `UPDATE classify_jobs SET state='retry', locked_at=NULL WHERE state='running' AND locked_at < now() - make_interval(secs => $1)`, staleAfter.Seconds()); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `UPDATE classify_jobs SET state='pending', attempts=0, next_attempt_at=now() WHERE state IN ('failed','undetermined') AND next_attempt_at <= now()`)
	return err
}

// ClaimJobs takes up to n ready jobs for this worker. FOR UPDATE SKIP LOCKED makes it safe to run
// from several instances: two workers never get the same domain.
func (s *Store) ClaimJobs(ctx context.Context, n int) ([]string, error) {
	rs, err := s.pool.Query(ctx, `UPDATE classify_jobs SET state='running', locked_at=now(), attempts=attempts+1
		WHERE domain IN (SELECT domain FROM classify_jobs WHERE state IN ('pending','retry') AND next_attempt_at <= now()
		                 ORDER BY priority DESC, enqueued_at LIMIT $1 FOR UPDATE SKIP LOCKED)
		RETURNING domain`, n)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []string
	for rs.Next() {
		var d string
		if err := rs.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rs.Err()
}

// ReleaseJobs gives claimed jobs back without counting the try (the service was not reachable for a
// reason that is not the domain's fault: key refused, rate limit).
func (s *Store) ReleaseJobs(ctx context.Context, domains []string, code string, after time.Duration) error {
	_, err := s.pool.Exec(ctx, `UPDATE classify_jobs SET state='pending', locked_at=NULL, attempts=GREATEST(attempts-1,0), last_error_code=NULLIF($2,''),
		next_attempt_at=now() + make_interval(secs => $3) WHERE domain = ANY($1) AND state='running'`, domains, code, after.Seconds())
	return err
}

// FailJobsTry records an unsuccessful try: back to retry with a delay, or parked as failed for a day
// after MaxJobAttempts.
func (s *Store) FailJobsTry(ctx context.Context, domains []string, code string, delay time.Duration) error {
	_, err := s.pool.Exec(ctx, `UPDATE classify_jobs SET locked_at=NULL, last_error_code=$2,
		state = CASE WHEN attempts >= $4 THEN 'failed' ELSE 'retry' END,
		next_attempt_at = CASE WHEN attempts >= $4 THEN now() + interval '24 hours' ELSE now() + make_interval(secs => $3) END
		WHERE domain = ANY($1) AND state='running'`, domains, code, delay.Seconds(), MaxJobAttempts)
	return err
}

// CompleteJob marks a job done, undetermined (asked again in a week) or skipped.
func (s *Store) CompleteJob(ctx context.Context, domain, state, code string) error {
	_, err := s.pool.Exec(ctx, `UPDATE classify_jobs SET state=$2, locked_at=NULL, last_error_code=NULLIF($3,''), completed_at=now(),
		next_attempt_at = CASE WHEN $2='undetermined' THEN now() + interval '7 days' ELSE next_attempt_at END WHERE domain=$1`, domain, state, code)
	return err
}

// AutoRule is what the model said about one domain, ready to be stored as a rule.
type AutoRule struct {
	Domain, Service, Category, Model, Reason string
	Score                                    float64
}

func scoreLabel(score float64) string {
	switch {
	case score >= 0.85:
		return "high"
	case score >= 0.6:
		return "medium"
	}
	return "low"
}

// ApplyAutoRule stores an automatic classification unless the domain is already classified by anything
// other than an earlier automatic rule. Returns false when it was not applied.
func (s *Store) ApplyAutoRule(ctx context.Context, r AutoRule) (bool, error) {
	var other bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM service_rules sr WHERE sr.enabled AND sr.source <> 'auto'
		AND ($1 = sr.pattern OR $1 LIKE '%.' || sr.pattern))`, r.Domain).Scan(&other)
	if err != nil || other {
		return false, err
	}
	service := r.Service
	if service == "" {
		service = r.Domain
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO service_rules (rule_version, pattern, service, confidence, category, source, score, model, reason, classified_at)
		VALUES ($1,$2,$3,$4,$5,'auto',$6,$7,NULLIF($8,''),now())
		ON CONFLICT (rule_version, pattern) DO UPDATE SET service=EXCLUDED.service, confidence=EXCLUDED.confidence, category=EXCLUDED.category,
		  score=EXCLUDED.score, model=EXCLUDED.model, reason=EXCLUDED.reason, classified_at=now(), enabled=true
		WHERE service_rules.source='auto'`, AutoRuleVersion, r.Domain, service, scoreLabel(r.Score), r.Category, r.Score, r.Model, r.Reason)
	return err == nil, err
}

// RequeueStaleAutoRules sends automatic results older than ttl back for a second look; manual and
// built-in rules are never touched. Returns how many were queued.
func (s *Store) RequeueStaleAutoRules(ctx context.Context, ttl time.Duration, limit int) (int, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE classify_jobs j SET state='pending', origin='review', attempts=0, next_attempt_at=now(), completed_at=NULL
		WHERE j.state='done' AND j.domain IN (SELECT pattern FROM service_rules WHERE source='auto' AND classified_at < now() - make_interval(secs => $1)
		                                      ORDER BY classified_at LIMIT $2)`, ttl.Seconds(), limit)
	return int(tag.RowsAffected()), err
}

// Budget.
func (s *Store) SpentToday(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT COALESCE((SELECT domains FROM classify_budget WHERE day = current_date), 0)`).Scan(&n)
	return n, err
}

func (s *Store) AddSpent(ctx context.Context, domains, requests, in, out int) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO classify_budget (day, domains, requests, tokens_in, tokens_out) VALUES (current_date,$1,$2,$3,$4)
		ON CONFLICT (day) DO UPDATE SET domains=classify_budget.domains+$1, requests=classify_budget.requests+$2,
		  tokens_in=classify_budget.tokens_in+$3, tokens_out=classify_budget.tokens_out+$4`, domains, requests, in, out)
	return err
}

type QueueStatus struct {
	Counts        map[string]int `json:"counts"`
	AutoRules     int            `json:"auto_rules"`
	SpentToday    int            `json:"spent_today"`
	RequestsToday int            `json:"requests_today"`
	TokensToday   int            `json:"tokens_today"`
	LastSuccessAt *time.Time     `json:"last_success_at"`
	LastErrorCode string         `json:"last_error_code,omitempty"`
	LastErrorAt   *time.Time     `json:"last_error_at,omitempty"`
	Backfill      string         `json:"backfill"`
}

func (s *Store) QueueStatus(ctx context.Context) (QueueStatus, error) {
	q := QueueStatus{Counts: map[string]int{}}
	rs, err := s.pool.Query(ctx, `SELECT state, count(*) FROM classify_jobs GROUP BY state`)
	if err != nil {
		return q, err
	}
	for rs.Next() {
		var st string
		var n int
		if err := rs.Scan(&st, &n); err != nil {
			rs.Close()
			return q, err
		}
		q.Counts[st] = n
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return q, err
	}
	var code *string
	err = s.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM service_rules WHERE source='auto'),
		COALESCE((SELECT domains FROM classify_budget WHERE day=current_date),0), COALESCE((SELECT requests FROM classify_budget WHERE day=current_date),0),
		COALESCE((SELECT tokens_in+tokens_out FROM classify_budget WHERE day=current_date),0),
		a.last_success_at, a.last_error_code, a.last_error_at, a.backfill_state FROM autoclassify_settings a WHERE a.id`).
		Scan(&q.AutoRules, &q.SpentToday, &q.RequestsToday, &q.TokensToday, &q.LastSuccessAt, &code, &q.LastErrorAt, &q.Backfill)
	if code != nil {
		q.LastErrorCode = *code
	}
	return q, err
}

// SetAutoEnabled is the kill switch.
func (s *Store) SetAutoEnabled(ctx context.Context, on bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE autoclassify_settings SET enabled=$1, updated_at=now() WHERE id`, on)
	return err
}

func (s *Store) NoteAutoSuccess(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `UPDATE autoclassify_settings SET last_success_at=now(), last_error_code=NULL, last_error_at=NULL WHERE id`)
	return err
}

func (s *Store) NoteAutoError(ctx context.Context, code string) error {
	_, err := s.pool.Exec(ctx, `UPDATE autoclassify_settings SET last_error_code=$1, last_error_at=now() WHERE id`, code)
	return err
}

// CategoryOf says how one domain is classified right now (category and origin label), through the same
// match the analytics use. Both are empty when no rule applies.
func (s *Store) CategoryOf(ctx context.Context, domain string) (category, origin string, err error) {
	var cat, src *string
	var score *float64
	if err = s.pool.QueryRow(ctx, `SELECT r.category, r.source, r.score FROM (SELECT $1::text AS name) s `+ruleMatch("s.name"), domain).Scan(&cat, &src, &score); err != nil {
		return "", "", err
	}
	if cat != nil {
		category = *cat
	}
	if src != nil {
		sc := 0.0
		if score != nil {
			sc = *score
		}
		origin = OriginOf(*src, sc)
	}
	return category, origin, nil
}

// SetBackfill moves the one-time historical fill: idle -> running -> done.
func (s *Store) SetBackfill(ctx context.Context, state string) error {
	_, err := s.pool.Exec(ctx, `UPDATE autoclassify_settings SET backfill_state=$1, backfill_started_at = CASE WHEN $1='running' THEN now() ELSE backfill_started_at END WHERE id`, state)
	return err
}

// Where a classification comes from, as shown next to it.
const (
	OriginRule   = "rule"   // built-in rule
	OriginManual = "manual" // the owner's own rule
	OriginAuto   = "auto"   // set by the model
	OriginGuess  = "guess"  // set by the model with low confidence
)

// GuessBelow is the model confidence under which an automatic result is shown as a guess.
const GuessBelow = 0.6

// OriginOf maps the source and score of the matching rule to a label key; "" when nothing matched.
func OriginOf(source string, score float64) string {
	switch source {
	case "builtin":
		return OriginRule
	case "custom":
		return OriginManual
	case "auto":
		if score < GuessBelow {
			return OriginGuess
		}
		return OriginAuto
	}
	return ""
}

// AutoInfo is the diagnostic detail of an automatic classification, shown on request.
type AutoInfo struct {
	Model        string     `json:"model"`
	Reason       string     `json:"reason"`
	Score        float64    `json:"score"`
	ClassifiedAt *time.Time `json:"classified_at"`
}

// AutoInfoFor returns the automatic rule stored for a domain, or nil.
func (s *Store) AutoInfoFor(ctx context.Context, domain string) *AutoInfo {
	var a AutoInfo
	var model, reason *string
	err := s.pool.QueryRow(ctx, `SELECT model, reason, COALESCE(score,0), classified_at FROM service_rules WHERE source='auto' AND pattern=$1 AND enabled`, domain).
		Scan(&model, &reason, &a.Score, &a.ClassifiedAt)
	if err != nil {
		return nil
	}
	if model != nil {
		a.Model = *model
	}
	if reason != nil {
		a.Reason = *reason
	}
	return &a
}
