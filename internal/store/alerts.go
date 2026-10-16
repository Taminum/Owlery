package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Alert kinds raised by the evaluator.
const (
	AlertAgentSilent = "agent_silent" // an enrolled agent has not been heard from
	AlertPanelSync   = "panel_sync"   // the panel cannot be synced
	AlertProbeDown   = "probe_down"   // a probed channel has stopped answering

	// Raised for servers in the security module. Their panel is the first one the server is linked to;
	// a server linked to none has no panel and its alerts are the owner's.
	AlertSecAgent = "sec_agent_silent" // a security agent has stopped reporting
	AlertSecTLS   = "sec_tls"          // a certificate is expiring, expired or not valid
	AlertSecPort  = "sec_port"         // an unexpected port answers, or an expected one does not

	// Users of a panel. They belong to the panel of the user.
	AlertUserExpiry  = "user_expiry"  // an active user's subscription ends within days
	AlertUserTraffic = "user_traffic" // an active user has used most of the traffic limit

	// DNS Map. These belong to no panel: they are the owner's.
	AlertDNSFailed = "dns_check_failed" // the last run could not settle even the apex's basic records
	AlertDNSChange = "dns_change"       // an important record changed in the last day, confirmed by two resolvers
)

type Alert struct {
	ID         string     `json:"id"`
	PanelID    string     `json:"panel_id"`
	Kind       string     `json:"kind"`
	Subject    string     `json:"subject"`
	Label      string     `json:"label"`
	Detail     string     `json:"detail"`
	OpenedAt   time.Time  `json:"opened_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	ResolvedAt *time.Time `json:"resolved_at"`
}

// Condition is one thing the evaluator found to be wrong right now.
type Condition struct {
	PanelID string
	Kind    string
	Subject string
	Label   string
	Detail  string
}

// ApplyConditions makes the alerts of the given kinds match what is wrong now: a condition that
// is new opens an alert, one that persists is refreshed (its opened_at is kept), and an open
// alert whose condition is gone is closed. It returns how many were opened and closed.
func (s *Store) ApplyConditions(ctx context.Context, kinds []string, conds []Condition, now time.Time) (opened, closed int, err error) {
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		subjects := map[string][]string{}
		for _, c := range conds {
			// An empty panel is allowed: the alert then belongs to no panel and only the owner sees it.
			var pid *uuid.UUID
			if c.PanelID != "" {
				u, perr := ParseID(c.PanelID)
				if perr != nil {
					continue
				}
				pid = &u
			}
			_, e := tx.Exec(ctx, `INSERT INTO alerts (panel_id, kind, subject, label, detail, opened_at, last_seen_at) VALUES ($1,$2,$3,$4,$5,$6,$6)
				ON CONFLICT (kind, subject) WHERE resolved_at IS NULL DO UPDATE SET label=EXCLUDED.label, detail=EXCLUDED.detail, last_seen_at=EXCLUDED.last_seen_at`,
				pid, c.Kind, c.Subject, c.Label, c.Detail, now)
			if e != nil {
				return e
			}
			subjects[c.Kind] = append(subjects[c.Kind], c.Subject)
		}
		for _, k := range kinds {
			// An empty list must be passed as an empty array: a nil slice reaches SQL as NULL, "subject = ANY(NULL)" is
			// unknown, and nothing would ever close once the last condition of a kind is gone.
			keep := subjects[k]
			if keep == nil {
				keep = []string{}
			}
			tag, e := tx.Exec(ctx, `UPDATE alerts SET resolved_at=$3 WHERE kind=$1 AND resolved_at IS NULL AND NOT (subject = ANY($2::text[]))`, k, keep, now)
			if e != nil {
				return e
			}
			closed += int(tag.RowsAffected())
		}
		var n int
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM alerts WHERE opened_at = $1 AND resolved_at IS NULL`, now).Scan(&n); e != nil {
			return e
		}
		opened = n
		return nil
	})
	return opened, closed, err
}

// ListAlerts returns alerts of the panels in scope, open first then recent history.
func (s *Store) ListAlerts(ctx context.Context, panelIDs []string, withUnscoped, openOnly bool, limit int) ([]Alert, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rs, err := s.pool.Query(ctx, `SELECT id, panel_id, kind, subject, label, detail, opened_at, last_seen_at, resolved_at FROM alerts
		WHERE (panel_id = ANY($1::uuid[]) OR ($4 AND panel_id IS NULL)) AND ($2 = false OR resolved_at IS NULL)
		ORDER BY (resolved_at IS NULL) DESC, COALESCE(resolved_at, opened_at) DESC LIMIT $3`, uuids(panelIDs), openOnly, limit, withUnscoped)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := []Alert{}
	for rs.Next() {
		var a Alert
		var id uuid.UUID
		var pid *uuid.UUID
		if err := rs.Scan(&id, &pid, &a.Kind, &a.Subject, &a.Label, &a.Detail, &a.OpenedAt, &a.LastSeenAt, &a.ResolvedAt); err != nil {
			return nil, err
		}
		a.ID = id.String()
		if pid != nil {
			a.PanelID = pid.String()
		}
		out = append(out, a)
	}
	return out, rs.Err()
}

func (s *Store) PurgeResolvedAlerts(ctx context.Context, olderThan time.Time) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM alerts WHERE resolved_at IS NOT NULL AND resolved_at < $1`, olderThan)
	return err
}

// AlertSources reads what the evaluator needs, in one place: live agents and non-demo panels.
type AgentState struct {
	AgentID   string
	PanelID   string
	Kind      string
	Name      string
	NodeName  string
	Status    string
	LastSeen  *time.Time
	CreatedAt time.Time
}

func (s *Store) AgentStates(ctx context.Context) ([]AgentState, error) {
	rs, err := s.pool.Query(ctx, `SELECT a.id, a.panel_id, a.kind, COALESCE(a.name,''), n.name, a.status, a.last_seen, a.created_at
		FROM agents a JOIN nodes n ON n.id=a.node_id AND n.panel_id=a.panel_id JOIN panels p ON p.id=a.panel_id
		WHERE a.status <> 'revoked' AND NOT p.demo AND n.removed_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []AgentState
	for rs.Next() {
		var a AgentState
		var id uuid.UUID
		var pid *uuid.UUID
		if err := rs.Scan(&id, &pid, &a.Kind, &a.Name, &a.NodeName, &a.Status, &a.LastSeen, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.AgentID, a.PanelID = id.String(), pid.String()
		out = append(out, a)
	}
	return out, rs.Err()
}

type PanelState struct {
	PanelID  string
	Name     string
	Failures int
	Open     *time.Time
	Status   string
	LastSync *time.Time
}

func (s *Store) PanelStates(ctx context.Context) ([]PanelState, error) {
	rs, err := s.pool.Query(ctx, `SELECT id, name, consecutive_failures, circuit_open_until, status, last_sync_at FROM panels WHERE NOT demo AND status <> 'disabled'`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []PanelState
	for rs.Next() {
		var p PanelState
		var id uuid.UUID
		if err := rs.Scan(&id, &p.Name, &p.Failures, &p.Open, &p.Status, &p.LastSync); err != nil {
			return nil, err
		}
		p.PanelID = id.String()
		out = append(out, p)
	}
	return out, rs.Err()
}
