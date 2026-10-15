package store

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SecurityRetention is how long detailed security history is kept: events, snapshots that recorded a
// change, and certificate observations. Analytics tables and the audit log are not touched by it.
const SecurityRetention = 180 * 24 * time.Hour

// JournalFilter narrows the all-servers journal. Zero values mean "any".
type JournalFilter struct {
	ID       string // one event, by id
	VPSID    string
	Category string
	Type     string
	Severity string
	Query    string // a substring of the event's details: an IP, a jail, a host or a port
	From, To *time.Time
	BeforeTS *time.Time
	BeforeID string
	Limit    int
}

// JournalEvent is an event with the name of the server it belongs to.
type JournalEvent struct {
	SecEvent
	VPSName string `json:"vps_name"`
}

// Journal returns events of every server the scope can see, newest first, with a stable tie-breaker.
func (s *Store) Journal(ctx context.Context, sc Scope, f JournalFilter) ([]JournalEvent, error) {
	pred, args := vpsVisible(sc, 0)
	n := len(args)
	where := []string{pred}
	add := func(cond string, v any) {
		n++
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "$#", "$"+strconv.Itoa(n)))
	}
	if f.ID != "" {
		u, err := uuid.Parse(f.ID)
		if err != nil {
			return []JournalEvent{}, nil
		}
		add("e.id = $#", u)
	}
	if u, err := uuid.Parse(f.VPSID); err == nil {
		add("e.vps_id = $#", u)
	} else if f.VPSID != "" {
		return []JournalEvent{}, nil
	}
	if f.Category != "" {
		add("e.category = $#", f.Category)
	}
	if f.Type != "" {
		add("e.type = $#", f.Type)
	}
	if f.Severity != "" {
		add("e.severity = $#", f.Severity)
	}
	if f.Query != "" {
		add(`e.payload::text ILIKE $# ESCAPE '\'`, "%"+likeEscape(f.Query)+"%")
	}
	if f.From != nil {
		add("e.observed_at >= $#", *f.From)
	}
	if f.To != nil {
		add("e.observed_at < $#", *f.To)
	}
	if f.BeforeTS != nil {
		id := uuid.Max
		if u, err := uuid.Parse(f.BeforeID); err == nil {
			id = u
		}
		n += 2
		args = append(args, *f.BeforeTS, id)
		where = append(where, "(e.observed_at, e.id) < ($"+strconv.Itoa(n-1)+"::timestamptz, $"+strconv.Itoa(n)+"::uuid)")
	}
	n++
	args = append(args, f.Limit)
	rows, err := s.pool.Query(ctx, `SELECT e.id, e.vps_id, v.name, e.category, e.type, e.severity, e.source, e.observed_at, e.received_at, e.payload
		FROM security_events e JOIN security_vps v ON v.id = e.vps_id WHERE `+strings.Join(where, " AND ")+
		` ORDER BY e.observed_at DESC, e.id DESC LIMIT $`+strconv.Itoa(n), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []JournalEvent{}
	for rows.Next() {
		var e JournalEvent
		var id, vid uuid.UUID
		var p []byte
		if err := rows.Scan(&id, &vid, &e.VPSName, &e.Category, &e.Type, &e.Severity, &e.Source, &e.ObservedAt, &e.ReceivedAt, &p); err != nil {
			return nil, err
		}
		e.ID, e.VPSID, e.Payload = id.String(), vid.String(), p
		out = append(out, e)
	}
	return out, rows.Err()
}

// PurgeSecurity deletes detailed security history older than the retention, in small batches so that a
// large backlog never holds a long lock. It returns how many rows went.
func (s *Store) PurgeSecurity(ctx context.Context, now time.Time) (int64, error) {
	cut := now.Add(-SecurityRetention)
	var total int64
	for _, q := range []string{
		`DELETE FROM security_events WHERE ctid IN (SELECT ctid FROM security_events WHERE observed_at < $1 LIMIT 5000)`,
		`DELETE FROM security_snapshots WHERE ctid IN (SELECT ctid FROM security_snapshots WHERE received_at < $1 LIMIT 5000)`,
		`DELETE FROM security_tls_observations WHERE ctid IN (SELECT ctid FROM security_tls_observations WHERE observed_at < $1 LIMIT 5000)`,
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

// --- what the alert evaluator reads ---------------------------------------------------------------

type SecAgentAlert struct {
	AgentID  string
	VPSName  string
	PanelID  string // the server's first linked panel, or ""
	LastSeen *time.Time
}

type SecTLSAlert struct {
	EndpointID string
	VPSName    string
	PanelID    string
	Host       string
	Port       int
	State      string
	NotAfter   *time.Time
}

type SecPortAlert struct {
	EndpointID      string
	VPSName         string
	PanelID         string
	Host            string
	Port            int
	Expected        bool
	Result          string
	UnexpectedSince *time.Time
}

type SecAlertStates struct {
	Agents []SecAgentAlert
	TLS    []SecTLSAlert
	Ports  []SecPortAlert
}

const firstPanel = `COALESCE((SELECT l.panel_id::text FROM security_vps_links l WHERE l.vps_id = v.id ORDER BY l.created_at, l.id LIMIT 1), '')`

// SecurityAlertStates reads the live state of every enabled server for the alert evaluator.
func (s *Store) SecurityAlertStates(ctx context.Context) (SecAlertStates, error) {
	var out SecAlertStates
	rows, err := s.pool.Query(ctx, `SELECT a.id, v.name, `+firstPanel+`, a.last_seen FROM security_agents a JOIN security_vps v ON v.id=a.vps_id
		WHERE a.status='active' AND v.enabled AND v.archived_at IS NULL`)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var x SecAgentAlert
		var id uuid.UUID
		if err := rows.Scan(&id, &x.VPSName, &x.PanelID, &x.LastSeen); err != nil {
			rows.Close()
			return out, err
		}
		x.AgentID = id.String()
		out.Agents = append(out.Agents, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}

	rows, err = s.pool.Query(ctx, `SELECT e.id, v.name, `+firstPanel+`, e.host, e.port, e.last_state, e.last_not_after FROM security_tls_endpoints e JOIN security_vps v ON v.id=e.vps_id
		WHERE e.enabled AND v.enabled AND v.archived_at IS NULL AND e.last_state IS NOT NULL`)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var x SecTLSAlert
		var id uuid.UUID
		if err := rows.Scan(&id, &x.VPSName, &x.PanelID, &x.Host, &x.Port, &x.State, &x.NotAfter); err != nil {
			rows.Close()
			return out, err
		}
		x.EndpointID = id.String()
		out.TLS = append(out.TLS, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}

	rows, err = s.pool.Query(ctx, `SELECT e.id, v.name, `+firstPanel+`, e.host, e.port, e.expected, e.last_result, e.unexpected_since FROM security_port_endpoints e JOIN security_vps v ON v.id=e.vps_id
		WHERE e.enabled AND v.enabled AND v.archived_at IS NULL AND e.last_result IS NOT NULL`)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var x SecPortAlert
		var id uuid.UUID
		if err := rows.Scan(&id, &x.VPSName, &x.PanelID, &x.Host, &x.Port, &x.Expected, &x.Result, &x.UnexpectedSince); err != nil {
			return out, err
		}
		x.EndpointID = id.String()
		out.Ports = append(out.Ports, x)
	}
	return out, rows.Err()
}

// FWSnapshot is one stored reading of the firewall: written only when the rules or the verdict changed.
type FWSnapshot struct {
	ID         string    `json:"id"`
	ObservedAt time.Time `json:"observed_at"`
	ReceivedAt time.Time `json:"received_at"`
	Status     string    `json:"status"`
	Hash       string    `json:"hash"`
	Backend    string    `json:"backend"`
	Rules      string    `json:"-"`
}

// FirewallSnapshots returns a server's stored firewall readings, newest first.
func (s *Store) FirewallSnapshots(ctx context.Context, sc Scope, vpsID string, limit int, withRules bool) ([]FWSnapshot, error) {
	if _, err := s.GetVPS(ctx, sc, vpsID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT id, observed_at, received_at, status, source_hash, COALESCE(data->>'backend',''), CASE WHEN $3 THEN COALESCE(data->>'rules','') ELSE '' END
		FROM security_snapshots WHERE vps_id=$1 AND category='firewall' ORDER BY observed_at DESC, id DESC LIMIT $2`, uuid.MustParse(vpsID), limit, withRules)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FWSnapshot{}
	for rows.Next() {
		var x FWSnapshot
		var id uuid.UUID
		if err := rows.Scan(&id, &x.ObservedAt, &x.ReceivedAt, &x.Status, &x.Hash, &x.Backend, &x.Rules); err != nil {
			return nil, err
		}
		x.ID = id.String()
		out = append(out, x)
	}
	return out, rows.Err()
}

// FirewallSnapshot returns one stored reading with its rules text.
func (s *Store) FirewallSnapshot(ctx context.Context, sc Scope, vpsID, id string) (FWSnapshot, error) {
	if _, err := s.GetVPS(ctx, sc, vpsID); err != nil {
		return FWSnapshot{}, err
	}
	u, err := ParseID(id)
	if err != nil {
		return FWSnapshot{}, ErrNotFound
	}
	var x FWSnapshot
	var sid uuid.UUID
	err = s.pool.QueryRow(ctx, `SELECT id, observed_at, received_at, status, source_hash, COALESCE(data->>'backend',''), COALESCE(data->>'rules','')
		FROM security_snapshots WHERE id=$1 AND vps_id=$2 AND category='firewall'`, u, uuid.MustParse(vpsID)).
		Scan(&sid, &x.ObservedAt, &x.ReceivedAt, &x.Status, &x.Hash, &x.Backend, &x.Rules)
	if errors.Is(err, pgx.ErrNoRows) {
		return FWSnapshot{}, ErrNotFound
	}
	x.ID = sid.String()
	return x, err
}
