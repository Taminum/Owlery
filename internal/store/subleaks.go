package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// SubRequest is one subscription request the panel reported.
type SubRequest struct {
	RemoteID   int64
	RemoteUser string
	At         time.Time
	IP         string
	Agent      string
}

// SubscriptionRetention is how long requests are kept: the page looks back a month at most.
const SubscriptionRetention = 35 * 24 * time.Hour

// AddSubscriptionRequests stores the requests of a panel that are not stored yet and says how many were new.
func (s *Store) AddSubscriptionRequests(ctx context.Context, panelID string, recs []SubRequest) (int64, error) {
	if len(recs) == 0 {
		return 0, nil
	}
	pid, err := uuid.Parse(panelID)
	if err != nil {
		return 0, err
	}
	ids, users, ats, ips, agents := make([]int64, len(recs)), make([]string, len(recs)), make([]time.Time, len(recs)), make([]string, len(recs)), make([]string, len(recs))
	for i, r := range recs {
		ids[i], users[i], ats[i], ips[i], agents[i] = r.RemoteID, r.RemoteUser, r.At, r.IP, r.Agent
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO subscription_requests (panel_id, remote_id, remote_user, requested_at, ip, user_agent)
		SELECT $1, * FROM unnest($2::bigint[], $3::text[], $4::timestamptz[], $5::text[], $6::text[])
		ON CONFLICT (panel_id, remote_id) DO NOTHING`, pid, ids, users, ats, ips, agents)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PruneSubscriptionRequests drops what is older than the retention.
func (s *Store) PruneSubscriptionRequests(ctx context.Context, now time.Time) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM subscription_requests WHERE requested_at < $1`, now.Add(-SubscriptionRetention))
	return err
}

// SubLeak is one subscription (one user of a panel) and from where it was asked for within a period.
type SubLeak struct {
	PanelID    string
	RemoteUser string
	Name       string // the user's name when the panel has told it, else empty
	IPs        int    // different addresses
	IPsBefore  int    // different addresses before the last day of the period
	Requests   int
	Last       time.Time
	Agents     []string // every user agent seen, as the panel sent it
}

// SubLeaks lists the subscriptions of the panels in scope that were asked for from at least minIPs different addresses
// between from and to, the ones with most addresses first.
func (s *Store) SubLeaks(ctx context.Context, sc Scope, from, to time.Time, minIPs, limit int) ([]SubLeak, error) {
	pred, args := sc.predicate("r.panel_id", 0)
	n := len(args)
	args = append(args, from, to, minIPs, limit)
	rows, err := s.pool.Query(ctx, `SELECT r.panel_id, r.remote_user, COALESCE(MAX(u.display_name), ''),
			COUNT(DISTINCT r.ip) FILTER (WHERE r.ip <> ''),
			COUNT(DISTINCT r.ip) FILTER (WHERE r.ip <> '' AND r.requested_at < $`+itoa(n+2)+`::timestamptz - interval '1 day'),
			COUNT(*), MAX(r.requested_at), array_agg(DISTINCT r.user_agent) FILTER (WHERE r.user_agent <> '')
		FROM subscription_requests r
		JOIN panels p ON p.id = r.panel_id AND NOT p.demo AND p.status <> 'disabled'
		LEFT JOIN users u ON u.panel_id = r.panel_id AND u.remote_uuid = r.remote_user AND u.removed_at IS NULL
		WHERE `+pred+` AND r.requested_at >= $`+itoa(n+1)+` AND r.requested_at < $`+itoa(n+2)+`
		GROUP BY r.panel_id, r.remote_user
		HAVING COUNT(DISTINCT r.ip) FILTER (WHERE r.ip <> '') >= $`+itoa(n+3)+`
		ORDER BY 4 DESC, 7 DESC, 2 LIMIT $`+itoa(n+4), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SubLeak{}
	for rows.Next() {
		var x SubLeak
		var pid uuid.UUID
		if err := rows.Scan(&pid, &x.RemoteUser, &x.Name, &x.IPs, &x.IPsBefore, &x.Requests, &x.Last, &x.Agents); err != nil {
			return nil, err
		}
		x.PanelID = pid.String()
		out = append(out, x)
	}
	return out, rows.Err()
}

// SubscriptionsAsked is how many subscriptions were asked for at all within a period, in the panels in scope.
func (s *Store) SubscriptionsAsked(ctx context.Context, sc Scope, from, to time.Time) (int, error) {
	pred, args := sc.predicate("r.panel_id", 0)
	n := len(args)
	args = append(args, from, to)
	var c int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM (SELECT 1 FROM subscription_requests r
		JOIN panels p ON p.id = r.panel_id AND NOT p.demo AND p.status <> 'disabled'
		WHERE `+pred+` AND r.requested_at >= $`+itoa(n+1)+` AND r.requested_at < $`+itoa(n+2)+`
		GROUP BY r.panel_id, r.remote_user) t`, args...).Scan(&c)
	return c, err
}

// SubLeakIP is one address a subscription was asked for from.
type SubLeakIP struct {
	IP       string
	Requests int
	Last     time.Time
	Agent    string // the one used most often from this address
}

// SubLeakIPs lists the addresses one subscription was asked for from, the busiest first.
func (s *Store) SubLeakIPs(ctx context.Context, panelID, remoteUser string, from, to time.Time) ([]SubLeakIP, error) {
	pid, err := uuid.Parse(panelID)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT ip, COUNT(*), MAX(requested_at), mode() WITHIN GROUP (ORDER BY user_agent)
		FROM subscription_requests
		WHERE panel_id = $1 AND remote_user = $2 AND ip <> '' AND requested_at >= $3 AND requested_at < $4
		GROUP BY ip ORDER BY 2 DESC, 3 DESC, 1 LIMIT 100`, pid, remoteUser, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SubLeakIP{}
	for rows.Next() {
		var x SubLeakIP
		if err := rows.Scan(&x.IP, &x.Requests, &x.Last, &x.Agent); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
