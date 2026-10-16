package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// UserLimitState is what the alerts need to know about an active user of a panel.
type UserLimitState struct {
	PanelID    string
	UserID     string
	Username   string
	ExpireAt   *time.Time
	LimitBytes *int64
	UsedBytes  *int64
}

// UserLimitStates lists the users that the panel reports as active and that have an end date or a limit.
// Users in any other status are left out: a disabled, expired or limited user is already known to the panel.
func (s *Store) UserLimitStates(ctx context.Context) ([]UserLimitState, error) {
	rows, err := s.pool.Query(ctx, `SELECT u.id, u.panel_id, COALESCE(u.display_name, u.remote_uuid), u.expire_at, u.traffic_limit_bytes, u.traffic_used_bytes
		FROM users u JOIN panels p ON p.id = u.panel_id
		WHERE u.removed_at IS NULL AND u.status = 'ACTIVE' AND p.status <> 'disabled' AND NOT p.demo
		  AND (u.expire_at IS NOT NULL OR COALESCE(u.traffic_limit_bytes, 0) > 0)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserLimitState
	for rows.Next() {
		var st UserLimitState
		var id, pid uuid.UUID
		if err := rows.Scan(&id, &pid, &st.Username, &st.ExpireAt, &st.LimitBytes, &st.UsedBytes); err != nil {
			return nil, err
		}
		st.UserID, st.PanelID = id.String(), pid.String()
		out = append(out, st)
	}
	return out, rows.Err()
}

// Subscription is one user of a panel with what the panel allows, for the list on the users page.
type Subscription struct {
	PanelID    string     `json:"panel_id"`
	PanelName  string     `json:"panel_name"`
	Username   string     `json:"username"`
	Status     string     `json:"status"`
	ExpireAt   *time.Time `json:"expire_at"`
	LimitBytes *int64     `json:"traffic_limit_bytes"`
	UsedBytes  *int64     `json:"traffic_used_bytes"`
}

// ListSubscriptions returns the users of the panels in scope, the ones that end soonest first.
func (s *Store) ListSubscriptions(ctx context.Context, sc Scope, limit int) ([]Subscription, error) {
	pred, args := sc.predicate("u.panel_id", 0)
	args = append(args, limit)
	rows, err := s.pool.Query(ctx, `SELECT u.panel_id, p.name, COALESCE(u.display_name, u.remote_uuid), COALESCE(u.status, ''), u.expire_at, u.traffic_limit_bytes, u.traffic_used_bytes
		FROM users u JOIN panels p ON p.id = u.panel_id
		WHERE u.removed_at IS NULL AND `+pred+`
		ORDER BY u.expire_at ASC NULLS LAST, u.display_name LIMIT $`+itoa(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Subscription{}
	for rows.Next() {
		var x Subscription
		var pid uuid.UUID
		if err := rows.Scan(&pid, &x.PanelName, &x.Username, &x.Status, &x.ExpireAt, &x.LimitBytes, &x.UsedBytes); err != nil {
			return nil, err
		}
		x.PanelID = pid.String()
		out = append(out, x)
	}
	return out, rows.Err()
}
