package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// RollupUptime counts, per machine and per day (UTC), how many minute samples came in over the last eight days and keeps the
// larger count: the samples themselves are purged after a week, the day totals stay.
func (s *Store) RollupUptime(ctx context.Context, now time.Time) error {
	from := now.UTC().AddDate(0, 0, -8)
	_, err := s.pool.Exec(ctx, `INSERT INTO host_uptime_days (vps_id, day, minutes)
		SELECT vps_id, (at AT TIME ZONE 'UTC')::date, LEAST(count(*), 1440)::int FROM host_samples WHERE at >= $1 GROUP BY 1, 2
		ON CONFLICT (vps_id, day) DO UPDATE SET minutes = GREATEST(host_uptime_days.minutes, EXCLUDED.minutes)`, from)
	return err
}

// UptimeDay is one day of a machine's availability. Of is how many minutes of that day had passed (1440, or fewer for today).
type UptimeDay struct {
	Day     string `json:"day"`
	Minutes int    `json:"minutes"`
	Of      int    `json:"of"`
}

// Availability gives the last thirty days of one machine, oldest first, from the first day anything was recorded for it.
// A machine with nothing recorded gets an empty list.
func (s *Store) Availability(ctx context.Context, sc Scope, vpsID string, now time.Time) ([]UptimeDay, error) {
	vid, err := ParseID(vpsID)
	if err != nil {
		return nil, ErrNotFound
	}
	pred, args := vpsVisible(sc, 1)
	var ok bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM security_vps v WHERE v.id=$1 AND v.archived_at IS NULL AND `+pred+`)`, append([]any{vid}, args...)...).Scan(&ok); err != nil || !ok {
		return nil, ErrNotFound
	}
	now = now.UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	rows, err := s.pool.Query(ctx, `SELECT day, minutes FROM host_uptime_days WHERE vps_id=$1 AND day > $2 ORDER BY day`, uuid.UUID(vid), today.AddDate(0, 0, -30))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	got := map[string]int{}
	var first time.Time
	for rows.Next() {
		var d time.Time
		var m int
		if err := rows.Scan(&d, &m); err != nil {
			return nil, err
		}
		if first.IsZero() {
			first = d
		}
		got[d.Format("2006-01-02")] = m
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := []UptimeDay{}
	if first.IsZero() {
		return out, nil
	}
	for d := time.Date(first.Year(), first.Month(), first.Day(), 0, 0, 0, 0, time.UTC); !d.After(today); d = d.AddDate(0, 0, 1) {
		of := 1440
		if d.Equal(today) {
			of = max(1, int(now.Sub(today).Minutes()))
		}
		key := d.Format("2006-01-02")
		out = append(out, UptimeDay{Day: key, Minutes: min(got[key], of), Of: of})
	}
	return out, nil
}
