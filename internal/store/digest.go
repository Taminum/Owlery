package store

import (
	"context"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// EventCount is how many journal events of one type a window holds.
type EventCount struct {
	Type     string `json:"type"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

// SecurityEventCounts groups the journal of every server the scope can see by type, for a window.
func (s *Store) SecurityEventCounts(ctx context.Context, sc Scope, from, to time.Time) ([]EventCount, error) {
	pred, args := vpsVisible(sc, 0)
	n := len(args)
	args = append(args, from, to)
	rows, err := s.pool.Query(ctx, `SELECT e.type, e.category, max(e.severity), count(*) FROM security_events e JOIN security_vps v ON v.id = e.vps_id
		WHERE `+pred+` AND e.observed_at >= $`+strconv.Itoa(n+1)+` AND e.observed_at < $`+strconv.Itoa(n+2)+`
		GROUP BY e.type, e.category ORDER BY count(*) DESC, e.type`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EventCount{}
	for rows.Next() {
		var c EventCount
		if err := rows.Scan(&c.Type, &c.Category, &c.Severity, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// NewDevice is a device behind a router that was not seen before the window began.
type NewDevice struct {
	PanelID string    `json:"panel_id"`
	IP      string    `json:"ip"`
	Name    string    `json:"name"`
	First   time.Time `json:"first_seen"`
	Bytes   int64     `json:"bytes"`
}

// NewDevices lists devices whose first connection on record falls inside the window. History older than the
// retention is gone, so a window longer than the retention is not asked for.
//
// It never reads the table through: the devices are few and the records are millions, so it walks the
// (panel, device, time) index from one device to the next, asks the same index for each one's first record, and
// only then reads the records of those that turn out to be new.
func (s *Store) NewDevices(ctx context.Context, panelIDs []string, from, to time.Time) ([]NewDevice, error) {
	rows, err := s.pool.Query(ctx, `WITH RECURSIVE p AS (SELECT unnest($1::uuid[]) AS panel_id),
		d AS (
			SELECT p.panel_id, (SELECT min(c.device_ip) FROM device_connections c WHERE c.panel_id = p.panel_id) AS ip FROM p
			UNION ALL
			SELECT d.panel_id, (SELECT min(c.device_ip) FROM device_connections c WHERE c.panel_id = d.panel_id AND c.device_ip > d.ip) FROM d WHERE d.ip IS NOT NULL
		),
		f AS (
			SELECT d.panel_id, d.ip, (SELECT min(c.started_at) FROM device_connections c WHERE c.panel_id = d.panel_id AND c.device_ip = d.ip) AS first
			FROM d WHERE d.ip IS NOT NULL
		)
		SELECT f.panel_id, host(f.ip),
			COALESCE((SELECT c.device_name FROM device_connections c WHERE c.panel_id = f.panel_id AND c.device_ip = f.ip AND c.device_name IS NOT NULL ORDER BY c.started_at DESC LIMIT 1), ''),
			f.first,
			(SELECT COALESCE(sum(c.up_bytes + c.down_bytes), 0) FROM device_connections c WHERE c.panel_id = f.panel_id AND c.device_ip = f.ip)
		FROM f WHERE f.first >= $2 AND f.first < $3
		ORDER BY f.first DESC LIMIT 20`, uuids(panelIDs), from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NewDevice{}
	for rows.Next() {
		var d NewDevice
		var pid uuid.UUID
		if err := rows.Scan(&pid, &d.IP, &d.Name, &d.First, &d.Bytes); err != nil {
			return nil, err
		}
		d.PanelID = pid.String()
		out = append(out, d)
	}
	return out, rows.Err()
}

// DNSChangeCount is how many DNS changes were confirmed in a window, and how many of them were on records
// that flip so often they are marked volatile.
type DNSChangeCount struct {
	Total    int `json:"total"`
	Volatile int `json:"volatile"`
	Failed   int `json:"failed_checks"`
}

func (s *Store) DNSChangeCounts(ctx context.Context, from, to time.Time) (DNSChangeCount, error) {
	var c DNSChangeCount
	err := s.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE c.kind <> 'dns.check_failed' AND c.kind <> 'dns.check_recovered'),
			count(*) FILTER (WHERE c.volatile AND c.kind <> 'dns.check_failed' AND c.kind <> 'dns.check_recovered'),
			count(*) FILTER (WHERE c.kind = 'dns.check_failed')
		FROM dns_changes c JOIN dns_maps m ON m.id = c.map_id WHERE m.archived_at IS NULL AND c.observed_at >= $1 AND c.observed_at < $2`, from, to).
		Scan(&c.Total, &c.Volatile, &c.Failed)
	return c, err
}
