package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TorrentRetention is how long reports are kept.
const TorrentRetention = 35 * 24 * time.Hour

// TorrentRow is one report of the torrent blocker.
type TorrentRow struct {
	RemoteID   int64
	RemoteUser string
	Node       string
	At         time.Time
}

// AddTorrentReports stores the reports of a panel that are not stored yet and says how many were new.
func (s *Store) AddTorrentReports(ctx context.Context, panelID string, recs []TorrentRow) (int64, error) {
	if len(recs) == 0 {
		return 0, nil
	}
	pid, err := uuid.Parse(panelID)
	if err != nil {
		return 0, err
	}
	ids, users, nodes, ats := make([]int64, len(recs)), make([]string, len(recs)), make([]string, len(recs)), make([]time.Time, len(recs))
	for i, r := range recs {
		ids[i], users[i], nodes[i], ats[i] = r.RemoteID, r.RemoteUser, r.Node, r.At
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO torrent_reports (panel_id, remote_id, remote_user, node, reported_at)
		SELECT $1, * FROM unnest($2::bigint[], $3::text[], $4::text[], $5::timestamptz[])
		ON CONFLICT (panel_id, remote_id) DO NOTHING`, pid, ids, users, nodes, ats)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PruneTorrentReports drops what is older than the retention.
func (s *Store) PruneTorrentReports(ctx context.Context, now time.Time) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM torrent_reports WHERE reported_at < $1`, now.Add(-TorrentRetention))
	return err
}

// Torrent is one subscription caught by the torrent blocker within a period.
type Torrent struct {
	PanelID    string
	RemoteUser string
	Name       string
	Reports    int
	Nodes      []string
	Last       time.Time
	Recent     int // reports in the last day of the period
}

// Torrents lists the subscriptions of the panels in scope caught between from and to, the most reports first. A
// subscription with at least minReports is returned.
func (s *Store) Torrents(ctx context.Context, sc Scope, from, to time.Time, minReports, limit int) ([]Torrent, error) {
	pred, args := sc.predicate("r.panel_id", 0)
	n := len(args)
	args = append(args, from, to, minReports, limit)
	rows, err := s.pool.Query(ctx, `SELECT r.panel_id, r.remote_user, COALESCE(MAX(u.display_name), ''), COUNT(*),
			COALESCE(array_agg(DISTINCT r.node) FILTER (WHERE r.node <> ''), '{}'), MAX(r.reported_at),
			COUNT(*) FILTER (WHERE r.reported_at >= $`+itoa(n+2)+`::timestamptz - interval '1 day')
		FROM torrent_reports r
		JOIN panels p ON p.id = r.panel_id AND NOT p.demo AND p.status <> 'disabled'
		LEFT JOIN users u ON u.panel_id = r.panel_id AND u.remote_uuid = r.remote_user AND u.removed_at IS NULL
		WHERE `+pred+` AND r.reported_at >= $`+itoa(n+1)+` AND r.reported_at < $`+itoa(n+2)+`
		GROUP BY r.panel_id, r.remote_user
		HAVING COUNT(*) >= $`+itoa(n+3)+`
		ORDER BY 4 DESC, 6 DESC, 2 LIMIT $`+itoa(n+4), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Torrent{}
	for rows.Next() {
		var x Torrent
		var pid uuid.UUID
		if err := rows.Scan(&pid, &x.RemoteUser, &x.Name, &x.Reports, &x.Nodes, &x.Last, &x.Recent); err != nil {
			return nil, err
		}
		x.PanelID = pid.String()
		out = append(out, x)
	}
	return out, rows.Err()
}

// ReplaceDevices makes the device counts of a panel match what it reports now.
func (s *Store) ReplaceDevices(ctx context.Context, panelID string, counts map[string]int, now time.Time) error {
	pid, err := uuid.Parse(panelID)
	if err != nil {
		return err
	}
	users, ns := make([]string, 0, len(counts)), make([]int32, 0, len(counts))
	for u, c := range counts {
		users, ns = append(users, u), append(ns, int32(c))
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `DELETE FROM subscription_devices WHERE panel_id = $1`, pid); e != nil {
			return e
		}
		if len(users) == 0 {
			return nil
		}
		_, e := tx.Exec(ctx, `INSERT INTO subscription_devices (panel_id, remote_user, devices, seen_at)
			SELECT $1, u, n, $4 FROM unnest($2::text[], $3::int[]) AS t(u, n)`, pid, users, ns, now)
		return e
	})
}

// DeviceCount is how many devices a subscription has.
type DeviceCount struct {
	PanelID    string
	RemoteUser string
	Name       string
	Devices    int
	IPs        int // different addresses the subscription was asked for from within the period
}

// DeviceCounts lists the subscriptions of the panels in scope that have at least minDevices devices, the most first,
// with the number of addresses they were asked for from between from and to.
func (s *Store) DeviceCounts(ctx context.Context, sc Scope, from, to time.Time, minDevices, limit int) ([]DeviceCount, error) {
	pred, args := sc.predicate("d.panel_id", 0)
	n := len(args)
	args = append(args, from, to, minDevices, limit)
	rows, err := s.pool.Query(ctx, `SELECT d.panel_id, d.remote_user, COALESCE(MAX(u.display_name), ''), MAX(d.devices),
			COALESCE((SELECT COUNT(DISTINCT r.ip) FROM subscription_requests r WHERE r.panel_id = d.panel_id AND r.remote_user = d.remote_user
				AND r.ip <> '' AND r.requested_at >= $`+itoa(n+1)+` AND r.requested_at < $`+itoa(n+2)+`), 0)
		FROM subscription_devices d
		JOIN panels p ON p.id = d.panel_id AND NOT p.demo AND p.status <> 'disabled'
		LEFT JOIN users u ON u.panel_id = d.panel_id AND u.remote_uuid = d.remote_user AND u.removed_at IS NULL
		WHERE `+pred+`
		GROUP BY d.panel_id, d.remote_user
		HAVING MAX(d.devices) >= $`+itoa(n+3)+`
		ORDER BY 4 DESC, 2 LIMIT $`+itoa(n+4), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeviceCount{}
	for rows.Next() {
		var x DeviceCount
		var pid uuid.UUID
		if err := rows.Scan(&pid, &x.RemoteUser, &x.Name, &x.Devices, &x.IPs); err != nil {
			return nil, err
		}
		x.PanelID = pid.String()
		out = append(out, x)
	}
	return out, rows.Err()
}

// ProtectionSeen says whether the panels in scope have reported any torrent report or device at all: it tells a page
// "the plugin is off or nothing happened" from a page with something to show.
func (s *Store) ProtectionSeen(ctx context.Context, sc Scope) (torrents, devices int, err error) {
	pred, args := sc.predicate("t.panel_id", 0)
	if err = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM torrent_reports t WHERE `+pred, args...).Scan(&torrents); err != nil {
		return
	}
	pred, args = sc.predicate("d.panel_id", 0)
	err = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM subscription_devices d WHERE `+pred, args...).Scan(&devices)
	return
}
