package store

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// DeviceRow is one LAN device seen by a router agent. Bytes are the counters sing-box kept on
// the router for each connection, so they are real traffic (unlike the exit nodes' log lines).
type DeviceRow struct {
	PanelID      string
	IP           netip.Addr
	Name         string
	Connections  int
	Destinations int
	NoDomain     int // connections with no sniffed domain
	Up, Down     int64
	First, Last  time.Time
}

const dScope = `d.panel_id = ANY($1::uuid[]) AND d.started_at >= $2 AND d.started_at < $3`

func (s *Store) DevicesAnalytics(ctx context.Context, q AnalyticsQuery) ([]DeviceRow, error) {
	rs, err := s.pool.Query(ctx, `SELECT d.panel_id, d.device_ip, COALESCE((array_agg(d.device_name ORDER BY d.started_at DESC) FILTER (WHERE d.device_name IS NOT NULL))[1], ''),
			count(*), count(DISTINCT COALESCE(d.destination_host, host(d.destination_ip))),
			count(*) FILTER (WHERE d.destination_host IS NULL), COALESCE(sum(d.up_bytes),0), COALESCE(sum(d.down_bytes),0),
			min(d.started_at), max(d.updated_at)
		FROM device_connections d WHERE `+dScope+` GROUP BY d.panel_id, d.device_ip
		ORDER BY sum(d.up_bytes + d.down_bytes) DESC, count(*) DESC, 2 LIMIT 200`, uuids(q.PanelIDs), q.From, q.To)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := []DeviceRow{}
	for rs.Next() {
		var r DeviceRow
		var pid uuid.UUID
		if err := rs.Scan(&pid, &r.IP, &r.Name, &r.Connections, &r.Destinations, &r.NoDomain, &r.Up, &r.Down, &r.First, &r.Last); err != nil {
			return nil, err
		}
		r.PanelID = pid.String()
		out = append(out, r)
	}
	return out, rs.Err()
}

type DeviceHost struct {
	Key         string
	Service     string
	Connections int
	Up, Down    int64
}

type DevicePoint struct {
	TS          time.Time
	Connections int
	Up, Down    int64
}

type DeviceDetail struct {
	Name        string
	Connections int
	Up, Down    int64
	Hosts       []DeviceHost
	Timeline    []DevicePoint
}

// DeviceDetailFor returns the top destinations (domain, else IP) with their service and the
// activity over time for one device of one panel.
func (s *Store) DeviceDetailFor(ctx context.Context, q AnalyticsQuery, panelID string, ip netip.Addr) (DeviceDetail, error) {
	var d DeviceDetail
	pid, err := ParseID(panelID)
	if err != nil {
		return d, ErrNotFound
	}
	err = s.pool.QueryRow(ctx, `SELECT COALESCE((array_agg(device_name ORDER BY started_at DESC) FILTER (WHERE device_name IS NOT NULL))[1], ''),
			count(*), COALESCE(sum(up_bytes),0), COALESCE(sum(down_bytes),0)
		FROM device_connections WHERE panel_id=$1 AND device_ip=$2 AND started_at >= $3 AND started_at < $4`,
		pid, ip, q.From, q.To).Scan(&d.Name, &d.Connections, &d.Up, &d.Down)
	if err != nil {
		return d, err
	}
	hs, err := s.pool.Query(ctx, `
WITH ev AS (
  SELECT COALESCE(destination_host, host(destination_ip)) AS key, destination_host AS host, up_bytes, down_bytes
  FROM device_connections WHERE panel_id=$1 AND device_ip=$2 AND started_at >= $3 AND started_at < $4
), hosts AS (SELECT DISTINCT host FROM ev WHERE host IS NOT NULL)
SELECT ev.key, COALESCE(max(r.service), ''), count(*), sum(ev.up_bytes), sum(ev.down_bytes)
FROM ev LEFT JOIN LATERAL (SELECT sr.service FROM service_rules sr
      WHERE sr.enabled AND ev.host IS NOT NULL AND (ev.host = sr.pattern OR ev.host LIKE '%.' || sr.pattern)
      ORDER BY length(sr.pattern) DESC LIMIT 1) r ON TRUE
GROUP BY ev.key ORDER BY sum(ev.up_bytes + ev.down_bytes) DESC, count(*) DESC, ev.key LIMIT 30`, pid, ip, q.From, q.To)
	if err != nil {
		return d, err
	}
	defer hs.Close()
	d.Hosts = []DeviceHost{}
	for hs.Next() {
		var h DeviceHost
		if err := hs.Scan(&h.Key, &h.Service, &h.Connections, &h.Up, &h.Down); err != nil {
			return d, err
		}
		d.Hosts = append(d.Hosts, h)
	}
	if err := hs.Err(); err != nil {
		return d, err
	}
	gran := q.Granularity
	if gran <= 0 {
		gran = time.Hour
	}
	ts, err := s.pool.Query(ctx, `SELECT to_timestamp(floor(extract(epoch FROM started_at) / $5) * $5) AS b, count(*), sum(up_bytes), sum(down_bytes)
		FROM device_connections WHERE panel_id=$1 AND device_ip=$2 AND started_at >= $3 AND started_at < $4 GROUP BY 1 ORDER BY 1`,
		pid, ip, q.From, q.To, gran.Seconds())
	if err != nil {
		return d, err
	}
	defer ts.Close()
	d.Timeline = []DevicePoint{}
	for ts.Next() {
		var p DevicePoint
		if err := ts.Scan(&p.TS, &p.Connections, &p.Up, &p.Down); err != nil {
			return d, err
		}
		d.Timeline = append(d.Timeline, p)
	}
	return d, ts.Err()
}

// HasRouterAgent reports whether any of the panels has a live router agent, to tell "no router
// connected" from "connected, nothing seen yet".
func (s *Store) HasRouterAgent(ctx context.Context, panelIDs []string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agents WHERE panel_id = ANY($1::uuid[]) AND kind='router' AND status <> 'revoked')`, uuids(panelIDs)).Scan(&ok)
	return ok, err
}

// PurgeExpiredDevices deletes router records past each panel's retention window.
func (s *Store) PurgeExpiredDevices(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM device_connections d USING panels p
		WHERE d.panel_id = p.id AND d.started_at < $1::timestamptz - make_interval(days => p.retention_days)`, now)
	return tag.RowsAffected(), err
}
