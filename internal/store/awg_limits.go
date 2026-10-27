package store

import (
	"context"
	"time"
)

// AWGLimits is a device's expiry and traffic allowance, with what has been used of the allowance so far.
type AWGLimits struct {
	ExpiresAt         *time.Time
	TrafficLimitBytes *int64
	LimitFrom         *time.Time
	UsedBytes         int64 // download plus upload since LimitFrom
	AutoRevokedReason string
}

// SetAWGPeerLimits sets (or, with nil, clears) a device's expiry and traffic limit. A new or changed traffic
// limit starts counting from now. It only acts on a device that is still on the host.
func (s *Store) SetAWGPeerLimits(ctx context.Context, sc Scope, peerID string, expires *time.Time, limit *int64, now time.Time) error {
	id, err := ParseID(peerID)
	if err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE awg_peers p SET expires_at=$2, traffic_limit_bytes=$3,
			limit_from = CASE WHEN $3::bigint IS NULL THEN NULL WHEN p.traffic_limit_bytes IS DISTINCT FROM $3::bigint OR p.limit_from IS NULL THEN $4::timestamptz ELSE p.limit_from END
		FROM awg_instances i WHERE p.id=$1 AND i.id=p.instance_id AND p.gone_at IS NULL AND ($5::bool OR i.panel_id = ANY($6::uuid[]))`,
		id, expires, limit, now, sc.All, scopeIDs(sc))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AWGLimitDue is a device whose time or allowance is over and that is still on a managed server.
type AWGLimitDue struct {
	PeerID, InstanceID, AgentID, Container, Key, Label string
	Reason                                             string // expired | traffic_limit
}

// AWGLimitsDue lists the devices that have to be revoked now.
func (s *Store) AWGLimitsDue(ctx context.Context, now time.Time) ([]AWGLimitDue, error) {
	rows, err := s.pool.Query(ctx, `
WITH used AS (
  SELECT x.peer_id, sum(x.drx + x.dtx) AS bytes FROM (
    SELECT s.peer_id, s.ts,
           CASE WHEN lag(s.rx_bytes) OVER w IS NULL THEN 0 WHEN s.rx_bytes >= lag(s.rx_bytes) OVER w THEN s.rx_bytes - lag(s.rx_bytes) OVER w ELSE s.rx_bytes END AS drx,
           CASE WHEN lag(s.tx_bytes) OVER w IS NULL THEN 0 WHEN s.tx_bytes >= lag(s.tx_bytes) OVER w THEN s.tx_bytes - lag(s.tx_bytes) OVER w ELSE s.tx_bytes END AS dtx
    FROM awg_samples s
    WHERE s.peer_id IN (SELECT id FROM awg_peers WHERE traffic_limit_bytes IS NOT NULL AND gone_at IS NULL)
    WINDOW w AS (PARTITION BY s.peer_id ORDER BY s.ts)
  ) x JOIN awg_peers p ON p.id = x.peer_id WHERE x.ts >= p.limit_from GROUP BY x.peer_id
)
SELECT p.id::text, i.id::text, i.agent_id::text, i.container, p.public_key, p.label,
       CASE WHEN p.expires_at IS NOT NULL AND p.expires_at <= $1 THEN 'expired' ELSE 'traffic_limit' END
FROM awg_peers p JOIN awg_instances i ON i.id = p.instance_id LEFT JOIN used u ON u.peer_id = p.id
WHERE p.gone_at IS NULL AND i.mode = 'managed'
  AND ((p.expires_at IS NOT NULL AND p.expires_at <= $1)
       OR (p.traffic_limit_bytes IS NOT NULL AND COALESCE(u.bytes, 0) >= p.traffic_limit_bytes))`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AWGLimitDue
	for rows.Next() {
		var d AWGLimitDue
		if err := rows.Scan(&d.PeerID, &d.InstanceID, &d.AgentID, &d.Container, &d.Key, &d.Label, &d.Reason); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// MarkAWGAutoRevoked records that Owlery revoked the device because its time or allowance was over.
func (s *Store) MarkAWGAutoRevoked(ctx context.Context, peerID, reason string) error {
	id, err := ParseID(peerID)
	if err != nil {
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `UPDATE awg_peers SET gone_at=COALESCE(gone_at, now()), auto_revoked_reason=$2 WHERE id=$1`, id, reason)
	return err
}

// AWGPeerLimits returns the limits of the devices of the given instances, with the traffic used so far.
func (s *Store) AWGPeerLimits(ctx context.Context, instanceIDs []string) (map[string]AWGLimits, error) {
	rows, err := s.pool.Query(ctx, `
WITH d AS (
  SELECT s.peer_id, s.ts,
         CASE WHEN lag(s.rx_bytes) OVER w IS NULL THEN 0 WHEN s.rx_bytes >= lag(s.rx_bytes) OVER w THEN s.rx_bytes - lag(s.rx_bytes) OVER w ELSE s.rx_bytes END AS drx,
         CASE WHEN lag(s.tx_bytes) OVER w IS NULL THEN 0 WHEN s.tx_bytes >= lag(s.tx_bytes) OVER w THEN s.tx_bytes - lag(s.tx_bytes) OVER w ELSE s.tx_bytes END AS dtx
  FROM awg_samples s
  WHERE s.peer_id IN (SELECT id FROM awg_peers WHERE instance_id = ANY($1::uuid[]) AND traffic_limit_bytes IS NOT NULL)
  WINDOW w AS (PARTITION BY s.peer_id ORDER BY s.ts)
)
SELECT p.id::text, p.expires_at, p.traffic_limit_bytes, p.limit_from, COALESCE(p.auto_revoked_reason, ''),
       COALESCE((SELECT sum(d.drx + d.dtx) FROM d WHERE d.peer_id = p.id AND d.ts >= p.limit_from), 0)
FROM awg_peers p WHERE p.instance_id = ANY($1::uuid[])
  AND (p.expires_at IS NOT NULL OR p.traffic_limit_bytes IS NOT NULL OR p.auto_revoked_reason IS NOT NULL)`, uuids(instanceIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]AWGLimits{}
	for rows.Next() {
		var id string
		var l AWGLimits
		if err := rows.Scan(&id, &l.ExpiresAt, &l.TrafficLimitBytes, &l.LimitFrom, &l.AutoRevokedReason, &l.UsedBytes); err != nil {
			return nil, err
		}
		out[id] = l
	}
	return out, rows.Err()
}
