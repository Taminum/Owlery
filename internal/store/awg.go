package store

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/Taminum/RemnaScope/internal/ingestproto"
)

var awgKeyRe = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)

// sampleEvery is the longest a peer goes without a stored sample while nothing changes.
const sampleEvery = 10 * time.Minute

// AWGVariant names the parameter set a config uses, from the names of its fields only. It says what
// the config looks like, not which release of Amnezia produced it.
func AWGVariant(fields []string) string {
	has := map[string]bool{}
	for _, f := range fields {
		has[f] = true
	}
	switch {
	case has["I1"] || has["HeaderProtectionKey"]:
		return "AWG 3.x"
	case has["S3"] && has["S4"]:
		return "AWG 2.0"
	case has["Jc"] || has["S1"] || has["H1"]:
		return "AWG 1.x"
	}
	return ""
}

func cleanText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[:n]
		for len(s) > 0 && s[len(s)-1]&0xC0 == 0x80 { // do not cut a character in half
			s = s[:len(s)-1]
		}
	}
	return s
}

// SaveAWG stores one snapshot from an AWG agent: instances and peers are updated, a peer the
// snapshot no longer lists is marked gone (not deleted: its history stays), and a counter sample is
// kept when something changed or the last one is old. Invalid entries are skipped, never an error.
func (s *Store) SaveAWG(ctx context.Context, agent Agent, snap ingestproto.AWG, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	for i, in := range snap.Instances {
		if i >= ingestproto.MaxAWGInstances {
			break
		}
		cont, iface := cleanText(in.Container, 80), cleanText(in.Interface, 40)
		if cont == "" || iface == "" {
			continue
		}
		var startedAt any
		if in.Started > 0 {
			startedAt = time.Unix(in.Started, 0).UTC()
		}
		mode := "read_only"
		if in.Managed {
			mode = "managed"
		}
		var legacyAt any
		if in.LegacyAt > 0 {
			legacyAt = time.Unix(in.LegacyAt, 0).UTC()
		}
		var port any
		if in.Port > 0 && in.Port < 65536 {
			port = in.Port
		}
		var instID string
		if err := tx.QueryRow(ctx, `INSERT INTO awg_instances (agent_id, panel_id, container, interface, listen_port, variant, last_report, started_at, legacy_at, mode)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (agent_id, container, interface) DO UPDATE SET listen_port=EXCLUDED.listen_port,
			  variant=CASE WHEN EXCLUDED.variant <> '' THEN EXCLUDED.variant ELSE awg_instances.variant END, last_report=EXCLUDED.last_report,
			  started_at=COALESCE(EXCLUDED.started_at, awg_instances.started_at),
			  legacy_at=COALESCE(awg_instances.legacy_at, EXCLUDED.legacy_at), mode=EXCLUDED.mode
			RETURNING id`, agent.ID, agent.PanelID, cont, iface, port, AWGVariant(in.Fields), now, startedAt, legacyAt, mode).Scan(&instID); err != nil {
			return err
		}
		var keys []string
		for j, p := range in.Peers {
			if j >= ingestproto.MaxAWGPeers {
				break
			}
			if !awgKeyRe.MatchString(p.Key) || p.RX < 0 || p.TX < 0 || p.Handshake < 0 {
				continue
			}
			keys = append(keys, p.Key)
			var peerID string
			var lDown, lUp, lHS, created any
			if p.Created > 0 {
				created = time.Unix(p.Created, 0).UTC()
			}
			if p.LegacyDown > 0 || p.LegacyUp > 0 || p.LegacyHS > 0 {
				lDown, lUp = p.LegacyDown, p.LegacyUp
				if p.LegacyHS > 0 {
					lHS = time.Unix(p.LegacyHS, 0).UTC()
				}
			}
			if err := tx.QueryRow(ctx, `INSERT INTO awg_peers (instance_id, public_key, label, tunnel_ip, last_seen, legacy_down, legacy_up, legacy_hs, created_hint)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
				ON CONFLICT (instance_id, public_key) DO UPDATE SET
				  legacy_down=COALESCE(awg_peers.legacy_down, EXCLUDED.legacy_down),
				  legacy_up=COALESCE(awg_peers.legacy_up, EXCLUDED.legacy_up),
				  legacy_hs=COALESCE(awg_peers.legacy_hs, EXCLUDED.legacy_hs),
				  created_hint=COALESCE(awg_peers.created_hint, EXCLUDED.created_hint),
				  label=CASE WHEN EXCLUDED.label <> '' THEN EXCLUDED.label ELSE awg_peers.label END,
				  tunnel_ip=CASE WHEN EXCLUDED.tunnel_ip <> '' THEN EXCLUDED.tunnel_ip ELSE awg_peers.tunnel_ip END,
				  last_seen=EXCLUDED.last_seen, gone_at=NULL
				RETURNING id`, instID, p.Key, cleanText(p.Name, 64), cleanText(p.IP, 64), now, lDown, lUp, lHS, created).Scan(&peerID); err != nil {
				return err
			}
			var hs any
			if p.Handshake > 0 {
				hs = time.Unix(p.Handshake, 0).UTC()
			}
			// Keep a sample when it is the first, when a number changed, or when the last one is old.
			if _, err := tx.Exec(ctx, `INSERT INTO awg_samples (peer_id, ts, rx_bytes, tx_bytes, handshake)
				SELECT $1, $2, $3, $4, $5
				WHERE NOT EXISTS (SELECT 1 FROM (SELECT * FROM awg_samples WHERE peer_id=$1 ORDER BY ts DESC LIMIT 1) l
				                  WHERE l.rx_bytes=$3 AND l.tx_bytes=$4 AND l.handshake IS NOT DISTINCT FROM $5::timestamptz
				                    AND l.ts > $2::timestamptz - make_interval(secs => $6))
				ON CONFLICT DO NOTHING`, peerID, now, p.RX, p.TX, hs, sampleEvery.Seconds()); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE awg_peers SET gone_at=$2 WHERE instance_id=$1 AND gone_at IS NULL AND public_key <> ALL($3::text[])`, instID, now, keys); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

type AWGPeerRow struct {
	ID          string
	Key         string
	Label       string
	TunnelIP    string
	FirstSeen   time.Time
	LastSeen    time.Time
	Gone        bool
	RX, TX      int64 // totals since the interface came up, as last read
	Handshake   *time.Time
	SampleAt    *time.Time
	PeriodRX    int64 // traffic in the asked period, resets accounted for
	PeriodTX    int64
	TrackedRX   int64 // everything RemnaScope has seen since its first sample of this peer, resets accounted for
	TrackedTX   int64
	TrackedFrom *time.Time // when that first sample was taken
	EverHS      *time.Time // the latest handshake RemnaScope has ever recorded for the peer
	LegacyDown  *int64     // what the Amnezia panel had recorded (a snapshot as of the instance's LegacyAt)
	LegacyUp    *int64
	LegacyHS    *time.Time
	CreatedHint *time.Time // when the device was created, as the old table recorded it
}

type AWGInstanceRow struct {
	ID         string
	PanelID    string
	AgentName  string
	Container  string
	Interface  string
	Port       int
	Variant    string
	Mode       string
	LastReport time.Time
	Started    *time.Time // the counters run from about this moment
	LegacyAt   *time.Time // when the Amnezia panel last wrote the totals shown as legacy
	Peers      []AWGPeerRow
}

// AWGInstances lists the instances (with their peers) of the panels in scope. period is the window
// over which the per-peer traffic is summed.
func (s *Store) AWGInstances(ctx context.Context, sc Scope, period time.Duration) ([]AWGInstanceRow, error) {
	rs, err := s.pool.Query(ctx, `SELECT i.id, i.panel_id, COALESCE(a.name,''), i.container, i.interface, COALESCE(i.listen_port,0), i.variant, i.mode, i.last_report, i.started_at, i.legacy_at
		FROM awg_instances i JOIN agents a ON a.id=i.agent_id JOIN panels p ON p.id=i.panel_id
		WHERE ($1::bool OR i.panel_id = ANY($2::uuid[])) AND a.status <> 'revoked' ORDER BY i.container, i.interface`, sc.All, scopeIDs(sc))
	if err != nil {
		return nil, err
	}
	var out []AWGInstanceRow
	byID := map[string]int{}
	for rs.Next() {
		var r AWGInstanceRow
		if err := rs.Scan(&r.ID, &r.PanelID, &r.AgentName, &r.Container, &r.Interface, &r.Port, &r.Variant, &r.Mode, &r.LastReport, &r.Started, &r.LegacyAt); err != nil {
			rs.Close()
			return nil, err
		}
		r.Peers = []AWGPeerRow{}
		byID[r.ID] = len(out)
		out = append(out, r)
	}
	rs.Close()
	if err := rs.Err(); err != nil || len(out) == 0 {
		return out, err
	}
	pr, err := s.pool.Query(ctx, `
WITH last AS (
  SELECT DISTINCT ON (peer_id) peer_id, ts, rx_bytes, tx_bytes, handshake FROM awg_samples ORDER BY peer_id, ts DESC
), win AS (
  SELECT peer_id, ts,
         CASE WHEN rx_bytes >= lag(rx_bytes) OVER w THEN rx_bytes - lag(rx_bytes) OVER w WHEN lag(rx_bytes) OVER w IS NULL THEN 0 ELSE rx_bytes END AS drx,
         CASE WHEN tx_bytes >= lag(tx_bytes) OVER w THEN tx_bytes - lag(tx_bytes) OVER w WHEN lag(tx_bytes) OVER w IS NULL THEN 0 ELSE tx_bytes END AS dtx
  FROM awg_samples WHERE ts >= now() - make_interval(secs => $1) - interval '1 hour'
  WINDOW w AS (PARTITION BY peer_id ORDER BY ts)
), per AS (
  SELECT peer_id, sum(drx) AS rx, sum(dtx) AS tx FROM win WHERE ts >= now() - make_interval(secs => $1) GROUP BY peer_id
), allw AS (
  SELECT peer_id, ts,
         CASE WHEN lag(rx_bytes) OVER w IS NULL THEN rx_bytes WHEN rx_bytes >= lag(rx_bytes) OVER w THEN rx_bytes - lag(rx_bytes) OVER w ELSE rx_bytes END AS drx,
         CASE WHEN lag(tx_bytes) OVER w IS NULL THEN tx_bytes WHEN tx_bytes >= lag(tx_bytes) OVER w THEN tx_bytes - lag(tx_bytes) OVER w ELSE tx_bytes END AS dtx
  FROM awg_samples WHERE peer_id IN (SELECT id FROM awg_peers WHERE instance_id = ANY($2::uuid[]))
  WINDOW w AS (PARTITION BY peer_id ORDER BY ts)
), trk AS (
  SELECT peer_id, sum(drx) AS rx, sum(dtx) AS tx, min(ts) AS since FROM allw GROUP BY peer_id
), ever AS (
  SELECT peer_id, max(handshake) AS hs FROM awg_samples WHERE handshake IS NOT NULL
    AND peer_id IN (SELECT id FROM awg_peers WHERE instance_id = ANY($2::uuid[])) GROUP BY peer_id
)
SELECT p.instance_id, p.id, p.public_key, p.label, p.tunnel_ip, p.first_seen, p.last_seen, p.gone_at IS NOT NULL,
       COALESCE(l.rx_bytes,0), COALESCE(l.tx_bytes,0), l.handshake, l.ts, COALESCE(per.rx,0), COALESCE(per.tx,0),
       COALESCE(trk.rx,0), COALESCE(trk.tx,0), trk.since, ever.hs, p.legacy_down, p.legacy_up, p.legacy_hs, p.created_hint
FROM awg_peers p LEFT JOIN last l ON l.peer_id=p.id LEFT JOIN per ON per.peer_id=p.id LEFT JOIN trk ON trk.peer_id=p.id LEFT JOIN ever ON ever.peer_id=p.id
WHERE p.instance_id = ANY($2::uuid[]) ORDER BY p.gone_at IS NOT NULL, p.label, p.first_seen`, period.Seconds(), idsOf(out))
	if err != nil {
		return nil, err
	}
	defer pr.Close()
	for pr.Next() {
		var inst string
		var p AWGPeerRow
		if err := pr.Scan(&inst, &p.ID, &p.Key, &p.Label, &p.TunnelIP, &p.FirstSeen, &p.LastSeen, &p.Gone, &p.RX, &p.TX, &p.Handshake, &p.SampleAt, &p.PeriodRX, &p.PeriodTX, &p.TrackedRX, &p.TrackedTX, &p.TrackedFrom, &p.EverHS, &p.LegacyDown, &p.LegacyUp, &p.LegacyHS, &p.CreatedHint); err != nil {
			return nil, err
		}
		i := byID[inst]
		out[i].Peers = append(out[i].Peers, p)
	}
	return out, pr.Err()
}

func idsOf(rows []AWGInstanceRow) []string {
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	return ids
}

func scopeIDs(sc Scope) []string {
	if sc.All {
		return []string{}
	}
	return sc.IDs
}

type AWGPoint struct {
	TS   time.Time
	RX   int64 // received from the peer in the bucket
	TX   int64 // sent to the peer in the bucket
	Seen bool  // at least one sample fell into the bucket: a bucket without one is "no data", not zero
}

// AWGSeries returns traffic per bucket for one peer, resets accounted for. The peer must belong to
// an instance in scope.
func (s *Store) AWGSeries(ctx context.Context, sc Scope, peerID string, from, to time.Time, bucket time.Duration) ([]AWGPoint, error) {
	pid, err := ParseID(peerID)
	if err != nil {
		return nil, ErrNotFound
	}
	var ok bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM awg_peers p JOIN awg_instances i ON i.id=p.instance_id
		WHERE p.id=$1 AND ($2::bool OR i.panel_id = ANY($3::uuid[])))`, pid, sc.All, scopeIDs(sc)).Scan(&ok); err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotFound
	}
	rs, err := s.pool.Query(ctx, `
WITH win AS (
  SELECT ts,
         CASE WHEN rx_bytes >= lag(rx_bytes) OVER w THEN rx_bytes - lag(rx_bytes) OVER w WHEN lag(rx_bytes) OVER w IS NULL THEN 0 ELSE rx_bytes END AS drx,
         CASE WHEN tx_bytes >= lag(tx_bytes) OVER w THEN tx_bytes - lag(tx_bytes) OVER w WHEN lag(tx_bytes) OVER w IS NULL THEN 0 ELSE tx_bytes END AS dtx
  FROM awg_samples WHERE peer_id=$1 AND ts >= $2::timestamptz - interval '1 hour' AND ts < $3
  WINDOW w AS (ORDER BY ts)
)
SELECT date_bin(make_interval(secs => $4), ts, $2::timestamptz), sum(drx), sum(dtx) FROM win WHERE ts >= $2 GROUP BY 1 ORDER BY 1`, pid, from, to, bucket.Seconds())
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []AWGPoint
	for rs.Next() {
		var p AWGPoint
		if err := rs.Scan(&p.TS, &p.RX, &p.TX); err != nil {
			return nil, err
		}
		p.Seen = true
		out = append(out, p)
	}
	return out, rs.Err()
}

// DeleteGoneAWGPeer removes a peer that is no longer on the server, with its history. A peer that is
// still listed by the interface cannot be removed here.
func (s *Store) DeleteGoneAWGPeer(ctx context.Context, sc Scope, peerID string) error {
	pid, err := ParseID(peerID)
	if err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM awg_peers p USING awg_instances i
		WHERE p.id=$1 AND p.instance_id=i.id AND p.gone_at IS NOT NULL AND ($2::bool OR i.panel_id = ANY($3::uuid[]))`, pid, sc.All, scopeIDs(sc))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AWGInstanceTarget says which agent and container an instance belongs to, if it is in scope.
func (s *Store) AWGInstanceTarget(ctx context.Context, sc Scope, instanceID string) (agentID, container, mode string, err error) {
	id, perr := ParseID(instanceID)
	if perr != nil {
		return "", "", "", ErrNotFound
	}
	err = s.pool.QueryRow(ctx, `SELECT i.agent_id::text, i.container, i.mode FROM awg_instances i WHERE i.id=$1 AND ($2::bool OR i.panel_id = ANY($3::uuid[]))`,
		id, sc.All, scopeIDs(sc)).Scan(&agentID, &container, &mode)
	if err != nil {
		return "", "", "", ErrNotFound
	}
	return
}

// AWGPeerTarget says which agent, container and public key a peer belongs to, if it is in scope.
func (s *Store) AWGPeerTarget(ctx context.Context, sc Scope, peerID string) (instanceID, agentID, container, mode, key, label string, gone bool, err error) {
	id, perr := ParseID(peerID)
	if perr != nil {
		return "", "", "", "", "", "", false, ErrNotFound
	}
	err = s.pool.QueryRow(ctx, `SELECT i.id::text, i.agent_id::text, i.container, i.mode, p.public_key, p.label, p.gone_at IS NOT NULL
		FROM awg_peers p JOIN awg_instances i ON i.id=p.instance_id WHERE p.id=$1 AND ($2::bool OR i.panel_id = ANY($3::uuid[]))`,
		id, sc.All, scopeIDs(sc)).Scan(&instanceID, &agentID, &container, &mode, &key, &label, &gone)
	if err != nil {
		return "", "", "", "", "", "", false, ErrNotFound
	}
	return
}

// RecordAWGAdd stores a device that was just added on the host, with the name it was given, so that it is
// listed at once under that name. The host's own snapshot confirms it a moment later.
func (s *Store) RecordAWGAdd(ctx context.Context, instanceID, key, ip, label string) error {
	id, err := ParseID(instanceID)
	if err != nil {
		return ErrNotFound
	}
	if !awgKeyRe.MatchString(key) {
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO awg_peers (instance_id, public_key, label, tunnel_ip, created_hint) VALUES ($1,$2,$3,$4,now())
		ON CONFLICT (instance_id, public_key) DO UPDATE SET label=EXCLUDED.label, tunnel_ip=CASE WHEN EXCLUDED.tunnel_ip <> '' THEN EXCLUDED.tunnel_ip ELSE awg_peers.tunnel_ip END, gone_at=NULL`,
		id, key, cleanText(label, 64), cleanText(ip, 64))
	return err
}

// MarkAWGGone marks a device revoked on the host. Its history stays until it is forgotten.
func (s *Store) MarkAWGGone(ctx context.Context, peerID string) error {
	id, err := ParseID(peerID)
	if err != nil {
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `UPDATE awg_peers SET gone_at=now() WHERE id=$1 AND gone_at IS NULL`, id)
	return err
}

// RenameAWGPeer changes the name RemnaScope shows for a device. Nothing is changed on the host.
func (s *Store) RenameAWGPeer(ctx context.Context, sc Scope, peerID, label string) error {
	id, err := ParseID(peerID)
	if err != nil {
		return ErrNotFound
	}
	label = cleanText(label, 64)
	if label == "" {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE awg_peers p SET label=$2 FROM awg_instances i WHERE p.id=$1 AND i.id=p.instance_id AND ($3::bool OR i.panel_id = ANY($4::uuid[]))`,
		id, label, sc.All, scopeIDs(sc))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordAWGOperation writes the audit row of a change request. It never holds a configuration.
func (s *Store) RecordAWGOperation(ctx context.Context, instanceID, kind, key, label, status, code, by string) error {
	var inst, u any
	if id, err := ParseID(instanceID); err == nil {
		inst = id
	}
	if id, err := ParseID(by); err == nil {
		u = id
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO awg_operations (instance_id, kind, public_key, label, status, error_code, requested_by) VALUES ($1,$2,NULLIF($3,''),NULLIF($4,''),$5,NULLIF($6,''),$7)`,
		inst, kind, key, cleanText(label, 64), status, cleanText(code, 40), u)
	return err
}
