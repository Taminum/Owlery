package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Taminum/Owlery/internal/secevents"
)

// TLSDiscoveryPorts are the ports on which a known listener is tried for TLS. Nothing outside this list is
// handshaken with: a handshake sent to an SSH or SMTP port only fills that service's log with complaints.
var TLSDiscoveryPorts = []int{443, 8443, 9443, 4443, 7443, 2053, 2083, 2087, 2096, 993, 995, 465, 636, 853, 8883}

// TLSRetry is how long a candidate that was tried is left alone before it is tried again.
const TLSRetry = 3 * 24 * time.Hour

// TLSCandidate is a place where a certificate may be found: a registered domain on 443, or a listener
// that is already known and answers, on a well-known TLS port.
type TLSCandidate struct {
	VPSID string
	Host  string
	Port  int
	// Ref is how the candidate is marked as tried: a port endpoint id for a listener, empty for a domain.
	Ref string
}

// TLSCandidates lists up to limit candidates that are not yet a TLS endpoint and were not tried lately.
func (s *Store) TLSCandidates(ctx context.Context, now time.Time, limit int) ([]TLSCandidate, error) {
	cut := now.Add(-TLSRetry)
	rows, err := s.pool.Query(ctx, `
		(SELECT v.id, a.address, 443, ''
		   FROM security_vps_addresses a JOIN security_vps v ON v.id = a.vps_id
		  WHERE a.kind = 'domain' AND v.enabled AND v.archived_at IS NULL AND (a.tls_probed_at IS NULL OR a.tls_probed_at < $1)
		    AND NOT EXISTS (SELECT 1 FROM security_tls_endpoints t WHERE t.vps_id = v.id AND t.host = a.address AND t.port = 443))
		UNION ALL
		(SELECT e.vps_id, e.host, e.port, e.id::text
		   FROM security_port_endpoints e JOIN security_vps v ON v.id = e.vps_id
		  WHERE e.enabled AND e.last_result = 'reachable' AND e.port = ANY($2) AND v.enabled AND v.archived_at IS NULL
		    AND (e.tls_probed_at IS NULL OR e.tls_probed_at < $1)
		    AND NOT EXISTS (SELECT 1 FROM security_tls_endpoints t WHERE t.vps_id = e.vps_id AND t.host = e.host AND t.port = e.port))
		LIMIT $3`, cut, TLSDiscoveryPorts, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TLSCandidate
	for rows.Next() {
		var c TLSCandidate
		var vid uuid.UUID
		if err := rows.Scan(&vid, &c.Host, &c.Port, &c.Ref); err != nil {
			return nil, err
		}
		c.VPSID = vid.String()
		out = append(out, c)
	}
	return out, rows.Err()
}

// MarkTLSTried records that a candidate was handshaken with, whatever came of it.
func (s *Store) MarkTLSTried(ctx context.Context, c TLSCandidate, now time.Time) error {
	if c.Ref != "" {
		_, err := s.pool.Exec(ctx, `UPDATE security_port_endpoints SET tls_probed_at=$2 WHERE id=$1`, uuid.MustParse(c.Ref), now)
		return err
	}
	_, err := s.pool.Exec(ctx, `UPDATE security_vps_addresses SET tls_probed_at=$3 WHERE vps_id=$1 AND address=$2`, uuid.MustParse(c.VPSID), c.Host, now)
	return err
}

// AddAutoTLSEndpoint adds an endpoint a handshake confirmed, once. It reports whether one was added, and
// writes a journal event for it. The server's own limit on endpoints still holds.
func (s *Store) AddAutoTLSEndpoint(ctx context.Context, c TLSCandidate, state string, now time.Time, v Vantage) (bool, error) {
	vid := uuid.MustParse(c.VPSID)
	added := false
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM security_tls_endpoints WHERE vps_id=$1`, vid).Scan(&n); err != nil {
			return err
		}
		if n >= MaxTLSEndpoints {
			return nil
		}
		tag, err := tx.Exec(ctx, `INSERT INTO security_tls_endpoints (vps_id, host, port, sni, source) VALUES ($1,$2,$3,'','auto') ON CONFLICT DO NOTHING`, vid, c.Host, c.Port)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		added = true
		return insertEvents(ctx, tx, vid, []secevents.Event{{Category: "tls", Type: "tls.discovered", Severity: secevents.SevInfo, Key: c.Host + "|" + itoa(c.Port),
			Payload: map[string]any{"host": c.Host, "port": c.Port, "state": state, "source": "external_check"}}}, now, v)
	})
	return added, err
}

// ScanTarget is a server that opted in to the scan and whose turn has come.
type ScanTarget struct {
	VPSID     string
	Addresses []string // registered IP addresses only; a domain is never scanned
}

// ScanEvery is how often an opted-in server is scanned.
const ScanEvery = 24 * time.Hour

func (s *Store) ScanTargets(ctx context.Context, now time.Time, limit int) ([]ScanTarget, error) {
	rows, err := s.pool.Query(ctx, `SELECT v.id, COALESCE((SELECT array_agg(a.address ORDER BY a.address) FROM security_vps_addresses a WHERE a.vps_id = v.id AND a.kind IN ('ipv4','ipv6')), '{}')
		FROM security_vps v WHERE v.discovery_scan AND v.enabled AND v.archived_at IS NULL AND (v.discovery_scan_at IS NULL OR v.discovery_scan_at < $1)
		ORDER BY v.discovery_scan_at NULLS FIRST LIMIT $2`, now.Add(-ScanEvery), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanTarget
	for rows.Next() {
		var t ScanTarget
		var id uuid.UUID
		if err := rows.Scan(&id, &t.Addresses); err != nil {
			return nil, err
		}
		t.VPSID = id.String()
		out = append(out, t)
	}
	return out, rows.Err()
}

// ScanFound is a port that answered during a scan.
type ScanFound struct {
	Host string
	Port int
	IP   string
}

// RecordScan stores that a scan ran and adds what answered as port endpoints that are not expected, once each.
// It returns the ones that were new. A port that is already an endpoint is left exactly as it is.
func (s *Store) RecordScan(ctx context.Context, vpsID string, now time.Time, found []ScanFound, v Vantage) ([]ScanFound, error) {
	vid := uuid.MustParse(vpsID)
	var fresh []ScanFound
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE security_vps SET discovery_scan_at=$2 WHERE id=$1`, vid, now); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM security_port_endpoints WHERE vps_id=$1`, vid).Scan(&n); err != nil {
			return err
		}
		for _, f := range found {
			if n >= MaxPortEndpoints {
				break
			}
			// A port number the server already has an endpoint for (under any of its names) is known, not new.
			tag, err := tx.Exec(ctx, `INSERT INTO security_port_endpoints (vps_id, host, port, expected, source, last_checked_at, last_result, last_ip, changed_at, last_vantage, last_vantage_name, last_independent)
				SELECT $1::uuid,$2::text,$3::int,false,'discovered',$4::timestamptz,'reachable',NULLIF($5::text,''),$4::timestamptz,$6::text,NULLIF($7::text,''),$8::boolean
				WHERE NOT EXISTS (SELECT 1 FROM security_port_endpoints WHERE vps_id=$1 AND port=$3)
				ON CONFLICT (vps_id, host, port) DO NOTHING`,
				vid, f.Host, f.Port, now, f.IP, v.ID, v.Name, v.Independent)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				continue
			}
			n++
			fresh = append(fresh, f)
			if err := insertEvents(ctx, tx, vid, []secevents.Event{{Category: "ports", Type: "port.discovered", Severity: secevents.SevWarning, Key: f.Host + "|" + itoa(f.Port),
				Payload: map[string]any{"host": f.Host, "port": f.Port, "ip": f.IP, "expected": false, "source": "external_check"}}}, now, v); err != nil {
				return err
			}
		}
		return nil
	})
	return fresh, err
}
