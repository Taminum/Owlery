package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Taminum/RemnaScope/internal/secevents"
	"github.com/Taminum/RemnaScope/internal/secproto"
)

const (
	MaxPortEndpoints = 100
	MaxTLSEndpoints  = 50
)

type PortEndpoint struct {
	ID            string     `json:"id"`
	VPSID         string     `json:"vps_id"`
	Host          string     `json:"host"`
	Port          int        `json:"port"`
	Expected      bool       `json:"expected"`
	Source        string     `json:"source"` // manual | local_listener
	Enabled       bool       `json:"enabled"`
	LastCheckedAt *time.Time `json:"last_checked_at"`
	LastResult    *string    `json:"last_result"`
	LastError     *string    `json:"last_error"`
	LastIP        *string    `json:"last_ip"`
	LastRTTMS     *int       `json:"last_rtt_ms"`
	ChangedAt     *time.Time `json:"changed_at"`
}

const portCols = `id, vps_id, host, port, expected, source, enabled, last_checked_at, last_result, last_error, last_ip, last_rtt_ms, changed_at`

func scanPort(r pgx.Row) (PortEndpoint, error) {
	var p PortEndpoint
	var id, vid uuid.UUID
	err := r.Scan(&id, &vid, &p.Host, &p.Port, &p.Expected, &p.Source, &p.Enabled, &p.LastCheckedAt, &p.LastResult, &p.LastError, &p.LastIP, &p.LastRTTMS, &p.ChangedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	p.ID, p.VPSID = id.String(), vid.String()
	return p, err
}

type TLSEndpoint struct {
	ID              string          `json:"id"`
	VPSID           string          `json:"vps_id"`
	Host            string          `json:"host"`
	Port            int             `json:"port"`
	SNI             string          `json:"sni"`
	Profile         string          `json:"profile"`
	Enabled         bool            `json:"enabled"`
	LastCheckedAt   *time.Time      `json:"last_checked_at"`
	LastState       *string         `json:"last_state"`
	LastIP          *string         `json:"last_ip"`
	LastFingerprint *string         `json:"last_fingerprint"`
	LastNotAfter    *time.Time      `json:"last_not_after"`
	LastObs         json.RawMessage `json:"last_obs"`
}

const tlsCols = `id, vps_id, host, port, sni, profile, enabled, last_checked_at, last_state, last_ip, last_fingerprint, last_not_after, last_obs`

func scanTLS(r pgx.Row) (TLSEndpoint, error) {
	var e TLSEndpoint
	var id, vid uuid.UUID
	var obs []byte
	err := r.Scan(&id, &vid, &e.Host, &e.Port, &e.SNI, &e.Profile, &e.Enabled, &e.LastCheckedAt, &e.LastState, &e.LastIP, &e.LastFingerprint, &e.LastNotAfter, &obs)
	if errors.Is(err, pgx.ErrNoRows) {
		return e, ErrNotFound
	}
	e.ID, e.VPSID, e.LastObs = id.String(), vid.String(), obs
	return e, err
}

// hostRegistered reports whether host is an address or domain of the server. External checks aim only at these.
func (s *Store) hostRegistered(ctx context.Context, vid uuid.UUID, host string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM security_vps_addresses WHERE vps_id=$1 AND address=$2)`, vid, host).Scan(&ok)
	return ok, err
}

// ErrHostNotRegistered means the host is not one of the server's registered addresses.
var ErrHostNotRegistered = errors.New("store: host is not registered on this server")

func (s *Store) AddPortEndpoint(ctx context.Context, sc Scope, vpsID, host string, port int, expected bool) (PortEndpoint, error) {
	if _, err := s.GetVPS(ctx, sc, vpsID); err != nil {
		return PortEndpoint{}, err
	}
	vid := uuid.MustParse(vpsID)
	if ok, err := s.hostRegistered(ctx, vid, host); err != nil {
		return PortEndpoint{}, err
	} else if !ok {
		return PortEndpoint{}, ErrHostNotRegistered
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security_port_endpoints WHERE vps_id=$1`, vid).Scan(&n); err != nil {
		return PortEndpoint{}, err
	}
	if n >= MaxPortEndpoints {
		return PortEndpoint{}, ErrLimit
	}
	// An endpoint the listener scan already found becomes the operator's own: it keeps its history.
	return scanPort(s.pool.QueryRow(ctx, `INSERT INTO security_port_endpoints (vps_id, host, port, expected, source) VALUES ($1,$2,$3,$4,'manual')
		ON CONFLICT (vps_id, host, port) DO UPDATE SET expected=EXCLUDED.expected, source='manual', enabled=true, next_due_at=NULL
		RETURNING `+portCols, vid, host, port, expected))
}

func (s *Store) PatchPortEndpoint(ctx context.Context, sc Scope, vpsID, id string, expected, enabled *bool) (PortEndpoint, error) {
	if _, err := s.GetVPS(ctx, sc, vpsID); err != nil {
		return PortEndpoint{}, err
	}
	vid, eid := uuid.MustParse(vpsID), uuid.Nil
	var err error
	if eid, err = ParseID(id); err != nil {
		return PortEndpoint{}, ErrNotFound
	}
	return scanPort(s.pool.QueryRow(ctx, `UPDATE security_port_endpoints SET expected=COALESCE($3, expected), enabled=COALESCE($4, enabled),
		next_due_at = CASE WHEN $4 IS TRUE THEN NULL ELSE next_due_at END
		WHERE id=$2 AND vps_id=$1 RETURNING `+portCols, vid, eid, expected, enabled))
}

func (s *Store) ListPortEndpoints(ctx context.Context, sc Scope, vpsID string) ([]PortEndpoint, error) {
	if _, err := s.GetVPS(ctx, sc, vpsID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+portCols+` FROM security_port_endpoints WHERE vps_id=$1 ORDER BY enabled DESC, port, host`, uuid.MustParse(vpsID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PortEndpoint{}
	for rows.Next() {
		p, err := scanPort(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) AddTLSEndpoint(ctx context.Context, sc Scope, vpsID, host string, port int, sni string) (TLSEndpoint, error) {
	if _, err := s.GetVPS(ctx, sc, vpsID); err != nil {
		return TLSEndpoint{}, err
	}
	vid := uuid.MustParse(vpsID)
	if ok, err := s.hostRegistered(ctx, vid, host); err != nil {
		return TLSEndpoint{}, err
	} else if !ok {
		return TLSEndpoint{}, ErrHostNotRegistered
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security_tls_endpoints WHERE vps_id=$1`, vid).Scan(&n); err != nil {
		return TLSEndpoint{}, err
	}
	if n >= MaxTLSEndpoints {
		return TLSEndpoint{}, ErrLimit
	}
	e, err := scanTLS(s.pool.QueryRow(ctx, `INSERT INTO security_tls_endpoints (vps_id, host, port, sni) VALUES ($1,$2,$3,$4) RETURNING `+tlsCols, vid, host, port, sni))
	if IsUniqueViolation(err) {
		return TLSEndpoint{}, ErrConflict
	}
	return e, err
}

func (s *Store) PatchTLSEndpoint(ctx context.Context, sc Scope, vpsID, id string, enabled *bool) (TLSEndpoint, error) {
	if _, err := s.GetVPS(ctx, sc, vpsID); err != nil {
		return TLSEndpoint{}, err
	}
	eid, err := ParseID(id)
	if err != nil {
		return TLSEndpoint{}, ErrNotFound
	}
	return scanTLS(s.pool.QueryRow(ctx, `UPDATE security_tls_endpoints SET enabled=COALESCE($3, enabled),
		next_due_at = CASE WHEN $3 IS TRUE THEN NULL ELSE next_due_at END WHERE id=$2 AND vps_id=$1 RETURNING `+tlsCols, uuid.MustParse(vpsID), eid, enabled))
}

func (s *Store) ListTLSEndpoints(ctx context.Context, sc Scope, vpsID string) ([]TLSEndpoint, error) {
	if _, err := s.GetVPS(ctx, sc, vpsID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+tlsCols+` FROM security_tls_endpoints WHERE vps_id=$1 ORDER BY enabled DESC, host, port`, uuid.MustParse(vpsID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TLSEndpoint{}
	for rows.Next() {
		e, err := scanTLS(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RequestChecks makes a server's endpoints of one kind due now; the worker picks them up. It returns how many.
func (s *Store) RequestChecks(ctx context.Context, sc Scope, vpsID, kind string) (int, error) {
	if _, err := s.GetVPS(ctx, sc, vpsID); err != nil {
		return 0, err
	}
	table := "security_port_endpoints"
	if kind == "tls" {
		table = "security_tls_endpoints"
	}
	tag, err := s.pool.Exec(ctx, `UPDATE `+table+` SET next_due_at=NULL WHERE vps_id=$1 AND enabled`, uuid.MustParse(vpsID))
	return int(tag.RowsAffected()), err
}

// --- candidates from the agent's listener scan ------------------------------------------------

func isWildcard(a string) bool { return a == "0.0.0.0" || a == "::" }

// SyncPortCandidates keeps the "known endpoints" set in step with what the servers actually listen on: a
// TCP listener that is not on loopback becomes a candidate on each registered address it can answer on. A
// listener that is gone disables its candidate (its history stays). Endpoints the operator added are not touched.
func (s *Store) SyncPortCandidates(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT v.id, st.data FROM security_vps v JOIN security_snapshot_state st ON st.vps_id=v.id AND st.category='sockets'
		WHERE v.archived_at IS NULL AND v.enabled AND st.status='ok'`)
	if err != nil {
		return err
	}
	type item struct {
		vid  uuid.UUID
		data []byte
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.vid, &it.data); err != nil {
			rows.Close()
			return err
		}
		items = append(items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, it := range items {
		var sock secproto.Sockets
		if json.Unmarshal(it.data, &sock) != nil {
			continue
		}
		ar, err := s.pool.Query(ctx, `SELECT address, kind FROM security_vps_addresses WHERE vps_id=$1`, it.vid)
		if err != nil {
			return err
		}
		var addrs []VPSAddress
		for ar.Next() {
			var a VPSAddress
			if err := ar.Scan(&a.Address, &a.Kind); err != nil {
				ar.Close()
				return err
			}
			addrs = append(addrs, a)
		}
		ar.Close()

		want := map[string]bool{}
		for _, l := range sock.Listeners {
			if l.Proto != "tcp" || l.Port < 1 {
				continue
			}
			ip, perr := netip.ParseAddr(l.Addr)
			if perr == nil && ip.IsLoopback() {
				continue
			}
			for _, a := range addrs {
				switch {
				case isWildcard(l.Addr) && (a.Kind == "domain" || (l.Addr == "0.0.0.0" && a.Kind == "ipv4") || (l.Addr == "::" && a.Kind == "ipv6")):
				case !isWildcard(l.Addr) && a.Address == l.Addr:
				default:
					continue
				}
				want[fmt.Sprintf("%s|%d", a.Address, l.Port)] = true
			}
		}
		for k := range want {
			host, port := splitKey(k)
			if _, err := s.pool.Exec(ctx, `INSERT INTO security_port_endpoints (vps_id, host, port, source) VALUES ($1,$2,$3,'local_listener')
				ON CONFLICT (vps_id, host, port) DO UPDATE SET enabled = true WHERE security_port_endpoints.source='local_listener' AND NOT security_port_endpoints.enabled`,
				it.vid, host, port); err != nil {
				return err
			}
		}
		cur, err := s.pool.Query(ctx, `SELECT id, host, port FROM security_port_endpoints WHERE vps_id=$1 AND source='local_listener' AND enabled`, it.vid)
		if err != nil {
			return err
		}
		var stale []uuid.UUID
		for cur.Next() {
			var id uuid.UUID
			var host string
			var port int
			if err := cur.Scan(&id, &host, &port); err != nil {
				cur.Close()
				return err
			}
			if !want[fmt.Sprintf("%s|%d", host, port)] {
				stale = append(stale, id)
			}
		}
		cur.Close()
		if len(stale) > 0 {
			if _, err := s.pool.Exec(ctx, `UPDATE security_port_endpoints SET enabled=false WHERE id = ANY($1)`, stale); err != nil {
				return err
			}
		}
	}
	return nil
}

func splitKey(k string) (string, int) {
	for i := len(k) - 1; i >= 0; i-- {
		if k[i] == '|' {
			var p int
			_, _ = fmt.Sscanf(k[i+1:], "%d", &p)
			return k[:i], p
		}
	}
	return k, 0
}

// --- the worker's side ---------------------------------------------------------------------------

type DuePort struct {
	ID   string
	Host string
	Port int
}

type DueTLS struct {
	ID   string
	Host string
	Port int
	SNI  string
}

// DuePorts lists enabled endpoints of enabled, live servers whose time has come.
func (s *Store) DuePorts(ctx context.Context, now time.Time, limit int) ([]DuePort, error) {
	rows, err := s.pool.Query(ctx, `SELECT e.id, e.host, e.port FROM security_port_endpoints e JOIN security_vps v ON v.id=e.vps_id
		WHERE e.enabled AND v.enabled AND v.archived_at IS NULL AND (e.next_due_at IS NULL OR e.next_due_at <= $1)
		ORDER BY e.next_due_at NULLS FIRST LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DuePort
	for rows.Next() {
		var d DuePort
		var id uuid.UUID
		if err := rows.Scan(&id, &d.Host, &d.Port); err != nil {
			return nil, err
		}
		d.ID = id.String()
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) DueTLS(ctx context.Context, now time.Time, limit int) ([]DueTLS, error) {
	rows, err := s.pool.Query(ctx, `SELECT e.id, e.host, e.port, e.sni FROM security_tls_endpoints e JOIN security_vps v ON v.id=e.vps_id
		WHERE e.enabled AND v.enabled AND v.archived_at IS NULL AND (e.next_due_at IS NULL OR e.next_due_at <= $1)
		ORDER BY e.next_due_at NULLS FIRST LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DueTLS
	for rows.Next() {
		var d DueTLS
		var id uuid.UUID
		if err := rows.Scan(&id, &d.Host, &d.Port, &d.SNI); err != nil {
			return nil, err
		}
		d.ID = id.String()
		out = append(out, d)
	}
	return out, rows.Err()
}

func insertEvents(ctx context.Context, tx pgx.Tx, vid uuid.UUID, evs []secevents.Event, observed time.Time) error {
	for _, e := range evs {
		payload, _ := json.Marshal(e.Payload)
		if _, err := tx.Exec(ctx, `INSERT INTO security_events (vps_id, category, type, severity, source, observed_at, received_at, dedupe_key, payload)
			VALUES ($1,$2,$3,$4,'external_check',$5,$5,$6,$7) ON CONFLICT (vps_id, dedupe_key) DO NOTHING`,
			vid, e.Category, e.Type, e.Severity, observed, e.Type+"|"+e.Key+"|"+observed.Format(time.RFC3339Nano), payload); err != nil {
			return err
		}
	}
	return nil
}

// PortObservation is one finished TCP check.
type PortObservation struct {
	Result string
	IP     string
	RTTms  int
	Error  string
}

// RecordPortCheck stores a result, writes the events the change implies, and schedules the next check.
func (s *Store) RecordPortCheck(ctx context.Context, id string, o PortObservation, now, next time.Time) error {
	eid, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var vid uuid.UUID
		var host string
		var port int
		var expected bool
		var prev *string
		if err := tx.QueryRow(ctx, `SELECT vps_id, host, port, expected, last_result FROM security_port_endpoints WHERE id=$1 FOR UPDATE`, eid).Scan(&vid, &host, &port, &expected, &prev); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		pp := secevents.PortPrev{}
		if prev != nil {
			pp = secevents.PortPrev{Known: true, Result: *prev}
		}
		if err := insertEvents(ctx, tx, vid, secevents.PortDiff(pp, o.Result, expected, host, port, o.IP), now); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE security_port_endpoints SET last_checked_at=$2, next_due_at=$3, last_result=$4, last_error=NULLIF($5,''), last_ip=NULLIF($6,''),
			last_rtt_ms=NULLIF($7,0), changed_at = CASE WHEN last_result IS DISTINCT FROM $4 THEN $2 ELSE changed_at END WHERE id=$1`,
			eid, now, next, o.Result, o.Error, o.IP, o.RTTms)
		return err
	})
}

// TLSObservation is one finished TLS check.
type TLSObservation struct {
	State       string
	IP          string
	HasCert     bool
	Fingerprint string
	NotAfter    time.Time
	DaysLeft    int
	Data        json.RawMessage // the full description kept with the endpoint
}

// RecordTLSCheck stores a result, writes the events it implies (each expiry threshold once, a renewal
// as a renewal), keeps a history row only when the certificate or verdict changed, and schedules the next check.
func (s *Store) RecordTLSCheck(ctx context.Context, id string, o TLSObservation, now, next time.Time) error {
	eid, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var vid uuid.UUID
		var host string
		var port, band int
		var state, fp *string
		var notAfter *time.Time
		if err := tx.QueryRow(ctx, `SELECT vps_id, host, port, last_state, last_fingerprint, last_not_after, last_band FROM security_tls_endpoints WHERE id=$1 FOR UPDATE`, eid).
			Scan(&vid, &host, &port, &state, &fp, &notAfter, &band); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		prev := secevents.TLSPrev{Band: band}
		if state != nil {
			prev.Known, prev.State = true, *state
		}
		if fp != nil {
			prev.Fingerprint = *fp
		}
		if notAfter != nil {
			prev.NotAfter = *notAfter
		}
		// A check that did not reach a certificate leaves what is known about the certificate alone.
		evs, newBand := secevents.TLSDiff(prev, secevents.TLSCur{State: o.State, Fingerprint: o.Fingerprint, DaysLeft: o.DaysLeft, NotAfter: o.NotAfter, HasCert: o.HasCert}, host, port)
		if err := insertEvents(ctx, tx, vid, evs, now); err != nil {
			return err
		}
		changed := !prev.Known || prev.State != o.State || (o.HasCert && prev.Fingerprint != o.Fingerprint)
		if changed {
			if _, err := tx.Exec(ctx, `INSERT INTO security_tls_observations (endpoint_id, observed_at, state, fingerprint, data) VALUES ($1,$2,$3,NULLIF($4,''),$5)`,
				eid, now, o.State, o.Fingerprint, o.Data); err != nil {
				return err
			}
		}
		var na *time.Time
		if o.HasCert {
			na = &o.NotAfter
		}
		_, err := tx.Exec(ctx, `UPDATE security_tls_endpoints SET last_checked_at=$2, next_due_at=$3, last_state=$4, last_ip=NULLIF($5,''),
			last_fingerprint = CASE WHEN $6 <> '' THEN $6 ELSE last_fingerprint END,
			last_not_after = CASE WHEN $7::timestamptz IS NOT NULL THEN $7 ELSE last_not_after END,
			last_band=$8, last_obs=$9 WHERE id=$1`, eid, now, next, o.State, o.IP, o.Fingerprint, na, newBand, o.Data)
		return err
	})
}
