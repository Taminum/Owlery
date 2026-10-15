package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Taminum/RemnaScope/internal/secevents"
	"github.com/Taminum/RemnaScope/internal/secproto"
)

// SecAgent is a security agent as the server sees it.
type SecAgent struct {
	ID           string     `json:"id"`
	VPSID        string     `json:"vps_id"`
	Status       string     `json:"status"` // enrolling | active | revoked
	AgentVersion *string    `json:"agent_version"`
	Hostname     *string    `json:"hostname"`
	Capabilities []string   `json:"capabilities"`
	LastSeen     *time.Time `json:"last_seen"`
	CreatedAt    time.Time  `json:"created_at"`
}

const secAgentCols = `id, vps_id, status, agent_version, hostname, capabilities, last_seen, created_at`

func scanSecAgent(r pgx.Row) (SecAgent, error) {
	var a SecAgent
	var id, vid uuid.UUID
	err := r.Scan(&id, &vid, &a.Status, &a.AgentVersion, &a.Hostname, &a.Capabilities, &a.LastSeen, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	a.ID, a.VPSID = id.String(), vid.String()
	if a.Capabilities == nil {
		a.Capabilities = []string{}
	}
	return a, err
}

// CreateSecAgent enrols the one live agent a VPS may have. The caller has checked the actor's rights.
func (s *Store) CreateSecAgent(ctx context.Context, vpsID, createdBy string, tokenHash []byte) (SecAgent, error) {
	vid, err := ParseID(vpsID)
	if err != nil {
		return SecAgent{}, ErrNotFound
	}
	var by *uuid.UUID
	if u, err := uuid.Parse(createdBy); err == nil {
		by = &u
	}
	id := uuid.New()
	_, err = s.pool.Exec(ctx, `INSERT INTO security_agents (id, vps_id, token_hash, created_by)
		SELECT $1, v.id, $3, $4 FROM security_vps v WHERE v.id=$2 AND v.archived_at IS NULL`, id, vid, tokenHash, by)
	if IsUniqueViolation(err) {
		return SecAgent{}, ErrConflict
	}
	if err != nil {
		return SecAgent{}, err
	}
	return scanSecAgent(s.pool.QueryRow(ctx, `SELECT `+secAgentCols+` FROM security_agents WHERE id=$1`, id))
}

// SecAgentOf returns the live agent of a server, or ErrNotFound when it has none.
func (s *Store) SecAgentOf(ctx context.Context, vpsID string) (SecAgent, error) {
	vid, err := ParseID(vpsID)
	if err != nil {
		return SecAgent{}, ErrNotFound
	}
	return scanSecAgent(s.pool.QueryRow(ctx, `SELECT `+secAgentCols+` FROM security_agents WHERE vps_id=$1 AND status <> 'revoked'`, vid))
}

func (s *Store) RevokeSecAgent(ctx context.Context, vpsID string) error {
	vid, err := ParseID(vpsID)
	if err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE security_agents SET status='revoked', revoked_at=now() WHERE vps_id=$1 AND status <> 'revoked'`, vid)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SecAgentForAuth is the only unscoped read: ingest authenticates by agent id and secret.
func (s *Store) SecAgentForAuth(ctx context.Context, agentID string) (SecAgent, []byte, error) {
	aid, err := ParseID(agentID)
	if err != nil {
		return SecAgent{}, nil, ErrNotFound
	}
	var hash []byte
	if err := s.pool.QueryRow(ctx, `SELECT token_hash FROM security_agents WHERE id=$1`, aid).Scan(&hash); errors.Is(err, pgx.ErrNoRows) {
		return SecAgent{}, nil, ErrNotFound
	} else if err != nil {
		return SecAgent{}, nil, err
	}
	a, err := scanSecAgent(s.pool.QueryRow(ctx, `SELECT `+secAgentCols+` FROM security_agents WHERE id=$1`, aid))
	return a, hash, err
}

// SecAgentHello records a connection and returns the last acknowledged sequence; a new epoch restarts numbering.
func (s *Store) SecAgentHello(ctx context.Context, agentID, epoch, version, hostname string, caps []string) (int64, error) {
	aid, err := ParseID(agentID)
	if err != nil {
		return 0, ErrNotFound
	}
	if caps == nil {
		caps = []string{}
	}
	var ack int64
	err = s.pool.QueryRow(ctx, `UPDATE security_agents SET
			last_ack_seq = CASE WHEN epoch IS DISTINCT FROM $2 THEN 0 ELSE last_ack_seq END,
			epoch=$2, agent_version=$3, hostname=NULLIF($4,''), capabilities=$5, status='active', last_seen=now()
		WHERE id=$1 AND status <> 'revoked' RETURNING last_ack_seq`, aid, epoch, version, hostname, caps).Scan(&ack)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return ack, err
}

func (s *Store) TouchSecAgent(ctx context.Context, agentID string) error {
	aid, err := ParseID(agentID)
	if err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE security_agents SET last_seen=now() WHERE id=$1 AND status <> 'revoked'`, aid)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ErrBadSnapshot means the payload did not validate; the connection should be closed.
var ErrBadSnapshot = errors.New("store: bad snapshot")

// ParseSnapshotData validates and canonicalises a snapshot's data, returning the typed value for diffing,
// the canonical JSON that is stored, and the hash that identifies it. Lists are sorted so that the same
// facts always give the same hash.
func ParseSnapshotData(category, status string, raw json.RawMessage) (secevents.Snap, []byte, string, error) {
	snap := secevents.Snap{Status: status}
	canon := []byte("{}")
	if len(raw) > secproto.MaxDataBytes {
		return snap, nil, "", ErrBadSnapshot
	}
	if status != secproto.StatusOK && len(raw) == 0 {
		return snap, canon, hashOf(status, canon), nil
	}
	dec := func(v any) error {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		return d.Decode(v)
	}
	var err error
	switch category {
	case secproto.CatFail2ban:
		var f secproto.Fail2ban
		if err = dec(&f); err != nil || len(f.Jails) > secproto.MaxJails {
			return snap, nil, "", ErrBadSnapshot
		}
		for i := range f.Jails {
			j := &f.Jails[i]
			if j.Name == "" || len(j.Name) > 64 || len(j.BannedIPs) > secproto.MaxBannedIPs {
				return snap, nil, "", ErrBadSnapshot
			}
			if j.BannedIPs == nil {
				j.BannedIPs = []string{}
			}
			sort.Strings(j.BannedIPs)
		}
		sort.Slice(f.Jails, func(a, b int) bool { return f.Jails[a].Name < f.Jails[b].Name })
		snap.F2B = &f
		canon, err = json.Marshal(f)
	case secproto.CatSockets:
		var k secproto.Sockets
		if err = dec(&k); err != nil || len(k.Listeners) > secproto.MaxListeners {
			return snap, nil, "", ErrBadSnapshot
		}
		for _, l := range k.Listeners {
			if (l.Proto != "tcp" && l.Proto != "udp") || l.Port < 0 || l.Port > 65535 || len(l.Addr) > 64 || len(l.Process) > 64 {
				return snap, nil, "", ErrBadSnapshot
			}
		}
		if k.Listeners == nil {
			k.Listeners = []secproto.Listener{}
		}
		sort.Slice(k.Listeners, func(a, b int) bool {
			x, y := k.Listeners[a], k.Listeners[b]
			if x.Proto != y.Proto {
				return x.Proto < y.Proto
			}
			if x.Port != y.Port {
				return x.Port < y.Port
			}
			return x.Addr < y.Addr
		})
		snap.Sock = &k
		// A changed process name or pid alone is not a change of what is exposed, so it stays out of the hash.
		hashable := make([]secproto.Listener, len(k.Listeners))
		for i, l := range k.Listeners {
			hashable[i] = secproto.Listener{Proto: l.Proto, Addr: l.Addr, Port: l.Port}
		}
		hb, _ := json.Marshal(hashable)
		canon, err = json.Marshal(k)
		if err == nil {
			snap.Hash = hashOf(status, hb)
			return snap, canon, snap.Hash, nil
		}
	case secproto.CatFirewall:
		var w secproto.Firewall
		if err = dec(&w); err != nil || len(w.Rules) > secproto.MaxRulesBytes || len(w.Backend) > 16 {
			return snap, nil, "", ErrBadSnapshot
		}
		snap.FW = &w
		canon, err = json.Marshal(w)
	default:
		return snap, nil, "", ErrBadSnapshot
	}
	if err != nil {
		return snap, nil, "", ErrBadSnapshot
	}
	snap.Hash = hashOf(status, canon)
	return snap, canon, snap.Hash, nil
}

func hashOf(status string, canon []byte) string {
	h := sha256.New()
	h.Write([]byte(status))
	h.Write([]byte{0})
	h.Write(canon)
	return hex.EncodeToString(h.Sum(nil))
}

// SnapshotResult says what a committed snapshot did.
type SnapshotResult struct {
	AckSeq int64
	Stored bool
	Events int
}

// CommitSnapshot stores one snapshot and the events its change implies, atomically. A sequence already
// acknowledged is answered again without being stored a second time. The VPS comes from the agent's
// own row, never from the payload.
func (s *Store) CommitSnapshot(ctx context.Context, agentID string, seq int64, category string, observed time.Time, snap secevents.Snap, canon []byte, hash string, now time.Time) (SnapshotResult, error) {
	aid, err := ParseID(agentID)
	if err != nil {
		return SnapshotResult{}, ErrNotFound
	}
	var res SnapshotResult
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var vid uuid.UUID
		var ack int64
		var status string
		if err := tx.QueryRow(ctx, `SELECT vps_id, last_ack_seq, status FROM security_agents WHERE id=$1 FOR UPDATE`, aid).Scan(&vid, &ack, &status); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if status == "revoked" {
			return ErrNotFound
		}
		res.AckSeq = ack
		if seq <= ack {
			return nil // a repeat
		}

		var prevStatus, prevHash string
		var prevData []byte
		err := tx.QueryRow(ctx, `SELECT status, source_hash, data FROM security_snapshot_state WHERE vps_id=$1 AND category=$2 FOR UPDATE`, vid, category).Scan(&prevStatus, &prevHash, &prevData)
		first := errors.Is(err, pgx.ErrNoRows)
		if err != nil && !first {
			return err
		}
		skew := now.Sub(observed).Milliseconds()
		if _, err := tx.Exec(ctx, `INSERT INTO security_snapshot_state (vps_id, category, status, source_hash, observed_at, received_at, clock_skew_ms, agent_id, data)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (vps_id, category) DO UPDATE SET status=EXCLUDED.status, source_hash=EXCLUDED.source_hash, observed_at=EXCLUDED.observed_at,
				received_at=EXCLUDED.received_at, clock_skew_ms=EXCLUDED.clock_skew_ms, agent_id=EXCLUDED.agent_id, data=EXCLUDED.data`,
			vid, category, snap.Status, hash, observed, now, skew, aid, canon); err != nil {
			return err
		}
		changed := first || prevStatus != snap.Status || prevHash != hash
		if changed {
			if _, err := tx.Exec(ctx, `INSERT INTO security_snapshots (vps_id, category, status, source_hash, observed_at, received_at, data) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
				vid, category, snap.Status, hash, observed, now, canon); err != nil {
				return err
			}
		}
		// The first snapshot of a category is a baseline: it explains nothing yet.
		if changed && !first {
			prev, err := decodeStoredSnap(category, prevStatus, prevHash, prevData)
			if err != nil {
				return err
			}
			for _, e := range secevents.Diff(category, prev, snap) {
				payload, _ := json.Marshal(e.Payload)
				tag, err := tx.Exec(ctx, `INSERT INTO security_events (vps_id, category, type, severity, source, observed_at, received_at, dedupe_key, agent_id, payload)
					VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (vps_id, dedupe_key) DO NOTHING`,
					vid, e.Category, e.Type, e.Severity, secevents.SourceStateDiff, observed, now, e.Type+"|"+e.Key+"|"+hash, aid, payload)
				if err != nil {
					return err
				}
				res.Events += int(tag.RowsAffected())
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE security_agents SET last_ack_seq=$2, last_seen=now() WHERE id=$1`, aid, seq); err != nil {
			return err
		}
		res.AckSeq, res.Stored = seq, true
		return nil
	})
	return res, err
}

func decodeStoredSnap(category, status, hash string, data []byte) (secevents.Snap, error) {
	s := secevents.Snap{Status: status, Hash: hash}
	if len(data) == 0 || string(data) == "{}" {
		return s, nil
	}
	var err error
	switch category {
	case secproto.CatFail2ban:
		var v secproto.Fail2ban
		err = json.Unmarshal(data, &v)
		s.F2B = &v
	case secproto.CatSockets:
		var v secproto.Sockets
		err = json.Unmarshal(data, &v)
		s.Sock = &v
	case secproto.CatFirewall:
		var v secproto.Firewall
		err = json.Unmarshal(data, &v)
		s.FW = &v
	}
	return s, err
}

// --- reads ---------------------------------------------------------------------------------------

type SnapshotState struct {
	Category    string          `json:"category"`
	Status      string          `json:"status"`
	ObservedAt  time.Time       `json:"observed_at"`
	ReceivedAt  time.Time       `json:"received_at"`
	ClockSkewMS int64           `json:"clock_skew_ms"`
	Data        json.RawMessage `json:"data"`
}

// SnapshotStates returns the latest snapshot of each category for a server the scope can see.
func (s *Store) SnapshotStates(ctx context.Context, sc Scope, vpsID string) ([]SnapshotState, error) {
	if _, err := s.GetVPS(ctx, sc, vpsID); err != nil {
		return nil, err
	}
	vid := uuid.MustParse(vpsID)
	rows, err := s.pool.Query(ctx, `SELECT category, status, observed_at, received_at, clock_skew_ms, data FROM security_snapshot_state WHERE vps_id=$1 ORDER BY category`, vid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SnapshotState{}
	for rows.Next() {
		var x SnapshotState
		var d []byte
		if err := rows.Scan(&x.Category, &x.Status, &x.ObservedAt, &x.ReceivedAt, &x.ClockSkewMS, &d); err != nil {
			return nil, err
		}
		x.Data = d
		out = append(out, x)
	}
	return out, rows.Err()
}

type SecEvent struct {
	ID         string          `json:"id"`
	VPSID      string          `json:"vps_id"`
	Category   string          `json:"category"`
	Type       string          `json:"type"`
	Severity   string          `json:"severity"`
	Source     string          `json:"source"`
	ObservedAt time.Time       `json:"observed_at"`
	ReceivedAt time.Time       `json:"received_at"`
	Payload    json.RawMessage `json:"payload"`
}

// SecEvents returns a server's journal, newest first. before is the (observed_at, id) of the last row of
// the previous page.
func (s *Store) SecEvents(ctx context.Context, sc Scope, vpsID, category string, beforeTS *time.Time, beforeID string, limit int) ([]SecEvent, error) {
	if _, err := s.GetVPS(ctx, sc, vpsID); err != nil {
		return nil, err
	}
	vid := uuid.MustParse(vpsID)
	var bid *uuid.UUID
	if u, err := uuid.Parse(beforeID); err == nil {
		bid = &u
	}
	rows, err := s.pool.Query(ctx, `SELECT id, vps_id, category, type, severity, source, observed_at, received_at, payload FROM security_events
		WHERE vps_id=$1 AND ($2 = '' OR category=$2)
		  AND ($3::timestamptz IS NULL OR (observed_at, id) < ($3::timestamptz, $4::uuid))
		ORDER BY observed_at DESC, id DESC LIMIT $5`, vid, category, beforeTS, bid, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SecEvent{}
	for rows.Next() {
		var e SecEvent
		var id, v uuid.UUID
		var p []byte
		if err := rows.Scan(&id, &v, &e.Category, &e.Type, &e.Severity, &e.Source, &e.ObservedAt, &e.ReceivedAt, &p); err != nil {
			return nil, err
		}
		e.ID, e.VPSID, e.Payload = id.String(), v.String(), p
		out = append(out, e)
	}
	return out, rows.Err()
}

// SecSummary is what a server's card shows at a glance: whether it has an agent, and the last known state of
// Fail2ban. It carries the times so the caller can call old data old.
type SecSummary struct {
	AgentStatus   string // "" when the server has no agent
	AgentLastSeen *time.Time
	F2BStatus     string // "" when nothing was received yet
	F2BReceivedAt *time.Time
	F2BObservedAt *time.Time
	Jails         int
	Banned        int // addresses banned right now, across jails
	TotalBanned   int // bans made since Fail2ban started counting
}

// SecuritySummaries returns one summary per server the scope can see.
func (s *Store) SecuritySummaries(ctx context.Context, sc Scope) (map[string]SecSummary, error) {
	pred, args := vpsVisible(sc, 0)
	rows, err := s.pool.Query(ctx, `SELECT v.id, ag.status, ag.last_seen, st.status, st.received_at, st.observed_at, st.data
		FROM security_vps v
		LEFT JOIN security_agents ag ON ag.vps_id = v.id AND ag.status <> 'revoked'
		LEFT JOIN security_snapshot_state st ON st.vps_id = v.id AND st.category = 'fail2ban'
		WHERE `+pred, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]SecSummary{}
	for rows.Next() {
		var id uuid.UUID
		var agStatus, stStatus *string
		var sum SecSummary
		var data []byte
		if err := rows.Scan(&id, &agStatus, &sum.AgentLastSeen, &stStatus, &sum.F2BReceivedAt, &sum.F2BObservedAt, &data); err != nil {
			return nil, err
		}
		if agStatus != nil {
			sum.AgentStatus = *agStatus
		}
		if stStatus != nil {
			sum.F2BStatus = *stStatus
			var f secproto.Fail2ban
			if json.Unmarshal(data, &f) == nil {
				sum.Jails = len(f.Jails)
				for _, j := range f.Jails {
					sum.Banned += max(j.CurrentlyBanned, len(j.BannedIPs))
					sum.TotalBanned += j.TotalBanned
				}
			}
		}
		out[id.String()] = sum
	}
	return out, rows.Err()
}
