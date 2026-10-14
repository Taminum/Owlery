package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Taminum/RemnaScope/internal/geoip"
	"github.com/Taminum/RemnaScope/internal/routerlog"
	"github.com/Taminum/RemnaScope/internal/site"
	"github.com/Taminum/RemnaScope/internal/xraylog"
)

type Agent struct {
	ID          string     `json:"id"`
	PanelID     string     `json:"panel_id"`
	NodeID      string     `json:"node_id"`
	NodeName    string     `json:"node_name"`
	Name        *string    `json:"name"`
	Kind        string     `json:"kind"` // node | router
	CoversUser  *string    `json:"covers_user"`
	Status      string     `json:"status"` // enrolling | active | revoked
	Epoch       *string    `json:"epoch"`
	Version     *string    `json:"agent_version"`
	SourceID    *string    `json:"source_id"`
	LastSeen    *time.Time `json:"last_seen"`
	LastBatchAt *time.Time `json:"last_batch_at"`
	LastEventAt *time.Time `json:"last_event_at"`
	LastAckSeq  int64      `json:"last_ack_seq"`
	SpoolBytes  int64      `json:"spool_bytes"`
	Dropped     int64      `json:"dropped_total"`
	ParseErrors int64      `json:"parse_errors"`
	EventsTotal int64      `json:"events_total"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
}

const agentCols = `a.id, a.panel_id, a.node_id, n.name, a.name, a.kind, a.covers_user, a.status, a.epoch, a.agent_version, a.source_id, a.last_seen, a.last_batch_at,
	a.last_event_at, a.last_ack_seq, a.spool_bytes, a.dropped_total, a.parse_errors, a.events_total, a.created_at, a.revoked_at`

func scanAgent(r pgx.Row) (Agent, error) {
	var a Agent
	var id, pid, nid uuid.UUID
	err := r.Scan(&id, &pid, &nid, &a.NodeName, &a.Name, &a.Kind, &a.CoversUser, &a.Status, &a.Epoch, &a.Version, &a.SourceID, &a.LastSeen, &a.LastBatchAt,
		&a.LastEventAt, &a.LastAckSeq, &a.SpoolBytes, &a.Dropped, &a.ParseErrors, &a.EventsTotal, &a.CreatedAt, &a.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	a.ID, a.PanelID, a.NodeID = id.String(), pid.String(), nid.String()
	return a, err
}

// CreateAgent enrols an agent for one node of a panel. The node must belong to that panel
// (the composite foreign key enforces it again), and a node has at most one live agent.
func (s *Store) CreateAgent(ctx context.Context, sc Scope, panelID, nodeID, name, kind, coversUser string, tokenHash []byte) (Agent, error) {
	pid, err := ParseID(panelID)
	if err != nil || !sc.Allows(panelID) {
		return Agent{}, ErrNotFound
	}
	nid, err := ParseID(nodeID)
	if err != nil {
		return Agent{}, ErrNotFound
	}
	var ok bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM nodes WHERE id=$1 AND panel_id=$2 AND removed_at IS NULL)`, nid, pid).Scan(&ok); err != nil {
		return Agent{}, err
	}
	if !ok {
		return Agent{}, ErrNotFound
	}
	id := uuid.New()
	_, err = s.pool.Exec(ctx, `INSERT INTO agents (id, panel_id, node_id, token_hash, status, name, kind, covers_user) VALUES ($1,$2,$3,$4,'enrolling',$5,$6,$7)`, id, pid, nid, tokenHash, nilIfEmpty(name), kind, nilIfEmpty(coversUser))
	if IsUniqueViolation(err) {
		return Agent{}, ErrConflict
	}
	if err != nil {
		return Agent{}, err
	}
	return s.agentByID(ctx, id)
}

func (s *Store) agentByID(ctx context.Context, id uuid.UUID) (Agent, error) {
	return scanAgent(s.pool.QueryRow(ctx, `SELECT `+agentCols+` FROM agents a JOIN nodes n ON n.id=a.node_id AND n.panel_id=a.panel_id WHERE a.id=$1`, id))
}

func (s *Store) ListAgents(ctx context.Context, sc Scope, panelID string) ([]Agent, error) {
	pid, err := ParseID(panelID)
	if err != nil || !sc.Allows(panelID) {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT `+agentCols+` FROM agents a JOIN nodes n ON n.id=a.node_id AND n.panel_id=a.panel_id
		WHERE a.panel_id=$1 AND a.status <> 'revoked' ORDER BY lower(n.name)`, pid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) RevokeAgent(ctx context.Context, sc Scope, panelID, agentID string) error {
	pid, err := ParseID(panelID)
	if err != nil || !sc.Allows(panelID) {
		return ErrNotFound
	}
	aid, err := ParseID(agentID)
	if err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE agents SET status='revoked', revoked_at=now() WHERE id=$1 AND panel_id=$2 AND status <> 'revoked'`, aid, pid)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// AgentForAuth is the only unscoped agent read: the ingest endpoint authenticates by agent id
// and secret, not by a user session. It returns the stored token hash for constant-time comparison.
func (s *Store) AgentForAuth(ctx context.Context, agentID string) (Agent, []byte, error) {
	aid, err := ParseID(agentID)
	if err != nil {
		return Agent{}, nil, ErrNotFound
	}
	var hash []byte
	if err := s.pool.QueryRow(ctx, `SELECT token_hash FROM agents WHERE id=$1`, aid).Scan(&hash); errors.Is(err, pgx.ErrNoRows) {
		return Agent{}, nil, ErrNotFound
	} else if err != nil {
		return Agent{}, nil, err
	}
	a, err := s.agentByID(ctx, aid)
	return a, hash, err
}

// AgentHello records a connection and returns the last acknowledged sequence. A new epoch
// (the agent lost its state and restarted numbering) resets the sequence, so events are never
// confused with an earlier numbering.
func (s *Store) AgentHello(ctx context.Context, agentID, epoch, version, source string) (int64, error) {
	aid, err := ParseID(agentID)
	if err != nil {
		return 0, ErrNotFound
	}
	var ack int64
	err = s.pool.QueryRow(ctx, `UPDATE agents SET
			last_ack_seq = CASE WHEN epoch IS DISTINCT FROM $2 THEN 0 ELSE last_ack_seq END,
			epoch = $2, agent_version = $3, source_id = $4, status = CASE WHEN status='revoked' THEN status ELSE 'active' END,
			last_hello_at = now(), last_seen = now()
		WHERE id=$1 AND status <> 'revoked' RETURNING last_ack_seq`, aid, epoch, version, source).Scan(&ack)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return ack, err
}

func (s *Store) TouchAgent(ctx context.Context, agentID string, spoolBytes int64) error {
	aid, err := ParseID(agentID)
	if err != nil {
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `UPDATE agents SET last_seen=now(), spool_bytes=$2 WHERE id=$1 AND status <> 'revoked'`, aid, spoolBytes)
	return err
}

type Line struct {
	Seq    int64
	Event  *xraylog.Event   // nil when the line did not parse (node agents)
	Device *routerlog.Event // nil when the line did not parse (router agents)
	FP     []byte           // sha256 of the raw line
}

type GapReport struct {
	From, To *time.Time
	Lines    int64
	Reason   string
}

type Commit struct {
	AgentID    string
	Lines      []Line
	Dropped    int64
	SpoolBytes int64
	Gaps       []GapReport
}

type CommitResult struct {
	Accepted   int
	Duplicates int
	ParseErrs  int
	AckSeq     int64
}

// ErrSeqGap means the batch does not continue where the last acknowledged one ended.
type ErrSeqGap struct{ Expected int64 }

func (e *ErrSeqGap) Error() string {
	return fmt.Sprintf("store: sequence gap, expected %d", e.Expected)
}

var eventNS = uuid.MustParse("6f1d7a52-3b0e-4c11-9a0e-5c1d2d3a4b5c")

// CommitBatch stores a batch atomically and advances the agent's acknowledged sequence.
// Events already acknowledged (a resent batch) are skipped, so a replay never double counts;
// identical-looking lines with different sequence numbers are all kept.
// The panel and node come from the agent's own row, never from the payload.
func (s *Store) CommitBatch(ctx context.Context, c Commit) (CommitResult, error) {
	aid, err := ParseID(c.AgentID)
	if err != nil {
		return CommitResult{}, ErrNotFound
	}
	var res CommitResult
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var pid, nid uuid.UUID
		var epoch *string
		var ack int64
		var status string
		if err := tx.QueryRow(ctx, `SELECT panel_id, node_id, epoch, last_ack_seq, status FROM agents WHERE id=$1 FOR UPDATE`, aid).Scan(&pid, &nid, &epoch, &ack, &status); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if status == "revoked" {
			return ErrNotFound
		}
		ep := ""
		if epoch != nil {
			ep = *epoch
		}
		res.AckSeq = ack

		var fresh []Line
		for _, l := range c.Lines {
			if l.Seq <= ack {
				res.Duplicates++
				continue
			}
			fresh = append(fresh, l)
		}
		for i, l := range fresh {
			if l.Seq != ack+1+int64(i) {
				return &ErrSeqGap{Expected: ack + 1}
			}
		}

		var (
			ids   []uuid.UUID
			ts    []time.Time
			cip   []*netip.Addr
			dhost []*string
			sites []*string
			ctry  []*string
			dip   []*netip.Addr
			dport []int32
			proto []string
			inb   []string
			outb  []string
			email []*string
			fp    [][]byte
			arrow []string
			intl  []bool
			maxTS *time.Time
		)
		var dev []*routerlog.Event
		for _, l := range fresh {
			if l.Device != nil {
				dev = append(dev, l.Device)
				if maxTS == nil || l.Device.Seen.After(*maxTS) {
					t := l.Device.Seen
					maxTS = &t
				}
				continue
			}
			if l.Event == nil {
				res.ParseErrs++
				continue
			}
			e := l.Event
			ids = append(ids, uuid.NewSHA1(eventNS, []byte(fmt.Sprintf("%s|%s|%d", aid, ep, l.Seq))))
			ts = append(ts, e.Time)
			cip = append(cip, addrPtr(e.ClientIP))
			dhost = append(dhost, nilIfEmpty(e.DestHost))
			sites = append(sites, nilIfEmpty(site.Of(e.DestHost)))
			ctry = append(ctry, countryOf(e.DestIP))
			dip = append(dip, addrPtr(e.DestIP))
			dport = append(dport, int32(e.DestPort))
			proto = append(proto, e.Protocol)
			inb = append(inb, e.InboundTag)
			outb = append(outb, e.OutboundTag)
			email = append(email, nilIfEmpty(e.Email))
			fp = append(fp, l.FP)
			arrow = append(arrow, e.Arrow)
			intl = append(intl, e.Internal)
			if maxTS == nil || e.Time.After(*maxTS) {
				t := e.Time
				maxTS = &t
			}
		}
		if len(ids) > 0 {
			tag, err := tx.Exec(ctx, `INSERT INTO connection_events
				(event_id, panel_id, node_id, agent_id, ts, client_ip, destination_host, destination_ip, destination_port, protocol,
				 inbound_tag, outbound_tag, xray_email, user_id, raw_fingerprint, parser_version, arrow, internal, site, country)
				SELECT v.id, $1, $2, $3, v.ts, v.cip, v.dhost, v.dip, v.dport, v.proto, v.inb, v.outb, v.email,
				       (SELECT u.id FROM users u WHERE u.panel_id=$1 AND u.remote_uuid = v.email AND u.removed_at IS NULL),
				       v.fp, $4, v.arrow, v.internal, v.site, v.country
				FROM unnest($5::uuid[], $6::timestamptz[], $7::inet[], $8::text[], $9::inet[], $10::int[], $11::text[], $12::text[],
				            $13::text[], $14::text[], $15::bytea[], $16::text[], $17::bool[], $18::text[], $19::text[])
				     AS v(id, ts, cip, dhost, dip, dport, proto, inb, outb, email, fp, arrow, internal, site, country)
				ON CONFLICT (event_id) DO NOTHING`,
				pid, nid, aid, int32(xraylog.ParserVersion), ids, ts, cip, dhost, dip, dport, proto, inb, outb, email, fp, arrow, intl, sites, ctry)
			if err != nil {
				return err
			}
			res.Accepted = int(tag.RowsAffected())
			res.Duplicates += len(ids) - res.Accepted
		}
		if len(dev) > 0 {
			n, err := upsertDevices(ctx, tx, pid, aid, dev)
			if err != nil {
				return err
			}
			res.Accepted += n
		}
		if n := len(fresh); n > 0 {
			res.AckSeq = fresh[n-1].Seq
		}
		for _, g := range c.Gaps {
			if _, err := tx.Exec(ctx, `INSERT INTO agent_gaps (panel_id, agent_id, node_id, from_ts, to_ts, lines, reason) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
				pid, aid, nid, g.From, g.To, g.Lines, g.Reason); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `UPDATE agents SET last_ack_seq=$2, last_seen=now(), last_batch_at=now(),
				last_event_at = COALESCE(GREATEST(last_event_at, $3), last_event_at, $3),
				spool_bytes=$4, dropped_total=dropped_total+$5, parse_errors=parse_errors+$6, events_total=events_total+$7
			WHERE id=$1`, aid, res.AckSeq, maxTS, c.SpoolBytes, c.Dropped, res.ParseErrs, res.Accepted)
		return err
	})
	return res, err
}

// upsertDevices stores router records. A record for a connection already known only moves its
// counters forward and its last-seen time: a replayed or older record never lowers anything.
// mergeDeviceRecords folds the records of one connection that arrive in the same batch (opened,
// refreshed, closed) into one, because a single INSERT .. ON CONFLICT cannot touch a row twice.
// Counters take the larger value and the last-seen time the later one, exactly as the upsert does
// across batches; the first non-empty host and the latest name are kept.
func mergeDeviceRecords(evs []*routerlog.Event) []*routerlog.Event {
	type key struct {
		id    string
		start time.Time
	}
	at := map[key]int{}
	out := make([]*routerlog.Event, 0, len(evs))
	for _, e := range evs {
		k := key{e.ID, e.Start}
		i, seen := at[k]
		if !seen {
			at[k] = len(out)
			c := *e
			out = append(out, &c)
			continue
		}
		m := out[i]
		m.Up, m.Down = max(m.Up, e.Up), max(m.Down, e.Down)
		if e.Seen.After(m.Seen) {
			m.Seen = e.Seen
		}
		if m.Host == "" {
			m.Host = e.Host
		}
		if e.DeviceName != "" {
			m.DeviceName = e.DeviceName
		}
	}
	return out
}

func upsertDevices(ctx context.Context, tx pgx.Tx, pid, aid uuid.UUID, evs []*routerlog.Event) (int, error) {
	evs = mergeDeviceRecords(evs)
	var (
		keys, names, hosts, protos, outs, sites []string
		ctry                                    []*string
		started, seen                           []time.Time
		devs, dips                              []*netip.Addr
		ports                                   []int32
		ups, downs                              []int64
	)
	for _, e := range evs {
		keys = append(keys, e.ID)
		started = append(started, e.Start)
		seen = append(seen, e.Seen)
		d := e.Device
		devs = append(devs, &d)
		names = append(names, e.DeviceName)
		hosts = append(hosts, e.Host)
		sites = append(sites, site.Of(e.Host))
		ctry = append(ctry, countryOf(e.DestIP))
		dips = append(dips, addrPtr(e.DestIP))
		ports = append(ports, int32(e.Port))
		protos = append(protos, e.Protocol)
		ups = append(ups, e.Up)
		downs = append(downs, e.Down)
		outs = append(outs, e.Outbound)
	}
	tag, err := tx.Exec(ctx, `INSERT INTO device_connections
		(panel_id, agent_id, conn_key, started_at, updated_at, device_ip, device_name, destination_host, destination_ip,
		 destination_port, protocol, up_bytes, down_bytes, outbound, site, country)
		SELECT $1, $2, v.k, v.st, v.sn, v.dev, NULLIF(v.nm,''), NULLIF(v.h,''), v.dip, v.port, v.proto, v.up, v.dn, NULLIF(v.o,''), NULLIF(v.s,''), v.c
		FROM unnest($3::text[], $4::timestamptz[], $5::timestamptz[], $6::inet[], $7::text[], $8::text[], $9::inet[], $10::int[],
		            $11::text[], $12::bigint[], $13::bigint[], $14::text[], $15::text[], $16::text[])
		     AS v(k, st, sn, dev, nm, h, dip, port, proto, up, dn, o, s, c)
		ON CONFLICT (agent_id, conn_key, started_at) DO UPDATE SET
			updated_at = GREATEST(device_connections.updated_at, EXCLUDED.updated_at),
			up_bytes = GREATEST(device_connections.up_bytes, EXCLUDED.up_bytes),
			down_bytes = GREATEST(device_connections.down_bytes, EXCLUDED.down_bytes),
			destination_host = COALESCE(device_connections.destination_host, EXCLUDED.destination_host),
			site = COALESCE(device_connections.site, EXCLUDED.site),
			device_name = COALESCE(EXCLUDED.device_name, device_connections.device_name)`,
		pid, aid, keys, started, seen, devs, names, hosts, dips, ports, protos, ups, downs, outs, sites, ctry)
	return int(tag.RowsAffected()), err
}

// countryOf is the country of a destination address: nil when the line has no IP at all, "ZZ"
// when it has one that is private or not in the table.
func countryOf(a netip.Addr) *string {
	if !a.IsValid() {
		return nil
	}
	c := geoip.Default().Country(a)
	if c == "" {
		c = UnknownCountry
	}
	return &c
}

func addrPtr(a netip.Addr) *netip.Addr {
	if !a.IsValid() {
		return nil
	}
	return &a
}

// PurgeExpiredEvents deletes raw events past each panel's retention window.
func (s *Store) PurgeExpiredEvents(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM connection_events e USING panels p
		WHERE e.panel_id = p.id AND e.ts < $1::timestamptz - make_interval(days => p.retention_days)`, now)
	return tag.RowsAffected(), err
}

// HashAgentSecret is how an agent secret is stored; the secret itself is shown once.
func HashAgentSecret(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}
