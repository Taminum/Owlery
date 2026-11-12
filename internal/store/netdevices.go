package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Taminum/Owlery/internal/netdev"
)

// NetView is what is kept of a device's latest readings.
type NetView struct {
	Board     string             `json:"board"`
	Version   string             `json:"version"`
	UptimeSec int64              `json:"uptime"`
	CPU       float64            `json:"cpu"`
	MemFree   int64              `json:"mem_free"`
	MemTotal  int64              `json:"mem_total"`
	Temp      *float64           `json:"temp,omitempty"`
	StatsAt   *time.Time         `json:"stats_at,omitempty"`
	Ifaces    []netdev.Iface     `json:"ifaces"`
	Clients   []netdev.Client    `json:"clients"`
	Conn      int64              `json:"conn,omitempty"`
	ConnMax   int64              `json:"conn_max,omitempty"`
	ConnAt    *time.Time         `json:"conn_at,omitempty"`
	Top       []netdev.TopSource `json:"top"`
	Nat       []netdev.NatRule   `json:"nat"`
}

type NetDevice struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Kind      string     `json:"kind"`
	CreatedAt time.Time  `json:"created_at"`
	LastSeen  *time.Time `json:"last_seen"`
	ParentID  *string    `json:"parent_id"` // the router this one stands behind; nil for the router at the edge of a network
	Online    bool       `json:"online"`    // heard from in the last five minutes
	View      NetView    `json:"view"`
}

const netOnlineWithin = 5 * time.Minute

func decodeView(raw []byte) NetView {
	v := NetView{Ifaces: []netdev.Iface{}, Clients: []netdev.Client{}, Top: []netdev.TopSource{}, Nat: []netdev.NatRule{}}
	_ = json.Unmarshal(raw, &v)
	if v.Ifaces == nil {
		v.Ifaces = []netdev.Iface{}
	}
	if v.Clients == nil {
		v.Clients = []netdev.Client{}
	}
	if v.Top == nil {
		v.Top = []netdev.TopSource{}
	}
	if v.Nat == nil {
		v.Nat = []netdev.NatRule{}
	}
	return v
}

func (s *Store) CreateNetDevice(ctx context.Context, name, kind string, tokenHash []byte) (NetDevice, error) {
	name = cleanText(name, 60)
	if name == "" {
		return NetDevice{}, errors.New("store: empty name")
	}
	var d NetDevice
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `INSERT INTO net_devices (name, kind, token_hash) VALUES ($1, $2, $3) RETURNING id, name, kind, created_at`, name, kind, tokenHash).Scan(&id, &d.Name, &d.Kind, &d.CreatedAt)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return NetDevice{}, ErrConflict
	}
	d.ID, d.View = id.String(), decodeView(nil)
	return d, err
}

func (s *Store) ListNetDevices(ctx context.Context, now time.Time) ([]NetDevice, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, kind, created_at, last_seen, last, parent_id FROM net_devices WHERE archived_at IS NULL ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NetDevice{}
	for rows.Next() {
		var d NetDevice
		var id uuid.UUID
		var raw []byte
		var parent *uuid.UUID
		if err := rows.Scan(&id, &d.Name, &d.Kind, &d.CreatedAt, &d.LastSeen, &raw, &parent); err != nil {
			return nil, err
		}
		d.ID, d.View = id.String(), decodeView(raw)
		if parent != nil {
			p := parent.String()
			d.ParentID = &p
		}
		d.Online = d.LastSeen != nil && now.Sub(*d.LastSeen) < netOnlineWithin
		out = append(out, d)
	}
	return out, rows.Err()
}

// RenameNetDevice changes the name of a live device.
func (s *Store) RenameNetDevice(ctx context.Context, id, name string) error {
	vid, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	name = cleanText(name, 60)
	if name == "" {
		return errors.New("store: empty name")
	}
	tag, err := s.pool.Exec(ctx, `UPDATE net_devices SET name=$2 WHERE id=$1 AND archived_at IS NULL`, vid, name)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return ErrConflict
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SetNetParent says which router a device stands behind ("" for none). A device cannot stand behind itself or behind one of its own
// descendants.
func (s *Store) SetNetParent(ctx context.Context, id, parent string) error {
	vid, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	if parent == "" {
		tag, err := s.pool.Exec(ctx, `UPDATE net_devices SET parent_id=NULL WHERE id=$1 AND archived_at IS NULL`, vid)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	}
	pid, err := ParseID(parent)
	if err != nil {
		return ErrNotFound
	}
	var ok bool
	// The parent must be a live device whose own chain of parents does not pass through this one.
	err = s.pool.QueryRow(ctx, `WITH RECURSIVE up AS (
    SELECT id, parent_id, 1 AS depth FROM net_devices WHERE id=$2 AND archived_at IS NULL
    UNION ALL SELECT n.id, n.parent_id, up.depth+1 FROM net_devices n JOIN up ON n.id = up.parent_id WHERE up.depth < 20)
SELECT EXISTS (SELECT 1 FROM up WHERE id=$2) AND NOT EXISTS (SELECT 1 FROM up WHERE id=$1)`, vid, pid).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return ErrConflict
	}
	tag, err := s.pool.Exec(ctx, `UPDATE net_devices SET parent_id=$2 WHERE id=$1 AND archived_at IS NULL`, vid, pid)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) DeleteNetDevice(ctx context.Context, id string) error {
	vid, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE net_devices SET archived_at = now() WHERE id=$1 AND archived_at IS NULL`, vid)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// NetDeviceForAuth gives the stored token hash of a live device, and when it was last heard.
func (s *Store) NetDeviceForAuth(ctx context.Context, id string) (hash []byte, lastSeen *time.Time, err error) {
	vid, perr := ParseID(id)
	if perr != nil {
		return nil, nil, ErrNotFound
	}
	err = s.pool.QueryRow(ctx, `SELECT token_hash, last_seen FROM net_devices WHERE id=$1 AND archived_at IS NULL`, vid).Scan(&hash, &lastSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	return
}

type netCounter struct {
	RX int64     `json:"rx"`
	TX int64     `json:"tx"`
	At time.Time `json:"at"`
}

// SaveNetReport applies one piece of a device's report to what is kept: statistics replace the old ones (and give interface speeds
// from the previous counters), a client list is replaced when the piece says it starts one and added to otherwise.
func (s *Store) SaveNetReport(ctx context.Context, id string, r netdev.Report, now time.Time) error {
	vid, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var raw, craw []byte
		if err := tx.QueryRow(ctx, `SELECT last, counters FROM net_devices WHERE id=$1 AND archived_at IS NULL FOR UPDATE`, vid).Scan(&raw, &craw); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		v := decodeView(raw)
		counters := map[string]netCounter{}
		_ = json.Unmarshal(craw, &counters)
		if r.Board != "" {
			v.Board = r.Board
		}
		if r.Version != "" {
			v.Version = r.Version
		}
		if r.HasStats {
			v.UptimeSec, v.CPU, v.MemFree, v.MemTotal, v.Temp = r.UptimeSec, r.CPU, r.MemFree, r.MemTotal, r.Temp
			at := now
			v.StatsAt = &at
			next := map[string]netCounter{}
			v.Ifaces = make([]netdev.Iface, 0, len(r.Ifaces))
			for _, f := range r.Ifaces {
				if p, ok := counters[f.Name]; ok {
					if dt := now.Sub(p.At).Seconds(); dt >= 5 && dt <= 900 && f.RX >= p.RX && f.TX >= p.TX {
						f.RXBps, f.TXBps = float64(f.RX-p.RX)/dt, float64(f.TX-p.TX)/dt
					}
				}
				next[f.Name] = netCounter{RX: f.RX, TX: f.TX, At: now}
				v.Ifaces = append(v.Ifaces, f)
			}
			counters = next
		}
		if r.HasConn {
			at := now
			v.Conn, v.ConnAt, v.Top = r.Conn, &at, r.Top
			if r.ConnMax > 0 {
				v.ConnMax = r.ConnMax
			}
			if v.Top == nil {
				v.Top = []netdev.TopSource{}
			}
		}
		if r.ResetNat {
			v.Nat = []netdev.NatRule{}
		}
		for _, n := range r.Nat {
			if len(v.Nat) < netdev.MaxNat {
				v.Nat = append(v.Nat, n)
			}
		}
		if r.ResetClients {
			v.Clients = []netdev.Client{}
		}
		if err := recordLANClients(ctx, tx, vid, r.Clients, now); err != nil {
			return err
		}
		if len(r.Clients) > 0 {
			seen := map[string]bool{}
			for _, c := range v.Clients {
				seen[c.MAC] = true
			}
			for _, c := range r.Clients {
				if len(v.Clients) >= netdev.MaxClients {
					break
				}
				if !seen[c.MAC] {
					seen[c.MAC] = true
					v.Clients = append(v.Clients, c)
				}
			}
		}
		nraw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		ncraw, err := json.Marshal(counters)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE net_devices SET last=$2, counters=$3, last_seen=$4 WHERE id=$1`, vid, nraw, ncraw, now)
		return err
	})
}

// AlertNetDown: a network device that used to report has been silent for a while.
const AlertNetDown = "net_down"

// AlertNetConnFull: the connection tracking table of a router is nearly full, and new connections will be dropped.
const AlertNetConnFull = "net_conn_full"
