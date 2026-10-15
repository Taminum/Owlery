package store

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MaxVPSAddresses and MaxVPSLinks bound what one server may carry.
const (
	MaxVPSAddresses = 20
	MaxVPSLinks     = 50
)

type VPSAddress struct {
	Address string `json:"address"`
	Kind    string `json:"kind"` // ipv4 | ipv6 | domain
}

type VPSLink struct {
	ID         string    `json:"id"`
	PanelID    string    `json:"panel_id"`
	NodeID     *string   `json:"node_id"`
	Provenance string    `json:"provenance"`
	CreatedAt  time.Time `json:"created_at"`
}

type VPS struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	Origin    string       `json:"origin"`
	Enabled   bool         `json:"enabled"`
	Note      string       `json:"note"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
	Addresses []VPSAddress `json:"addresses"`
	Links     []VPSLink    `json:"links"`
	// DiscoveryScan is opt-in: when on, a fixed list of common ports is tried on the registered IP
	// addresses once a day, and what answers becomes a port endpoint that is not expected.
	DiscoveryScan   bool       `json:"discovery_scan"`
	DiscoveryScanAt *time.Time `json:"discovery_scan_at"`
}

type VPSPatch struct {
	Name          *string
	Note          *string
	Enabled       *bool
	Addresses     *[]VPSAddress // replaces the whole set
	DiscoveryScan *bool
}

// vpsVisible is the predicate every VPS read shares: the server is not archived and the actor is the
// owner or holds a role on a panel it is linked to. A manual server with no links is the owner's alone.
func vpsVisible(sc Scope, n int) (string, []any) {
	if sc.All {
		return "v.archived_at IS NULL", nil
	}
	return `v.archived_at IS NULL AND EXISTS (SELECT 1 FROM security_vps_links l WHERE l.vps_id = v.id AND l.panel_id = ANY($` +
		strconv.Itoa(n+1) + `::uuid[]))`, []any{uuids(sc.IDs)}
}

const vpsCols = `v.id, v.name, v.origin, v.enabled, v.note, v.created_at, v.updated_at, v.discovery_scan, v.discovery_scan_at`

func scanVPS(r pgx.Row) (VPS, error) {
	var v VPS
	var id uuid.UUID
	err := r.Scan(&id, &v.Name, &v.Origin, &v.Enabled, &v.Note, &v.CreatedAt, &v.UpdatedAt, &v.DiscoveryScan, &v.DiscoveryScanAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, ErrNotFound
	}
	v.ID = id.String()
	v.Addresses, v.Links = []VPSAddress{}, []VPSLink{}
	return v, err
}

// CreateVPS adds a manually created server. Linking it to panels is a separate, explicit step.
func (s *Store) CreateVPS(ctx context.Context, createdBy, name, note string, addrs []VPSAddress) (VPS, error) {
	if len(addrs) > MaxVPSAddresses {
		return VPS{}, ErrLimit
	}
	id := uuid.New()
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var by *uuid.UUID
		if u, err := uuid.Parse(createdBy); err == nil {
			by = &u
		}
		if _, err := tx.Exec(ctx, `INSERT INTO security_vps (id, name, note, created_by) VALUES ($1,$2,$3,$4)`, id, name, note, by); err != nil {
			return err
		}
		return replaceVPSAddresses(ctx, tx, id, addrs)
	})
	if IsUniqueViolation(err) {
		return VPS{}, ErrConflict
	}
	if err != nil {
		return VPS{}, err
	}
	return s.GetVPS(ctx, Scope{All: true}, id.String())
}

func replaceVPSAddresses(ctx context.Context, tx pgx.Tx, id uuid.UUID, addrs []VPSAddress) error {
	if _, err := tx.Exec(ctx, `DELETE FROM security_vps_addresses WHERE vps_id=$1`, id); err != nil {
		return err
	}
	for _, a := range addrs {
		if _, err := tx.Exec(ctx, `INSERT INTO security_vps_addresses (vps_id, address, kind) VALUES ($1,$2,$3)`, id, a.Address, a.Kind); err != nil {
			return err
		}
	}
	return nil
}

// GetVPS returns one server the scope can see. A server outside the scope is "not found", the same as
// one that does not exist. Links to panels outside the scope are left out.
func (s *Store) GetVPS(ctx context.Context, sc Scope, id string) (VPS, error) {
	u, err := ParseID(id)
	if err != nil {
		return VPS{}, ErrNotFound
	}
	pred, args := vpsVisible(sc, 1)
	v, err := scanVPS(s.pool.QueryRow(ctx, `SELECT `+vpsCols+` FROM security_vps v WHERE v.id=$1 AND `+pred, append([]any{u}, args...)...))
	if err != nil {
		return VPS{}, err
	}
	m, err := s.fillVPS(ctx, sc, []VPS{v})
	if err != nil {
		return VPS{}, err
	}
	return m[0], nil
}

// ListVPS returns every server the scope can see, by name.
func (s *Store) ListVPS(ctx context.Context, sc Scope) ([]VPS, error) {
	pred, args := vpsVisible(sc, 0)
	rows, err := s.pool.Query(ctx, `SELECT `+vpsCols+` FROM security_vps v WHERE `+pred+` ORDER BY lower(v.name), v.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VPS{}
	for rows.Next() {
		v, err := scanVPS(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return s.fillVPS(ctx, sc, out)
}

func (s *Store) fillVPS(ctx context.Context, sc Scope, vs []VPS) ([]VPS, error) {
	if len(vs) == 0 {
		return vs, nil
	}
	ids := make([]uuid.UUID, len(vs))
	at := map[string]int{}
	for i, v := range vs {
		ids[i] = uuid.MustParse(v.ID)
		at[v.ID] = i
	}
	rows, err := s.pool.Query(ctx, `SELECT vps_id, address, kind FROM security_vps_addresses WHERE vps_id = ANY($1) ORDER BY kind, address`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id uuid.UUID
		var a VPSAddress
		if err := rows.Scan(&id, &a.Address, &a.Kind); err != nil {
			rows.Close()
			return nil, err
		}
		vs[at[id.String()]].Addresses = append(vs[at[id.String()]].Addresses, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	q := `SELECT id, vps_id, panel_id, node_id, provenance, created_at FROM security_vps_links WHERE vps_id = ANY($1)`
	qargs := []any{ids}
	if !sc.All {
		q += ` AND panel_id = ANY($2::uuid[])`
		qargs = append(qargs, uuids(sc.IDs))
	}
	rows, err = s.pool.Query(ctx, q+` ORDER BY created_at, id`, qargs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, vid, pid uuid.UUID
		var nid *uuid.UUID
		var l VPSLink
		if err := rows.Scan(&id, &vid, &pid, &nid, &l.Provenance, &l.CreatedAt); err != nil {
			return nil, err
		}
		l.ID, l.PanelID = id.String(), pid.String()
		if nid != nil {
			n := nid.String()
			l.NodeID = &n
		}
		vs[at[vid.String()]].Links = append(vs[at[vid.String()]].Links, l)
	}
	return vs, rows.Err()
}

// UpdateVPS changes the given fields. The caller has already decided the actor may.
func (s *Store) UpdateVPS(ctx context.Context, sc Scope, id string, p VPSPatch) (VPS, error) {
	u, err := ParseID(id)
	if err != nil {
		return VPS{}, ErrNotFound
	}
	if p.Addresses != nil && len(*p.Addresses) > MaxVPSAddresses {
		return VPS{}, ErrLimit
	}
	return s.updateVPS(ctx, sc, u, p)
}

func (s *Store) updateVPS(ctx context.Context, sc Scope, u uuid.UUID, p VPSPatch) (VPS, error) {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		pred, args := vpsVisible(sc, 5)
		tag, err := tx.Exec(ctx, `UPDATE security_vps v SET
				name = COALESCE($2, v.name), note = COALESCE($3, v.note), enabled = COALESCE($4, v.enabled),
				discovery_scan = COALESCE($5, v.discovery_scan), updated_at = now()
			WHERE v.id=$1 AND `+pred,
			append([]any{u, p.Name, p.Note, p.Enabled, p.DiscoveryScan}, args...)...)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if p.Addresses != nil {
			return replaceVPSAddresses(ctx, tx, u, *p.Addresses)
		}
		return nil
	})
	if IsUniqueViolation(err) {
		return VPS{}, ErrConflict
	}
	if err != nil {
		return VPS{}, err
	}
	return s.GetVPS(ctx, sc, u.String())
}

// ArchiveVPS hides a server and keeps its history; nothing about it is deleted. Its security agent is
// revoked in the same step, so an archived server cannot keep reporting.
func (s *Store) ArchiveVPS(ctx context.Context, sc Scope, id string) error {
	u, err := ParseID(id)
	if err != nil {
		return ErrNotFound
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		pred, args := vpsVisible(sc, 1)
		tag, err := tx.Exec(ctx, `UPDATE security_vps v SET archived_at = now(), enabled = false, updated_at = now() WHERE v.id=$1 AND `+pred, append([]any{u}, args...)...)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		_, err = tx.Exec(ctx, `UPDATE security_agents SET status='revoked', revoked_at=now() WHERE vps_id=$1 AND status <> 'revoked'`, u)
		return err
	})
}

// AddVPSLink records that the operator confirmed the server hosts a panel (nodeID empty) or one of
// its nodes. The node must belong to that panel; the composite foreign key enforces it again.
func (s *Store) AddVPSLink(ctx context.Context, sc Scope, vpsID, panelID, nodeID, createdBy string) (VPSLink, error) {
	vid, err := ParseID(vpsID)
	if err != nil {
		return VPSLink{}, ErrNotFound
	}
	pid, err := ParseID(panelID)
	if err != nil {
		return VPSLink{}, ErrNotFound
	}
	var nid *uuid.UUID
	if nodeID != "" {
		n, err := ParseID(nodeID)
		if err != nil {
			return VPSLink{}, ErrNotFound
		}
		var ok bool
		if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM nodes WHERE id=$1 AND panel_id=$2 AND removed_at IS NULL)`, n, pid).Scan(&ok); err != nil {
			return VPSLink{}, err
		}
		if !ok {
			return VPSLink{}, ErrNotFound
		}
		nid = &n
	}
	if _, err := s.GetVPS(ctx, Scope{All: true}, vid.String()); err != nil {
		return VPSLink{}, err
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security_vps_links WHERE vps_id=$1`, vid).Scan(&n); err != nil {
		return VPSLink{}, err
	}
	if n >= MaxVPSLinks {
		return VPSLink{}, ErrLimit
	}
	var by *uuid.UUID
	if u, err := uuid.Parse(createdBy); err == nil {
		by = &u
	}
	var l VPSLink
	var id uuid.UUID
	err = s.pool.QueryRow(ctx, `INSERT INTO security_vps_links (vps_id, panel_id, node_id, created_by) VALUES ($1,$2,$3,$4)
		RETURNING id, provenance, created_at`, vid, pid, nid, by).Scan(&id, &l.Provenance, &l.CreatedAt)
	if IsUniqueViolation(err) {
		return VPSLink{}, ErrConflict
	}
	if err != nil {
		return VPSLink{}, err
	}
	l.ID, l.PanelID = id.String(), pid.String()
	if nid != nil {
		n := nid.String()
		l.NodeID = &n
	}
	return l, nil
}

// VPSLinkPanel returns the panel a link points at, so the caller can check the actor's role on it.
func (s *Store) VPSLinkPanel(ctx context.Context, vpsID, linkID string) (string, error) {
	vid, err := ParseID(vpsID)
	if err != nil {
		return "", ErrNotFound
	}
	lid, err := ParseID(linkID)
	if err != nil {
		return "", ErrNotFound
	}
	var pid uuid.UUID
	err = s.pool.QueryRow(ctx, `SELECT panel_id FROM security_vps_links WHERE id=$1 AND vps_id=$2`, lid, vid).Scan(&pid)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return pid.String(), err
}

// RemoveVPSLink unlinks without touching the server or its history.
func (s *Store) RemoveVPSLink(ctx context.Context, vpsID, linkID string) error {
	vid, err := ParseID(vpsID)
	if err != nil {
		return ErrNotFound
	}
	lid, err := ParseID(linkID)
	if err != nil {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM security_vps_links WHERE id=$1 AND vps_id=$2`, lid, vid)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// VPSMatch is a registered server that holds an address.
type VPSMatch struct {
	VPSID string `json:"vps_id"`
	Name  string `json:"name"`
}

// VPSByAddresses finds, among the servers the scope can see, the ones that hold each of the given
// addresses. Only a registered address matches: an IP that merely shares a network with a server is not one.
func (s *Store) VPSByAddresses(ctx context.Context, sc Scope, addrs []string) (map[string]VPSMatch, error) {
	pred, args := vpsVisible(sc, 1)
	args = append([]any{addrs}, args...)
	rows, err := s.pool.Query(ctx, `SELECT a.address, v.id, v.name FROM security_vps_addresses a JOIN security_vps v ON v.id = a.vps_id
		WHERE a.address = ANY($1) AND `+pred+` ORDER BY v.created_at`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]VPSMatch{}
	for rows.Next() {
		var addr, name string
		var id uuid.UUID
		if err := rows.Scan(&addr, &id, &name); err != nil {
			return nil, err
		}
		if _, dup := out[addr]; !dup {
			out[addr] = VPSMatch{VPSID: id.String(), Name: name}
		}
	}
	return out, rows.Err()
}
