package store

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Maintenance is a window during which one machine's alerts are not reported.
type Maintenance struct {
	VPSID string    `json:"vps_id"`
	Until time.Time `json:"until"`
	Note  string    `json:"note"`
}

// SetMaintenance starts (or moves) a machine's window.
func (s *Store) SetMaintenance(ctx context.Context, vpsID string, until time.Time, note string) error {
	id, err := uuid.Parse(vpsID)
	if err != nil {
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO maintenance_windows (vps_id, until, note) VALUES ($1, $2, $3)
		ON CONFLICT (vps_id) DO UPDATE SET until=$2, note=$3, created_at=now()`, id, until, note)
	return err
}

// ClearMaintenance ends a machine's window at once.
func (s *Store) ClearMaintenance(ctx context.Context, vpsID string) error {
	id, err := uuid.Parse(vpsID)
	if err != nil {
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `DELETE FROM maintenance_windows WHERE vps_id=$1`, id)
	return err
}

// ActiveMaintenance lists the windows that are open at now, and forgets the ones that are over.
func (s *Store) ActiveMaintenance(ctx context.Context, now time.Time) ([]Maintenance, error) {
	if _, err := s.pool.Exec(ctx, `DELETE FROM maintenance_windows WHERE until <= $1`, now); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT vps_id, until, note FROM maintenance_windows ORDER BY until`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Maintenance{}
	for rows.Next() {
		var m Maintenance
		var id uuid.UUID
		if err := rows.Scan(&id, &m.Until, &m.Note); err != nil {
			return nil, err
		}
		m.VPSID = id.String()
		out = append(out, m)
	}
	return out, rows.Err()
}

// QuietSubjects lists what the open windows silence: the machine itself, its security agent and its checked certificates and
// ports. An alert's subject is one of these, or one of them followed by ":" and a detail (a disk, a container).
func (s *Store) QuietSubjects(ctx context.Context, now time.Time) (map[string]bool, error) {
	if _, err := s.pool.Exec(ctx, `DELETE FROM maintenance_windows WHERE until <= $1`, now); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT vps_id::text FROM maintenance_windows
		UNION SELECT a.id::text FROM security_agents a JOIN maintenance_windows m ON m.vps_id = a.vps_id
		UNION SELECT e.id::text FROM security_tls_endpoints e JOIN maintenance_windows m ON m.vps_id = e.vps_id
		UNION SELECT e.id::text FROM security_port_endpoints e JOIN maintenance_windows m ON m.vps_id = e.vps_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// SubjectBase is the part of an alert's subject before the first ":".
func SubjectBase(subject string) string {
	if i := strings.IndexByte(subject, ':'); i >= 0 {
		return subject[:i]
	}
	return subject
}
