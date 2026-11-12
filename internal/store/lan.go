package store

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Taminum/Owlery/internal/netdev"
)

// AlertLANNew: a device appeared in a router's client list that the owner has not looked at yet.
const AlertLANNew = "lan_new_device"

// LANDevice is a device some router has listed as a client.
type LANDevice struct {
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Host      string    `json:"host,omitempty"`
	Name      string    `json:"name,omitempty"`
	Source    string    `json:"source"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Confirmed bool      `json:"confirmed"`
	Seen      bool      `json:"seen"` // in the latest list of a router
}

// lanSeenWithin is how recently a router must have listed a device for it to count as seen now.
const lanSeenWithin = 10 * time.Minute

// recordLANClients keeps the clients of one router piece. When the router has never listed anything before, what it lists now is the
// baseline and counts as known; later arrivals wait for the owner.
func recordLANClients(ctx context.Context, tx pgx.Tx, deviceID uuid.UUID, clients []netdev.Client, now time.Time) error {
	if len(clients) == 0 {
		return nil
	}
	var before int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM lan_devices WHERE source_id=$1`, deviceID).Scan(&before); err != nil {
		return err
	}
	for _, c := range clients {
		_, err := tx.Exec(ctx, `INSERT INTO lan_devices (mac, ip, host, source_id, first_seen, last_seen, confirmed) VALUES ($1,$2,$3,$4,$5,$5,$6)
ON CONFLICT (mac) DO UPDATE SET ip=EXCLUDED.ip, host=CASE WHEN EXCLUDED.host<>'' THEN EXCLUDED.host ELSE lan_devices.host END, source_id=EXCLUDED.source_id, last_seen=EXCLUDED.last_seen`,
			c.MAC, c.IP, c.Host, deviceID, now, before == 0)
		if err != nil {
			return err
		}
	}
	return nil
}

// ListLANDevices lists every device ever listed, the ones seen most recently first.
func (s *Store) ListLANDevices(ctx context.Context, now time.Time) ([]LANDevice, error) {
	rows, err := s.pool.Query(ctx, `SELECT l.mac, l.ip, l.host, l.name, coalesce(n.name, ''), l.first_seen, l.last_seen, l.confirmed
FROM lan_devices l LEFT JOIN net_devices n ON n.id = l.source_id ORDER BY l.last_seen DESC, l.mac`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LANDevice{}
	for rows.Next() {
		var d LANDevice
		if err := rows.Scan(&d.MAC, &d.IP, &d.Host, &d.Name, &d.Source, &d.FirstSeen, &d.LastSeen, &d.Confirmed); err != nil {
			return nil, err
		}
		d.Seen = now.Sub(d.LastSeen) < lanSeenWithin
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetLANDevice gives a device its name (empty clears it) and marks it as looked at.
func (s *Store) SetLANDevice(ctx context.Context, mac, name string) error {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(hw) != 6 {
		return ErrNotFound
	}
	tag, err := s.pool.Exec(ctx, `UPDATE lan_devices SET name=$2, confirmed=true WHERE mac=$1`, strings.ToUpper(hw.String()), cleanText(name, 60))
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
