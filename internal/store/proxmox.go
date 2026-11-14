package store

import (
	"context"
	"encoding/json"
	"math"
	"time"

	"github.com/google/uuid"

	"github.com/Taminum/Owlery/internal/secproto"
)

// PVESampleRetention is how long the hourly readings of the guests are kept.
const PVESampleRetention = 35 * 24 * time.Hour

func clampBytes(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

func clampPct(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	return math.Round(math.Min(v, 100000)*10) / 10
}

// cleanPVE makes a reading fit to keep: an agent is trusted to report, not to be sensible.
func cleanPVE(p secproto.Proxmox, now time.Time) secproto.Proxmox {
	p.Type, p.At = "proxmox", now.UTC()
	p.Node, p.Version, p.Tailnet = cleanText(p.Node, 80), cleanText(p.Version, 40), cleanText(p.Tailnet, 64)
	p.CPUPct, p.MemUsed, p.MemTotal, p.DiskUsed, p.DiskTotal, p.Uptime = clampPct(p.CPUPct), clampBytes(p.MemUsed), clampBytes(p.MemTotal),
		clampBytes(p.DiskUsed), clampBytes(p.DiskTotal), clampBytes(p.Uptime)
	if len(p.Guests) > secproto.MaxPVEGuests {
		p.Guests = p.Guests[:secproto.MaxPVEGuests]
	}
	if len(p.Storages) > secproto.MaxPVEStorages {
		p.Storages = p.Storages[:secproto.MaxPVEStorages]
	}
	guests := make([]secproto.PVEGuest, 0, len(p.Guests))
	for _, g := range p.Guests {
		if g.ID <= 0 || (g.Kind != "lxc" && g.Kind != "qemu") {
			continue
		}
		g.Name, g.Status, g.LAN, g.Tailnet = cleanText(g.Name, 80), cleanText(g.Status, 20), cleanText(g.LAN, 64), cleanText(g.Tailnet, 64)
		g.CPUPct, g.MemUsed, g.MemTotal, g.DiskUsed, g.DiskMax, g.Uptime, g.Backup = clampPct(g.CPUPct), clampBytes(g.MemUsed), clampBytes(g.MemTotal),
			clampBytes(g.DiskUsed), clampBytes(g.DiskMax), clampBytes(g.Uptime), clampBytes(g.Backup)
		guests = append(guests, g)
	}
	p.Guests = guests
	stores := make([]secproto.PVEStorage, 0, len(p.Storages))
	for _, s := range p.Storages {
		if s.Name = cleanText(s.Name, 80); s.Name == "" {
			continue
		}
		s.Type, s.Used, s.Total = cleanText(s.Type, 20), clampBytes(s.Used), clampBytes(s.Total)
		stores = append(stores, s)
	}
	p.Storages = stores
	return p
}

// SavePVE keeps the latest reading of a Proxmox host and one reading an hour of each guest.
func (s *Store) SavePVE(ctx context.Context, vpsID string, p secproto.Proxmox, now time.Time) error {
	vid, err := ParseID(vpsID)
	if err != nil {
		return ErrNotFound
	}
	p = cleanPVE(p, now)
	last, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO pve_hosts (vps_id, updated_at, last) VALUES ($1,$2,$3)
		ON CONFLICT (vps_id) DO UPDATE SET updated_at=EXCLUDED.updated_at, last=EXCLUDED.last`, vid, now, last); err != nil {
		return err
	}
	for _, g := range p.Guests {
		if g.Template {
			continue
		}
		if _, err := s.pool.Exec(ctx, `INSERT INTO pve_guest_samples (vps_id, guest_id, at, running, disk_used, disk_max, mem_used, mem_max)
			VALUES ($1,$2,date_trunc('hour',$3::timestamptz),$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
			vid, g.ID, now, g.Status == "running", g.DiskUsed, g.DiskMax, g.MemUsed, g.MemTotal); err != nil {
			return err
		}
	}
	_, err = s.pool.Exec(ctx, `DELETE FROM pve_guest_samples WHERE vps_id=$1 AND at < $2`, vid, now.Add(-PVESampleRetention))
	return err
}

// PVEHost is a Proxmox host with its latest reading.
type PVEHost struct {
	VPSID     string
	VPSName   string
	UpdatedAt time.Time
	Data      secproto.Proxmox
}

// PVEHosts lists the Proxmox hosts that have reported, the live servers only.
func (s *Store) PVEHosts(ctx context.Context) ([]PVEHost, error) {
	rows, err := s.pool.Query(ctx, `SELECT h.vps_id, v.name, h.updated_at, h.last FROM pve_hosts h JOIN security_vps v ON v.id=h.vps_id
		WHERE v.enabled AND v.archived_at IS NULL ORDER BY v.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PVEHost{}
	for rows.Next() {
		var h PVEHost
		var id uuid.UUID
		var raw []byte
		if err := rows.Scan(&id, &h.VPSName, &h.UpdatedAt, &raw); err != nil {
			return nil, err
		}
		h.VPSID = id.String()
		if json.Unmarshal(raw, &h.Data) != nil {
			continue
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// PVEDiskPoint is one hourly reading of a guest's disk.
type PVEDiskPoint struct {
	At   time.Time
	Used int64
	Max  int64
}

// PVEDiskSeries gives the hourly readings of a guest's disk since from, oldest first.
func (s *Store) PVEDiskSeries(ctx context.Context, vpsID string, guest int, from time.Time) ([]PVEDiskPoint, error) {
	vid, err := ParseID(vpsID)
	if err != nil {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT at, disk_used, disk_max FROM pve_guest_samples WHERE vps_id=$1 AND guest_id=$2 AND at >= $3 ORDER BY at`, vid, guest, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PVEDiskPoint{}
	for rows.Next() {
		var p PVEDiskPoint
		if err := rows.Scan(&p.At, &p.Used, &p.Max); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PVEWasRunning says whether a guest was seen running within the period before now: the way to tell a guest that has
// stopped from one that has always been stopped.
func (s *Store) PVEWasRunning(ctx context.Context, vpsID string, guest int, since time.Time) (bool, error) {
	vid, err := ParseID(vpsID)
	if err != nil {
		return false, ErrNotFound
	}
	var n int
	err = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM pve_guest_samples WHERE vps_id=$1 AND guest_id=$2 AND at >= $3 AND running`, vid, guest, since).Scan(&n)
	return n > 0, err
}

// PVEDaysToFull estimates, from the readings since from, in how many days a disk of this size fills up at the pace it
// has been filling. It returns false when the disk is not growing or there is too little to go by.
func PVEDaysToFull(points []PVEDiskPoint) (float64, bool) {
	if len(points) < 24 {
		return 0, false
	}
	first, last := points[0], points[len(points)-1]
	span := last.At.Sub(first.At).Hours() / 24
	if span < 1 || last.Max <= 0 {
		return 0, false
	}
	perDay := float64(last.Used-first.Used) / span
	if perDay <= 0 {
		return 0, false
	}
	return float64(last.Max-last.Used) / perDay, true
}
