package store

import (
	"context"
	"encoding/json"
	"math"
	"time"

	"github.com/google/uuid"

	"github.com/Taminum/RemnaScope/internal/secproto"
)

// Alert kinds about the load of a monitored server. They are the owner's, like the servers' own list.
const (
	AlertHostDisk  = "host_disk"  // a file system is nearly full
	AlertHostCPU   = "host_cpu"   // the processor has been busy for a long time
	AlertHostMem   = "host_mem"   // memory has been nearly used up for a while
	AlertHostFlood = "host_flood" // traffic or connections far above the usual, or the kernel's queues overflowing
)

// SaveHost keeps what a security agent said about its host: the machine, the latest reading, and one sample a
// minute. Numbers are clamped: an agent is trusted to report, not to be sensible.
func (s *Store) SaveHost(ctx context.Context, vpsID string, h secproto.Host, now time.Time) error {
	vid, err := ParseID(vpsID)
	if err != nil {
		return ErrNotFound
	}
	nz := func(v int64) int64 {
		if v < 0 {
			return 0
		}
		return v
	}
	if len(h.Disks) > secproto.MaxHostDisks {
		h.Disks = h.Disks[:secproto.MaxHostDisks]
	}
	if len(h.Procs) > secproto.MaxHostProcs {
		h.Procs = h.Procs[:secproto.MaxHostProcs]
	}
	procs := make([]secproto.HostProc, 0, len(h.Procs))
	for _, p := range h.Procs {
		name := cleanText(p.Name, 40)
		if name == "" || p.Count < 1 {
			continue
		}
		cpu := p.CPU
		if math.IsNaN(cpu) || cpu < 0 {
			cpu = 0
		}
		if cpu > 100000 {
			cpu = 100000
		}
		procs = append(procs, secproto.HostProc{Name: name, Unit: cleanText(p.Unit, 80), Label: cleanText(p.Label, 80), Count: p.Count, CPU: math.Round(cpu*10) / 10, RSS: nz(p.RSS)})
	}
	if len(h.Units) > secproto.MaxHostUnits {
		h.Units = h.Units[:secproto.MaxHostUnits]
	}
	units := make([]secproto.HostUnit, 0, len(h.Units))
	for _, u := range h.Units {
		unit := cleanText(u.Unit, 80)
		if unit == "" || u.Count < 1 {
			continue
		}
		cpu := u.CPU
		if math.IsNaN(cpu) || cpu < 0 {
			cpu = 0
		}
		if cpu > 100000 {
			cpu = 100000
		}
		units = append(units, secproto.HostUnit{Unit: unit, Label: cleanText(u.Label, 80), Count: u.Count, CPU: math.Round(cpu*10) / 10, RSS: nz(u.RSS)})
	}
	h.MemTotal, h.MemUsed, h.SwapTotal, h.SwapUsed = nz(h.MemTotal), nz(h.MemUsed), nz(h.SwapTotal), nz(h.SwapUsed)
	if h.MemUsed > h.MemTotal && h.MemTotal > 0 {
		h.MemUsed = h.MemTotal
	}
	last, err := json.Marshal(struct {
		At        time.Time           `json:"at"`
		CPUPct    float64             `json:"cpu"`
		Load1     float64             `json:"l1"`
		Load5     float64             `json:"l5"`
		Load15    float64             `json:"l15"`
		MemUsed   int64               `json:"mem_used"`
		SwapUsed  int64               `json:"swap_used"`
		UptimeSec int64               `json:"up"`
		NetRX     int64               `json:"rx"`
		NetTX     int64               `json:"tx"`
		Disks     []secproto.HostDisk `json:"disks"`
		Procs     []secproto.HostProc `json:"procs"`
		Units     []secproto.HostUnit `json:"units"`
		Estab     int                 `json:"estab"`
		SynRecv   int                 `json:"syn"`
	}{now, h.CPUPct, h.Load1, h.Load5, h.Load15, h.MemUsed, h.SwapUsed, h.UptimeSec, nz(h.NetRX), nz(h.NetTX), h.Disks, procs, units, h.Estab, h.SynRecv})
	if err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO host_info (vps_id, updated_at, os, kernel, arch, cpu_model, cpus, mem_total, swap_total, last)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (vps_id) DO UPDATE SET updated_at=EXCLUDED.updated_at, os=EXCLUDED.os, kernel=EXCLUDED.kernel, arch=EXCLUDED.arch,
			cpu_model=EXCLUDED.cpu_model, cpus=EXCLUDED.cpus, mem_total=EXCLUDED.mem_total, swap_total=EXCLUDED.swap_total, last=EXCLUDED.last`,
		vid, now, cleanText(h.OS, 80), cleanText(h.Kernel, 80), cleanText(h.Arch, 20), cleanText(h.CPUModel, 120), h.CPUs, h.MemTotal, h.SwapTotal, last); err != nil {
		return err
	}
	var cpu any
	if h.CPUPct >= 0 && h.CPUPct <= 100 && !math.IsNaN(h.CPUPct) {
		cpu = float32(h.CPUPct)
	}
	var du, dt int64
	if len(h.Disks) > 0 {
		d := h.Disks[0]
		for _, x := range h.Disks {
			if x.Mount == "/" {
				d = x
			}
		}
		du, dt = nz(d.Used), nz(d.Total)
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO host_samples (vps_id, at, cpu, load1, mem_used, mem_total, disk_used, disk_total, net_rx, net_tx,
			rx_pkts, tx_pkts, estab, syn_recv, cookies, listen_drops)
		VALUES ($1, date_trunc('minute', $2::timestamptz), $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) ON CONFLICT DO NOTHING`,
		vid, now, cpu, float32(h.Load1), h.MemUsed, h.MemTotal, du, dt, nz(h.NetRX), nz(h.NetTX),
		nz(h.NetRXPkts), nz(h.NetTXPkts), int32(max(0, min(h.Estab, 1<<30))), int32(max(0, min(h.SynRecv, 1<<30))), nz(h.Syncookie), nz(h.ListenDrp))
	return err
}

// PurgeHostSamples drops samples older than the cut-off.
func (s *Store) PurgeHostSamples(ctx context.Context, before time.Time) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM host_samples WHERE at < $1`, before)
	return err
}

// HostRow is one server as the resources page shows it.
type HostRow struct {
	ID        string              `json:"id"`
	Name      string              `json:"name"`
	Online    bool                `json:"online"`
	AgentSeen *time.Time          `json:"agent_seen"`
	HasData   bool                `json:"has_data"`
	UpdatedAt *time.Time          `json:"updated_at"`
	OS        string              `json:"os"`
	Kernel    string              `json:"kernel"`
	Arch      string              `json:"arch"`
	CPUModel  string              `json:"cpu_model"`
	CPUs      int                 `json:"cpus"`
	MemTotal  int64               `json:"mem_total"`
	SwapTotal int64               `json:"swap_total"`
	CPUPct    *float64            `json:"cpu"`
	Load1     float64             `json:"load1"`
	Load5     float64             `json:"load5"`
	Load15    float64             `json:"load15"`
	MemUsed   int64               `json:"mem_used"`
	SwapUsed  int64               `json:"swap_used"`
	UptimeSec int64               `json:"uptime"`
	Disks     []secproto.HostDisk `json:"disks"`
	Procs     []secproto.HostProc `json:"procs"`
	Units     []secproto.HostUnit `json:"units"`
	Estab     int                 `json:"estab"`
	SynRecv   int                 `json:"syn_recv"`
	RXBps     float64             `json:"rx_bps"`
	TXBps     float64             `json:"tx_bps"`
	RXPps     float64             `json:"rx_pps"`
	CPUSpark  []*float64          `json:"cpu_spark"` // the last hour, a point a minute
	MemSpark  []float64           `json:"mem_spark"` // percent
}

// Hosts lists the servers the scope can see with their latest reading. A server whose agent has never reported
// a reading is listed without data, so that a missing agent is visible.
func (s *Store) Hosts(ctx context.Context, sc Scope, now time.Time) ([]HostRow, error) {
	pred, args := vpsVisible(sc, 0)
	rows, err := s.pool.Query(ctx, `SELECT v.id, v.name, a.last_seen, i.updated_at, COALESCE(i.os,''), COALESCE(i.kernel,''), COALESCE(i.arch,''), COALESCE(i.cpu_model,''),
			COALESCE(i.cpus,0), COALESCE(i.mem_total,0), COALESCE(i.swap_total,0), COALESCE(i.last, '{}'::jsonb)
		FROM security_vps v
		LEFT JOIN security_agents a ON a.vps_id = v.id AND a.status = 'active'
		LEFT JOIN host_info i ON i.vps_id = v.id
		WHERE v.archived_at IS NULL AND `+pred+` ORDER BY lower(v.name), v.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HostRow{}
	for rows.Next() {
		var h HostRow
		var id uuid.UUID
		var last []byte
		if err := rows.Scan(&id, &h.Name, &h.AgentSeen, &h.UpdatedAt, &h.OS, &h.Kernel, &h.Arch, &h.CPUModel, &h.CPUs, &h.MemTotal, &h.SwapTotal, &last); err != nil {
			return nil, err
		}
		h.ID = id.String()
		h.Online = h.UpdatedAt != nil && now.Sub(*h.UpdatedAt) < 2*time.Minute
		h.HasData = h.UpdatedAt != nil
		h.Disks = []secproto.HostDisk{}
		h.Procs = []secproto.HostProc{}
		h.Units = []secproto.HostUnit{}
		if h.HasData {
			var l struct {
				CPU      float64             `json:"cpu"`
				L1       float64             `json:"l1"`
				L5       float64             `json:"l5"`
				L15      float64             `json:"l15"`
				MemUsed  int64               `json:"mem_used"`
				SwapUsed int64               `json:"swap_used"`
				Up       int64               `json:"up"`
				Disks    []secproto.HostDisk `json:"disks"`
				Procs    []secproto.HostProc `json:"procs"`
				Units    []secproto.HostUnit `json:"units"`
				Estab    int                 `json:"estab"`
				Syn      int                 `json:"syn"`
			}
			if json.Unmarshal(last, &l) == nil {
				if l.CPU >= 0 {
					c := l.CPU
					h.CPUPct = &c
				}
				h.Load1, h.Load5, h.Load15, h.MemUsed, h.SwapUsed, h.UptimeSec = l.L1, l.L5, l.L15, l.MemUsed, l.SwapUsed, l.Up
				if l.Disks != nil {
					h.Disks = l.Disks
				}
				if l.Procs != nil {
					h.Procs = l.Procs
				}
				if l.Units != nil {
					h.Units = l.Units
				}
				h.Estab, h.SynRecv = l.Estab, l.Syn
			}
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].CPUSpark, out[i].MemSpark = []*float64{}, []float64{}
		vid, _ := uuid.Parse(out[i].ID)
		sr, err := s.pool.Query(ctx, `SELECT cpu, CASE WHEN mem_total > 0 THEN mem_used * 100.0 / mem_total ELSE 0 END FROM host_samples
			WHERE vps_id=$1 AND at > $2 ORDER BY at`, vid, now.Add(-time.Hour))
		if err != nil {
			return nil, err
		}
		for sr.Next() {
			var c *float32
			var m float64
			if err := sr.Scan(&c, &m); err != nil {
				sr.Close()
				return nil, err
			}
			var cp *float64
			if c != nil {
				v := float64(*c)
				cp = &v
			}
			out[i].CPUSpark = append(out[i].CPUSpark, cp)
			out[i].MemSpark = append(out[i].MemSpark, m)
		}
		sr.Close()
		two, err := s.pool.Query(ctx, `SELECT at, net_rx, net_tx, rx_pkts FROM host_samples WHERE vps_id=$1 ORDER BY at DESC LIMIT 2`, vid)
		if err != nil {
			return nil, err
		}
		var ats []time.Time
		var rx, tx, rp []int64
		for two.Next() {
			var at time.Time
			var a, b, c int64
			if err := two.Scan(&at, &a, &b, &c); err != nil {
				two.Close()
				return nil, err
			}
			ats, rx, tx, rp = append(ats, at), append(rx, a), append(tx, b), append(rp, c)
		}
		two.Close()
		if len(ats) == 2 {
			if dt := ats[0].Sub(ats[1]).Seconds(); dt > 0 && rx[0] >= rx[1] && tx[0] >= tx[1] && rp[0] >= rp[1] {
				out[i].RXBps, out[i].TXBps, out[i].RXPps = float64(rx[0]-rx[1])/dt, float64(tx[0]-tx[1])/dt, float64(rp[0]-rp[1])/dt
			}
		}
	}
	return out, nil
}

// HostPoint is one point of the history of a server.
type HostPoint struct {
	At      time.Time `json:"at"`
	CPU     *float64  `json:"cpu"`
	Load1   float64   `json:"load1"`
	MemPct  float64   `json:"mem_pct"`
	DiskPct float64   `json:"disk_pct"`
	RXBps   float64   `json:"rx_bps"`
	TXBps   float64   `json:"tx_bps"`
	RXPps   float64   `json:"rx_pps"`
	TXPps   float64   `json:"tx_pps"`
	Estab   float64   `json:"estab"`
	SynRecv float64   `json:"syn_recv"`
}

// HostSeries returns the history of one server over the last hours, averaged into at most about maxPoints points.
// The network counters become rates; a counter that went down (a reboot) gives no rate for that step.
func (s *Store) HostSeries(ctx context.Context, sc Scope, vpsID string, hours int, now time.Time, maxPoints int) ([]HostPoint, error) {
	vid, err := ParseID(vpsID)
	if err != nil {
		return nil, ErrNotFound
	}
	pred, args := vpsVisible(sc, 1)
	var ok bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM security_vps v WHERE v.id=$1 AND v.archived_at IS NULL AND `+pred+`)`, append([]any{vid}, args...)...).Scan(&ok); err != nil || !ok {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT at, cpu, load1, mem_used, mem_total, disk_used, disk_total, net_rx, net_tx, rx_pkts, tx_pkts, estab, syn_recv FROM host_samples
		WHERE vps_id=$1 AND at > $2 ORDER BY at`, vid, now.Add(-time.Duration(hours)*time.Hour))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type raw struct {
		at             time.Time
		cpu            *float32
		load           float32
		mu, mt, du, dt int64
		rx, tx         int64
		rxp, txp       int64
		estab, syn     int32
	}
	var all []raw
	for rows.Next() {
		var r raw
		if err := rows.Scan(&r.at, &r.cpu, &r.load, &r.mu, &r.mt, &r.du, &r.dt, &r.rx, &r.tx, &r.rxp, &r.txp, &r.estab, &r.syn); err != nil {
			return nil, err
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	step := 1
	if maxPoints > 0 && len(all) > maxPoints {
		step = (len(all) + maxPoints - 1) / maxPoints
	}
	out := []HostPoint{}
	for i := 0; i < len(all); i += step {
		end := i + step
		if end > len(all) {
			end = len(all)
		}
		var p HostPoint
		var cpuSum float64
		var cpuN int
		var lo, mp, dp, es, sy float64
		for _, r := range all[i:end] {
			if r.cpu != nil {
				cpuSum += float64(*r.cpu)
				cpuN++
			}
			lo += float64(r.load)
			es += float64(r.estab)
			sy += float64(r.syn)
			if r.mt > 0 {
				mp += float64(r.mu) * 100 / float64(r.mt)
			}
			if r.dt > 0 {
				dp += float64(r.du) * 100 / float64(r.dt)
			}
		}
		n := float64(end - i)
		p.At = all[end-1].at
		if cpuN > 0 {
			c := cpuSum / float64(cpuN)
			p.CPU = &c
		}
		p.Load1, p.MemPct, p.DiskPct = lo/n, mp/n, dp/n
		p.Estab, p.SynRecv = es/n, sy/n
		first, last := all[i], all[end-1]
		prev := first
		if i > 0 {
			prev = all[i-1]
		}
		if dt := last.at.Sub(prev.at).Seconds(); dt > 0 && last.rx >= prev.rx && last.tx >= prev.tx {
			p.RXBps = float64(last.rx-prev.rx) / dt
			p.TXBps = float64(last.tx-prev.tx) / dt
			if last.rxp >= prev.rxp && last.txp >= prev.txp {
				p.RXPps = float64(last.rxp-prev.rxp) / dt
				p.TXPps = float64(last.txp-prev.txp) / dt
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// HostAlertState is what the alerts look at for one server.
type HostAlertState struct {
	VPSID  string
	Name   string
	Online bool
	Disks  []secproto.HostDisk
	CPUAvg *float64 // the mean of the last ten minutes, when there are at least eight samples
	MemAvg *float64 // the mean memory use in percent over the last five minutes, when there are at least four samples
}

func (s *Store) HostAlertStates(ctx context.Context, now time.Time) ([]HostAlertState, error) {
	rows, err := s.pool.Query(ctx, `SELECT v.id, v.name, i.updated_at, COALESCE(i.last, '{}'::jsonb)
		FROM security_vps v JOIN host_info i ON i.vps_id = v.id WHERE v.archived_at IS NULL AND v.enabled`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostAlertState
	for rows.Next() {
		var st HostAlertState
		var id uuid.UUID
		var upd time.Time
		var last []byte
		if err := rows.Scan(&id, &st.Name, &upd, &last); err != nil {
			return nil, err
		}
		st.VPSID = id.String()
		st.Online = now.Sub(upd) < 5*time.Minute
		var l struct {
			Disks []secproto.HostDisk `json:"disks"`
		}
		_ = json.Unmarshal(last, &l)
		st.Disks = l.Disks
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		vid, _ := uuid.Parse(out[i].VPSID)
		var cpu *float64
		var n int
		if err := s.pool.QueryRow(ctx, `SELECT avg(cpu)::float8, count(cpu) FROM host_samples WHERE vps_id=$1 AND at > $2 AND cpu IS NOT NULL`, vid, now.Add(-10*time.Minute)).Scan(&cpu, &n); err == nil && n >= 8 {
			out[i].CPUAvg = cpu
		}
		var mem *float64
		if err := s.pool.QueryRow(ctx, `SELECT avg(mem_used * 100.0 / NULLIF(mem_total, 0))::float8, count(*) FROM host_samples WHERE vps_id=$1 AND at > $2 AND mem_total > 0`, vid, now.Add(-5*time.Minute)).Scan(&mem, &n); err == nil && n >= 4 {
			out[i].MemAvg = mem
		}
	}
	return out, nil
}

// FloodSample is one minute sample with the counters that a flood moves.
type FloodSample struct {
	At                   time.Time
	RX, RXPkts           int64
	Estab, SynRecv       int
	Cookies, ListenDrops int64
}

// HostFloodState is what the flood check looks at for one server: the last minutes, and the day before them as
// the picture of what is usual.
type HostFloodState struct {
	VPSID    string
	Name     string
	Online   bool
	Recent   []FloodSample // the last twelve minutes, oldest first
	Baseline []FloodSample // from a day ago to a quarter of an hour ago
}

func (s *Store) HostFloodStates(ctx context.Context, now time.Time) ([]HostFloodState, error) {
	rows, err := s.pool.Query(ctx, `SELECT v.id, v.name, i.updated_at FROM security_vps v JOIN host_info i ON i.vps_id = v.id WHERE v.archived_at IS NULL AND v.enabled`)
	if err != nil {
		return nil, err
	}
	var out []HostFloodState
	for rows.Next() {
		var st HostFloodState
		var id uuid.UUID
		var upd time.Time
		if err := rows.Scan(&id, &st.Name, &upd); err != nil {
			rows.Close()
			return nil, err
		}
		st.VPSID, st.Online = id.String(), now.Sub(upd) < 5*time.Minute
		out = append(out, st)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	load := func(vid uuid.UUID, from, to time.Time) ([]FloodSample, error) {
		r, err := s.pool.Query(ctx, `SELECT at, net_rx, rx_pkts, estab, syn_recv, cookies, listen_drops FROM host_samples WHERE vps_id=$1 AND at > $2 AND at <= $3 ORDER BY at`, vid, from, to)
		if err != nil {
			return nil, err
		}
		defer r.Close()
		var xs []FloodSample
		for r.Next() {
			var x FloodSample
			if err := r.Scan(&x.At, &x.RX, &x.RXPkts, &x.Estab, &x.SynRecv, &x.Cookies, &x.ListenDrops); err != nil {
				return nil, err
			}
			xs = append(xs, x)
		}
		return xs, r.Err()
	}
	for i := range out {
		vid, _ := uuid.Parse(out[i].VPSID)
		if out[i].Recent, err = load(vid, now.Add(-13*time.Minute), now); err != nil {
			return nil, err
		}
		if out[i].Baseline, err = load(vid, now.Add(-24*time.Hour), now.Add(-13*time.Minute)); err != nil {
			return nil, err
		}
	}
	return out, nil
}
