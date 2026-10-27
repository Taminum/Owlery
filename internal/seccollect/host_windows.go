//go:build windows

package seccollect

import (
	"errors"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/Taminum/Owlery/internal/secproto"
)

// readOS reads a Windows host through the system's own interfaces (gopsutil wraps them). Tests that point Proc at a
// directory of Linux files still read those, so the parsing is tested on every system.
func (h *HostReader) readOS(now time.Time) secproto.Host {
	if h.Proc != "/proc" {
		return h.readProcfs(now)
	}
	out := secproto.Host{Type: "host", At: now.UTC(), CPUPct: -1, Arch: runtime.GOARCH}
	if ts, err := cpu.Times(false); err == nil && len(ts) > 0 {
		// Milliseconds, so that the same integer fields as on Linux hold the counters.
		t := ts[0]
		total := uint64((t.User + t.System + t.Idle + t.Irq) * 1000)
		busy := total - uint64(t.Idle*1000)
		h.mu.Lock()
		if h.havePrev && total > h.prevTotal && busy >= h.prevBusy {
			out.CPUPct = min(float64(busy-h.prevBusy)*100/float64(total-h.prevTotal), 100)
		}
		h.prevBusy, h.prevTotal, h.havePrev = busy, total, true
		h.mu.Unlock()
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		out.MemTotal, out.MemUsed = int64(vm.Total), int64(vm.Total-vm.Available)
	}
	if sw, err := mem.SwapMemory(); err == nil {
		out.SwapTotal, out.SwapUsed = int64(sw.Total), int64(sw.Used)
	}
	st := staticInfo(now)
	out.OS, out.Kernel, out.CPUModel, out.CPUs = st.os, st.kernel, st.cpuModel, st.cpus
	if up, err := host.Uptime(); err == nil {
		out.UptimeSec = int64(up)
	}
	if nics, err := net.IOCounters(true); err == nil {
		for _, c := range nics {
			if virtualNIC(c.Name) {
				continue
			}
			out.NetRX += int64(c.BytesRecv)
			out.NetTX += int64(c.BytesSent)
			out.NetRXPkts += int64(c.PacketsRecv)
			out.NetTXPkts += int64(c.PacketsSent)
		}
	}
	if conns, err := net.Connections("tcp"); err == nil {
		for _, c := range conns {
			switch c.Status {
			case "ESTABLISHED":
				out.Estab++
			case "SYN_RECEIVED", "SYN_RECV":
				out.SynRecv++
			}
		}
	}
	if parts, err := disk.Partitions(false); err == nil {
		for _, p := range parts {
			if len(out.Disks) >= secproto.MaxHostDisks {
				break
			}
			if p.Fstype == "" || strings.Contains(strings.ToLower(strings.Join(p.Opts, ",")), "cdrom") {
				continue
			}
			if u, err := disk.Usage(p.Mountpoint); err == nil && u.Total > 0 {
				out.Disks = append(out.Disks, secproto.HostDisk{Mount: clean(p.Mountpoint, 120), FS: strings.ToLower(p.Fstype), Total: int64(u.Total), Used: int64(u.Used)})
			}
		}
	}
	out.Procs, out.Units = h.windowsProcs(now)
	return out
}

// What the machine is changes only with an upgrade, and asking Windows for it goes through WMI, which costs a
// noticeable share of a core each time. It is read once an hour.
type machineInfo struct {
	os, kernel, cpuModel string
	cpus                 int
	at                   time.Time
}

var (
	infoMu    sync.Mutex
	infoCache machineInfo
)

func staticInfo(now time.Time) machineInfo {
	infoMu.Lock()
	defer infoMu.Unlock()
	if !infoCache.at.IsZero() && now.Sub(infoCache.at) < time.Hour {
		return infoCache
	}
	var m machineInfo
	if hi, err := host.Info(); err == nil {
		m.os = clean(strings.TrimSpace(hi.Platform+" "+hi.PlatformVersion), 80)
		m.kernel = clean(hi.KernelVersion, 80)
	}
	if ci, err := cpu.Info(); err == nil && len(ci) > 0 {
		m.cpuModel = clean(ci[0].ModelName, 120)
	}
	if n, err := cpu.Counts(true); err == nil {
		m.cpus = n
	}
	m.at = now
	infoCache = m
	return m
}

// virtualNIC says whether an adapter only carries traffic that real adapters carry too, or none at all.
func virtualNIC(name string) bool {
	n := strings.ToLower(name)
	for _, s := range []string{"loopback", "isatap", "teredo", "vethernet", "hyper-v virtual", "bluetooth", "6to4"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// windowsProcs groups the processes by program and by the service they run as. Processor use is the processor time
// a process spent since the previous reading, in percent of one core, as on Linux.
func (h *HostReader) windowsProcs(now time.Time) ([]secproto.HostProc, []secproto.HostUnit) {
	ps, err := process.Processes()
	if err != nil {
		return nil, nil
	}
	services := servicePIDs()
	type group struct {
		name, unit string
		count      int
		cpu        float64
		rss        int64
	}
	groups := map[string]*group{}
	units := map[string]*group{}
	cur := map[int]procTicks{}
	elapsed := now.Sub(h.prevAt).Seconds()
	hadPrev := len(h.prevProc) > 0
	for _, p := range ps {
		pid := int(p.Pid)
		if pid <= 4 { // the idle process and the kernel
			continue
		}
		name, err := p.Name()
		if err != nil || name == "" {
			continue
		}
		name = strings.TrimSuffix(name, ".exe")
		start, _ := p.CreateTime()
		var ticks uint64
		if t, err := p.Times(); err == nil {
			ticks = uint64((t.User + t.System) * 1000)
		}
		cur[pid] = procTicks{start: uint64(start), ticks: ticks}
		var rss int64
		if m, err := p.MemoryInfo(); err == nil {
			rss = int64(m.RSS)
		}
		var used float64
		if prev, ok := h.prevProc[pid]; ok && hadPrev && elapsed > 0 && prev.start == uint64(start) && ticks >= prev.ticks {
			used = float64(ticks-prev.ticks) / 1000 * 100 / elapsed
		}
		unit := ""
		if s := services[uint32(pid)]; s != "" {
			unit = s + ".service"
		}
		key := name + "\x00" + unit
		g := groups[key]
		if g == nil {
			g = &group{name: clean(name, 40), unit: unit}
			groups[key] = g
		}
		g.count++
		g.rss += rss
		g.cpu += used
		if unit != "" {
			u := units[unit]
			if u == nil {
				u = &group{unit: unit}
				units[unit] = u
			}
			u.count++
			u.rss += rss
			u.cpu += used
		}
	}
	h.prevProc, h.prevAt = cur, now
	var all []secproto.HostProc
	for _, g := range groups {
		all = append(all, secproto.HostProc{Name: g.name, Unit: g.unit, Count: g.count, CPU: g.cpu, RSS: g.rss})
	}
	var us []secproto.HostUnit
	for _, u := range units {
		us = append(us, secproto.HostUnit{Unit: u.unit, Count: u.count, CPU: u.cpu, RSS: u.rss})
	}
	return topProcs(all, us)
}

// servicePIDs maps the process of every running service to the service's name. Several services may share one
// process (svchost); the process then counts for the first of them.
func servicePIDs() map[uint32]string {
	out := map[uint32]string{}
	m, err := mgr.Connect()
	if err != nil {
		return out
	}
	defer m.Disconnect()
	names, err := m.ListServices()
	if err != nil {
		return out
	}
	for _, n := range names {
		s, err := m.OpenService(n)
		if err != nil {
			continue
		}
		st, err := s.Query()
		s.Close()
		if err != nil || st.ProcessId == 0 {
			continue
		}
		if _, ok := out[st.ProcessId]; !ok {
			out[st.ProcessId] = n
		}
	}
	return out
}

func diskUsage(path string) (int64, int64, error) {
	var free, total, totalFree uint64
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
	}
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil {
		return 0, 0, err
	}
	if total == 0 {
		return 0, 0, errors.New("empty volume")
	}
	return int64(total), int64(total - totalFree), nil
}
