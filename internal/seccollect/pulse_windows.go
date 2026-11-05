//go:build windows

package seccollect

import (
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
)

// pulseOS is the same three readings as on Linux, through the system's own interfaces.
func (h *HostReader) pulseOS() pulseRaw {
	if h.Proc != "/proc" {
		return h.pulseProcfs()
	}
	var r pulseRaw
	if ts, err := cpu.Times(false); err == nil && len(ts) > 0 {
		t := ts[0]
		r.total = uint64((t.User + t.System + t.Idle + t.Irq) * 1000)
		r.busy = r.total - uint64(t.Idle*1000)
		r.haveCPU = true
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		r.memTotal, r.memUsed = int64(vm.Total), int64(vm.Total-vm.Available)
	}
	if nics, err := net.IOCounters(true); err == nil {
		for _, c := range nics {
			if virtualNIC(c.Name) {
				continue
			}
			r.rx += int64(c.BytesRecv)
			r.tx += int64(c.BytesSent)
		}
	}
	return r
}
