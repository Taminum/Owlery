package seccollect

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Taminum/RemnaScope/internal/secproto"
)

// HostReader reads how loaded the host is from /proc and statfs. It runs no command. CPU use is the share of
// non-idle time between two readings, so the first reading has none (-1).
type HostReader struct {
	Proc string // where /proc is; tests point it elsewhere
	Etc  string // where /etc is

	mu                  sync.Mutex
	prevBusy, prevTotal uint64
	havePrev            bool
	prevProc            map[int]procTicks
	prevAt              time.Time
	// ContainersFile lists the running containers (id, name, image, tab-separated), written by a small root unit
	// next to the agent, which has no access to Docker. Empty: container names are not known.
	ContainersFile string
}

func NewHostReader() *HostReader { return &HostReader{Proc: "/proc", Etc: "/etc"} }

func (h *HostReader) read(name string) string {
	b, err := os.ReadFile(filepath.Join(h.Proc, name))
	if err != nil {
		return ""
	}
	return string(b)
}

// ParseCPUStat returns the busy and total jiffies of the first "cpu" line of /proc/stat.
func ParseCPUStat(text string) (busy, total uint64, ok bool) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != "cpu" {
			continue
		}
		var v []uint64
		for _, x := range f[1:] {
			n, err := strconv.ParseUint(x, 10, 64)
			if err != nil {
				return 0, 0, false
			}
			v = append(v, n)
		}
		// user nice system idle iowait irq softirq steal, then guest and guest_nice, which are inside user already.
		n := len(v)
		if n > 8 {
			n = 8
		}
		for _, x := range v[:n] {
			total += x
		}
		idle := v[3]
		if len(v) > 4 {
			idle += v[4]
		}
		return total - idle, total, true
	}
	return 0, 0, false
}

// ParseMeminfo returns the values of /proc/meminfo in bytes.
func ParseMeminfo(text string) map[string]int64 {
	out := map[string]int64{}
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		n, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		if len(f) > 1 && strings.EqualFold(f[1], "kB") {
			n *= 1024
		}
		out[k] = n
	}
	return out
}

func parseLoad(text string) (l1, l5, l15 float64) {
	f := strings.Fields(text)
	if len(f) >= 3 {
		l1, _ = strconv.ParseFloat(f[0], 64)
		l5, _ = strconv.ParseFloat(f[1], 64)
		l15, _ = strconv.ParseFloat(f[2], 64)
	}
	return
}

// ParseNetDev sums the counters of the real interfaces: not the loopback, not the bridges and virtual pairs
// that containers and tunnels make, which would count the same traffic twice.
func ParseNetDev(text string) (rx, tx int64) {
	for _, line := range strings.Split(text, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		skip := name == "lo"
		for _, p := range []string{"veth", "docker", "br-", "virbr", "awg", "wg", "tun", "tap"} {
			skip = skip || strings.HasPrefix(name, p)
		}
		if skip {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		r, e1 := strconv.ParseInt(f[0], 10, 64)
		t, e2 := strconv.ParseInt(f[8], 10, 64)
		if e1 == nil && e2 == nil {
			rx += r
			tx += t
		}
	}
	return
}

// realFS are the file systems whose use is worth showing.
var realFS = map[string]bool{"ext4": true, "ext3": true, "ext2": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true}

type mountEntry struct{ Dev, Mount, FS string }

// ParseMounts keeps the mounts on real file systems, one per device.
func ParseMounts(text string) []mountEntry {
	var out []mountEntry
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !realFS[f[2]] || seen[f[0]] {
			continue
		}
		mount := strings.ReplaceAll(f[1], "\\040", " ")
		if strings.HasPrefix(mount, "/var/lib/docker") || strings.HasPrefix(mount, "/var/snap") || strings.HasPrefix(mount, "/snap") {
			continue
		}
		seen[f[0]] = true
		out = append(out, mountEntry{Dev: f[0], Mount: mount, FS: f[2]})
	}
	return out
}

func osPretty(text string) string {
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
			return strings.Trim(v, "\"'")
		}
	}
	return ""
}

func cpuModel(text string) (model string, cpus int) {
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "model name":
			if model == "" {
				model = strings.TrimSpace(v)
			}
		case "processor":
			cpus++
		}
	}
	return
}

func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// Read takes one reading of the host.
func (h *HostReader) Read(now time.Time) secproto.Host {
	out := secproto.Host{Type: "host", At: now.UTC(), CPUPct: -1, Arch: runtime.GOARCH}
	if busy, total, ok := ParseCPUStat(h.read("stat")); ok {
		h.mu.Lock()
		if h.havePrev && total > h.prevTotal && busy >= h.prevBusy {
			out.CPUPct = float64(busy-h.prevBusy) * 100 / float64(total-h.prevTotal)
			if out.CPUPct > 100 {
				out.CPUPct = 100
			}
		}
		h.prevBusy, h.prevTotal, h.havePrev = busy, total, true
		h.mu.Unlock()
	}
	out.Load1, out.Load5, out.Load15 = parseLoad(h.read("loadavg"))
	mem := ParseMeminfo(h.read("meminfo"))
	out.MemTotal = mem["MemTotal"]
	if avail, ok := mem["MemAvailable"]; ok {
		out.MemUsed = out.MemTotal - avail
	} else {
		out.MemUsed = out.MemTotal - mem["MemFree"] - mem["Buffers"] - mem["Cached"]
	}
	out.SwapTotal = mem["SwapTotal"]
	out.SwapUsed = mem["SwapTotal"] - mem["SwapFree"]
	if f := strings.Fields(h.read("uptime")); len(f) > 0 {
		if v, err := strconv.ParseFloat(f[0], 64); err == nil {
			out.UptimeSec = int64(v)
		}
	}
	out.NetRX, out.NetTX = ParseNetDev(h.read("net/dev"))
	out.Kernel = clean(h.read("sys/kernel/osrelease"), 80)
	model, cpus := cpuModel(h.read("cpuinfo"))
	out.CPUModel, out.CPUs = clean(model, 120), cpus
	if b, err := os.ReadFile(filepath.Join(h.Etc, "os-release")); err == nil {
		out.OS = clean(osPretty(string(b)), 80)
	}
	for _, m := range ParseMounts(h.read("mounts")) {
		if len(out.Disks) >= secproto.MaxHostDisks {
			break
		}
		if total, used, err := diskUsage(m.Mount); err == nil && total > 0 {
			out.Disks = append(out.Disks, secproto.HostDisk{Mount: clean(m.Mount, 120), FS: m.FS, Total: total, Used: used})
		}
	}
	out.Procs, out.Units = h.readProcs(now)
	return out
}
