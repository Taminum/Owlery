package seccollect

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// NetCounters are the counters of the real interfaces since boot.
type NetCounters struct {
	RXBytes, TXBytes, RXPkts, TXPkts int64
}

// ParseNetCounters sums /proc/net/dev over the real interfaces (not the loopback, not the bridges and virtual
// pairs that containers and tunnels make, which would count the same traffic twice).
func ParseNetCounters(text string) NetCounters {
	var c NetCounters
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
		if len(f) < 10 {
			continue
		}
		rb, e1 := strconv.ParseInt(f[0], 10, 64)
		rp, e2 := strconv.ParseInt(f[1], 10, 64)
		tb, e3 := strconv.ParseInt(f[8], 10, 64)
		tp, e4 := strconv.ParseInt(f[9], 10, 64)
		if e1 == nil && e2 == nil && e3 == nil && e4 == nil {
			c.RXBytes += rb
			c.RXPkts += rp
			c.TXBytes += tb
			c.TXPkts += tp
		}
	}
	return c
}

// ParseTCPStates counts the established and half-open (SYN_RECV) connections in /proc/net/tcp or tcp6. A flood of
// SYN packets shows as thousands of half-open ones.
func ParseTCPStates(text string) (estab, synRecv int) {
	for i, line := range strings.Split(text, "\n") {
		if i == 0 {
			continue // the header
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		switch f[3] {
		case "01":
			estab++
		case "03":
			synRecv++
		}
	}
	return
}

// ParseTcpExt reads the TcpExt counters of /proc/net/netstat into a map by name.
func ParseTcpExt(text string) map[string]int64 {
	out := map[string]int64{}
	lines := strings.Split(text, "\n")
	for i := 0; i+1 < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "TcpExt:") || !strings.HasPrefix(lines[i+1], "TcpExt:") {
			continue
		}
		names, vals := strings.Fields(lines[i])[1:], strings.Fields(lines[i+1])[1:]
		for j := 0; j < len(names) && j < len(vals); j++ {
			if n, err := strconv.ParseInt(vals[j], 10, 64); err == nil {
				out[names[j]] = n
			}
		}
		break
	}
	return out
}

// readLimited reads a /proc file that may be very large during a flood; beyond the limit it is cut.
func (h *HostReader) readLimited(name string, limit int) string {
	f, err := os.Open(filepath.Join(h.Proc, name))
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, limit)
	n, _ := f.Read(buf)
	// A single Read may return less than the file holds; read on until the limit or the end.
	for n < limit {
		m, err := f.Read(buf[n:])
		n += m
		if err != nil || m == 0 {
			break
		}
	}
	return string(buf[:n])
}

func (h *HostReader) readInt(name string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(h.read(name)), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}
