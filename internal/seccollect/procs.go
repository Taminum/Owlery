package seccollect

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Taminum/RemnaScope/internal/secproto"
)

const clockTicks = 100 // USER_HZ: what /proc counts CPU time in on every Linux the agent runs on

type procTicks struct {
	start uint64
	ticks uint64
}

var (
	dockerUnit = regexp.MustCompile(`docker-([0-9a-f]{12})[0-9a-f]*\.scope`)
	dockerV1   = regexp.MustCompile(`/docker/([0-9a-f]{12})[0-9a-f]*`)
)

// ParseProcStat reads one /proc/<pid>/stat: the program name, the CPU time (user plus system, in ticks) and the
// moment the process started. The name may hold spaces and brackets, so it is taken between the first "(" and the
// last ")".
func ParseProcStat(text string) (name string, ticks, start uint64, ok bool) {
	l, r := strings.IndexByte(text, '('), strings.LastIndexByte(text, ')')
	if l < 0 || r < l {
		return "", 0, 0, false
	}
	f := strings.Fields(text[r+1:])
	if len(f) < 20 {
		return "", 0, 0, false
	}
	ut, e1 := strconv.ParseUint(f[11], 10, 64)
	st, e2 := strconv.ParseUint(f[12], 10, 64)
	sc, e3 := strconv.ParseUint(f[19], 10, 64)
	if e1 != nil || e2 != nil || e3 != nil {
		return "", 0, 0, false
	}
	return text[l+1 : r], ut + st, sc, true
}

// UnitOf names where a process runs from its cgroup: a systemd service, a Docker container, or nothing.
func UnitOf(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		if m := dockerUnit.FindStringSubmatch(line); m != nil {
			return "docker:" + m[1]
		}
		if m := dockerV1.FindStringSubmatch(line); m != nil {
			return "docker:" + m[1]
		}
	}
	for _, line := range strings.Split(cgroup, "\n") {
		p := strings.Split(strings.TrimSpace(line), "/")
		if len(p) == 0 {
			continue
		}
		last := p[len(p)-1]
		if strings.HasSuffix(last, ".service") && len(last) <= 80 {
			return clean(last, 80)
		}
	}
	return ""
}

// readProcs groups the processes by program name and unit and returns the busiest by processor and by memory.
// The CPU share needs the previous reading: a process that is new, or a pid that was reused, has none yet.
func (h *HostReader) readProcs(now time.Time) []secproto.HostProc {
	entries, err := os.ReadDir(h.Proc)
	if err != nil {
		return nil
	}
	page := int64(os.Getpagesize())
	cur := map[int]procTicks{}
	type group struct {
		name, unit string
		count      int
		ticks      uint64
		rss        int64
	}
	groups := map[string]*group{}
	elapsed := now.Sub(h.prevAt).Seconds()
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		b, err := os.ReadFile(filepath.Join(h.Proc, e.Name(), "stat"))
		if err != nil {
			continue
		}
		name, ticks, start, ok := ParseProcStat(string(b))
		if !ok {
			continue
		}
		cur[pid] = procTicks{start: start, ticks: ticks}
		var rss int64
		if sm, err := os.ReadFile(filepath.Join(h.Proc, e.Name(), "statm")); err == nil {
			if f := strings.Fields(string(sm)); len(f) >= 2 {
				if n, err := strconv.ParseInt(f[1], 10, 64); err == nil {
					rss = n * page
				}
			}
		}
		var unit string
		if cg, err := os.ReadFile(filepath.Join(h.Proc, e.Name(), "cgroup")); err == nil {
			unit = UnitOf(string(cg))
		}
		key := name + "\x00" + unit
		g := groups[key]
		if g == nil {
			g = &group{name: clean(name, 40), unit: unit}
			groups[key] = g
		}
		g.count++
		g.rss += rss
		if p, ok := h.prevProc[pid]; ok && p.start == start && ticks >= p.ticks {
			g.ticks += ticks - p.ticks
		}
	}
	hadPrev := len(h.prevProc) > 0
	h.prevProc, h.prevAt = cur, now
	var all []secproto.HostProc
	for _, g := range groups {
		p := secproto.HostProc{Name: g.name, Unit: g.unit, Count: g.count, RSS: g.rss}
		if hadPrev && elapsed > 0 {
			p.CPU = float64(g.ticks) * 100 / (clockTicks * elapsed)
		}
		all = append(all, p)
	}
	pick := func(less func(a, b secproto.HostProc) bool, n int) []secproto.HostProc {
		s := append([]secproto.HostProc(nil), all...)
		sort.Slice(s, func(i, j int) bool { return less(s[i], s[j]) })
		if len(s) > n {
			s = s[:n]
		}
		return s
	}
	byCPU := pick(func(a, b secproto.HostProc) bool { return a.CPU > b.CPU }, secproto.MaxHostProcs/2)
	byMem := pick(func(a, b secproto.HostProc) bool { return a.RSS > b.RSS }, secproto.MaxHostProcs/2)
	seen := map[string]bool{}
	var out []secproto.HostProc
	for _, p := range append(byCPU, byMem...) {
		k := p.Name + "\x00" + p.Unit
		if !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	return out
}
