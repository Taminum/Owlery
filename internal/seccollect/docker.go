package seccollect

import (
	"bufio"
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

// DockerReader turns the files a small root unit writes (the agent has no access to Docker itself) into the containers of
// this machine. The unit lists what a page shows and nothing else, and the reader checks every field again.
type DockerReader struct {
	File       string // one JSON object per container; the statistics are in the file beside it, named -stats
	StaleAfter time.Duration
	hist       map[string][]restartSample
}

type restartSample struct {
	at    time.Time
	count int
}

func NewDocker(file string) *DockerReader {
	return &DockerReader{File: file, StaleAfter: 3 * time.Minute, hist: map[string][]restartSample{}}
}

func (d *DockerReader) statsFile() string {
	return strings.TrimSuffix(d.File, ".jsonl") + "-stats.jsonl"
}

var containerNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$`)

var dockerStates = map[string]bool{"running": true, "restarting": true, "paused": true, "created": true, "exited": true, "dead": true, "removing": true}

// Collect reads the list. A machine without the unit (so without Docker, as far as the agent can tell) is "not installed",
// and a list nobody has refreshed for a few minutes is "stopped": the unit has died, so the state shown would be old.
func (d *DockerReader) Collect(now time.Time) Snapshot {
	snap := Snapshot{Category: secproto.CatDocker}
	fi, err := os.Stat(d.File)
	switch {
	case err != nil:
		snap.Status = secproto.StatusNotInstalled
		return snap
	case now.Sub(fi.ModTime()) > d.StaleAfter:
		snap.Status = secproto.StatusStopped
		return snap
	}
	list := d.parse(d.File, now)
	stats := parseDockerStats(d.statsFile())
	for i := range list {
		if st, ok := stats[list[i].ID]; ok {
			list[i].CPU, list[i].Mem = st.cpu, st.mem
		}
	}
	sort.Slice(list, func(a, b int) bool { return list[a].Name < list[b].Name })
	if len(list) > secproto.MaxContainers {
		list = list[:secproto.MaxContainers]
	}
	snap.Status = secproto.StatusOK
	snap.Data = secproto.Docker{Containers: list}
	return snap
}

type inspected struct {
	ID       string                                 `json:"id"`
	Name     string                                 `json:"name"`
	Image    string                                 `json:"image"`
	State    string                                 `json:"state"`
	Exit     int                                    `json:"exit"`
	Started  string                                 `json:"started"`
	Finished string                                 `json:"finished"`
	Restarts int                                    `json:"restarts"`
	Health   string                                 `json:"health"`
	Policy   string                                 `json:"policy"`
	Ports    map[string][]struct{ HostPort string } `json:"ports"`
}

func (d *DockerReader) parse(file string, now time.Time) []secproto.DockerContainer {
	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []secproto.DockerContainer
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() && len(out) < secproto.MaxContainers {
		var x inspected
		if json.Unmarshal(sc.Bytes(), &x) != nil || len(x.ID) < 12 {
			continue
		}
		name := strings.TrimPrefix(x.Name, "/")
		if !containerNameRe.MatchString(name) {
			continue
		}
		c := secproto.DockerContainer{ID: x.ID[:12], Name: name, Image: cutText(x.Image, 120), State: x.State, Restarts: x.Restarts, Exit: x.Exit,
			Health: cutText(x.Health, 16), Policy: cutText(x.Policy, 20), Ports: dockerPorts(x.Ports)}
		if !dockerStates[c.State] {
			c.State = "unknown"
		}
		c.Started, c.Finished = dockerTime(x.Started), dockerTime(x.Finished)
		c.Restarts1h = d.restartsInHour(c.ID, c.Restarts, now)
		seen[c.ID] = true
		out = append(out, c)
	}
	for id := range d.hist { // a container that is gone leaves no history behind
		if !seen[id] {
			delete(d.hist, id)
		}
	}
	return out
}

// restartsInHour counts the restarts Docker made during the last hour, from what the agent has seen: Docker keeps one
// running total per container. A total that went down means the container was made anew, so the count starts again.
func (d *DockerReader) restartsInHour(id string, total int, now time.Time) int {
	h := d.hist[id]
	if n := len(h); n > 0 && total < h[n-1].count {
		h = nil
	}
	h = append(h, restartSample{now, total})
	cut := now.Add(-time.Hour)
	for len(h) > 1 && h[1].at.Before(cut) {
		h = h[1:]
	}
	if len(h) > 120 { // one sample every half minute for an hour is 120
		h = h[len(h)-120:]
	}
	d.hist[id] = h
	return total - h[0].count
}

func cutText(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// dockerTime reads a time Docker wrote; the zero time it writes for "never" is none.
func dockerTime(s string) *time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() < 2000 {
		return nil
	}
	t = t.UTC()
	return &t
}

// dockerPorts lists the ports a container publishes on the host, one entry per port, without the copies for IPv6.
func dockerPorts(m map[string][]struct{ HostPort string }) []string {
	set := map[string]bool{}
	for key, binds := range m {
		udp := strings.HasSuffix(key, "/udp")
		for _, b := range binds {
			if n, err := strconv.Atoi(b.HostPort); err == nil && n > 0 && n < 65536 {
				if udp {
					set["UDP "+b.HostPort] = true
				} else {
					set[b.HostPort] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(a, b int) bool {
		na, nb := portNumber(out[a]), portNumber(out[b])
		if na != nb {
			return na < nb
		}
		return out[a] < out[b]
	})
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

func portNumber(s string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(s, "UDP "))
	return n
}

type dockerStat struct {
	cpu *float64
	mem int64
}

func parseDockerStats(file string) map[string]dockerStat {
	out := map[string]dockerStat{}
	f, err := os.Open(file)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var x struct {
			ID       string `json:"ID"`
			CPUPerc  string `json:"CPUPerc"`
			MemUsage string `json:"MemUsage"`
		}
		if json.Unmarshal(sc.Bytes(), &x) != nil || len(x.ID) < 12 {
			continue
		}
		var st dockerStat
		if v, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(x.CPUPerc), "%"), 64); err == nil && v >= 0 && v < 100000 {
			st.cpu = &v
		}
		used, _, _ := strings.Cut(x.MemUsage, "/")
		st.mem = parseSize(used)
		out[x.ID[:12]] = st
	}
	return out
}

var sizeUnits = map[string]float64{"b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12, "kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30, "tib": 1 << 40}

// parseSize reads "210.5MiB" the way docker stats prints it; 0 when it is not a size.
func parseSize(s string) int64 {
	s = strings.ToLower(strings.TrimSpace(s))
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	n, err := strconv.ParseFloat(s[:i], 64)
	mult, ok := sizeUnits[strings.TrimSpace(s[i:])]
	if err != nil || !ok {
		return 0
	}
	return int64(n * mult)
}
