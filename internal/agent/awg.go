package agent

import (
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Taminum/RemnaScope/internal/ingestproto"
)

// SnapshotCommandOutputLimit caps what is read from the helper: a snapshot is a few kilobytes.
const awgOutputLimit = 512 << 10

// AWGSource runs a fixed helper command on a timer and turns its text output into snapshots of the
// AmneziaWG interfaces. It reads nothing else and has no way to change anything: the helper is a
// root-owned script that the agent may run through one exact sudoers rule, and that prints only
// public information (public keys, names, tunnel addresses, counters).
type AWGSource struct {
	Argv  []string
	Every time.Duration
	Emit  func(ingestproto.AWG)
	Log   func(msg string)
}

func (a *AWGSource) every() time.Duration {
	if a.Every > 0 {
		return a.Every
	}
	return time.Minute
}

func (a *AWGSource) Run(ctx context.Context, _ Emitter) error {
	t := time.NewTicker(a.every())
	defer t.Stop()
	for {
		a.once(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (a *AWGSource) once(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, a.Argv[0], a.Argv[1:]...)
	var out bytes.Buffer
	cmd.Stdout = &limitWriter{w: &out, n: awgOutputLimit}
	if err := cmd.Run(); err != nil {
		if a.Log != nil {
			a.Log("snapshot command failed")
		}
		return
	}
	snap := ParseAWGSnapshot(out.String())
	if (len(snap.Instances) > 0 || snap.ContainerAdmin) && a.Emit != nil {
		a.Emit(snap)
	}
}

type limitWriter struct {
	w *bytes.Buffer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.w.Len()+len(p) > l.n {
		return len(p), nil // beyond the limit is dropped, not an error
	}
	return l.w.Write(p)
}

// ParseAWGSnapshot reads the helper's tab-separated output:
//
//	I <container> <interface> <port> <field,field,...>
//	P <container> <public key> <handshake unix> <rx> <tx> <allowed ips>
//	N <container> <public key> <name>
//
// Lines it does not understand are ignored.
func ParseAWGSnapshot(text string) ingestproto.AWG {
	snap := ingestproto.AWG{Type: "awg"}
	idx := map[string]int{}
	names := map[string]string{}
	tables := map[string]int64{}
	managed := map[string]bool{}
	legacy := map[string][4]string{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "I":
			if len(f) < 5 || len(snap.Instances) >= ingestproto.MaxAWGInstances {
				continue
			}
			port, _ := strconv.Atoi(f[3])
			var fields []string
			for _, x := range strings.Split(f[4], ",") {
				if x = strings.TrimSpace(x); x != "" {
					fields = append(fields, x)
				}
			}
			var started int64
			if len(f) >= 6 {
				started, _ = strconv.ParseInt(f[5], 10, 64)
			}
			idx[f[1]] = len(snap.Instances)
			snap.Instances = append(snap.Instances, ingestproto.AWGInstance{Container: f[1], Interface: f[2], Port: port, Fields: fields, Started: started, Peers: []ingestproto.AWGPeer{}})
		case "P":
			i, ok := idx[f[1]]
			if !ok || len(f) < 7 || len(snap.Instances[i].Peers) >= ingestproto.MaxAWGPeers {
				continue
			}
			hs, e1 := strconv.ParseInt(f[3], 10, 64)
			rx, e2 := strconv.ParseInt(f[4], 10, 64)
			tx, e3 := strconv.ParseInt(f[5], 10, 64)
			if e1 != nil || e2 != nil || e3 != nil {
				continue
			}
			ip := strings.TrimSpace(strings.Split(f[6], ",")[0])
			snap.Instances[i].Peers = append(snap.Instances[i].Peers, ingestproto.AWGPeer{Key: f[2], IP: ip, RX: rx, TX: tx, Handshake: hs})
		case "N":
			if len(f) >= 4 {
				names[f[1]+"\x00"+f[2]] = f[3]
			}
		case "M":
			managed[f[1]] = true
		case "X":
			if f[1] == "container_admin" {
				snap.ContainerAdmin = true
			}
		case "T":
			if len(f) < 3 {
				continue
			}
			if at, err := strconv.ParseInt(f[2], 10, 64); err == nil && at > 0 {
				tables[f[1]] = at
			}
		case "L":
			if len(f) >= 6 {
				l := [4]string{f[3], f[4], f[5], ""}
				if len(f) >= 7 {
					l[3] = f[6]
				}
				legacy[f[1]+"\x00"+f[2]] = l
			}
		}
	}
	for i := range snap.Instances {
		for j := range snap.Instances[i].Peers {
			p := &snap.Instances[i].Peers[j]
			p.Name = names[snap.Instances[i].Container+"\x00"+p.Key]
			if l, ok := legacy[snap.Instances[i].Container+"\x00"+p.Key]; ok {
				p.LegacyDown, p.LegacyUp, p.Created = parseSize(l[0]), parseSize(l[1]), parseCreated(l[3])
				if at := tables[snap.Instances[i].Container]; at > 0 {
					if ago := parseAgo(l[2]); ago >= 0 {
						p.LegacyHS = at - ago
					}
				}
			}
		}
		snap.Instances[i].LegacyAt = tables[snap.Instances[i].Container]
		snap.Instances[i].Managed = managed[snap.Instances[i].Container]
	}
	return snap
}

// parseSize reads "106.76 GiB" or "792.61 MiB" into bytes; anything else is 0.
func parseSize(s string) int64 {
	f := strings.Fields(s)
	if len(f) != 2 {
		return 0
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil || v < 0 {
		return 0
	}
	mult := map[string]float64{"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}[f[1]]
	return int64(v * mult)
}

// parseAgo reads "4d, 3h, 14m, 18s ago" into seconds; -1 when it is not such a text ("None", empty).
func parseAgo(s string) int64 {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "ago"))
	if s == "" || s == "None" {
		return -1
	}
	var total int64
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if len(part) < 2 {
			return -1
		}
		n, err := strconv.ParseInt(part[:len(part)-1], 10, 64)
		if err != nil || n < 0 {
			return -1
		}
		switch part[len(part)-1] {
		case 'd':
			total += n * 86400
		case 'h':
			total += n * 3600
		case 'm':
			total += n * 60
		case 's':
			total += n
		default:
			return -1
		}
	}
	return total
}

// parseCreated reads the two date shapes the old table used: "2026-04-03T10:01:05.979470" and
// "Fri Aug 21 18:39:32 2026". Both are taken as UTC. Anything else is 0.
func parseCreated(s string) int64 {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"2006-01-02T15:04:05.999999", "2006-01-02T15:04:05", "Mon Jan _2 15:04:05 2006"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Unix()
		}
	}
	return 0
}
