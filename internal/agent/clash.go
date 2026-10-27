package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/ingestproto"
	"github.com/Taminum/Owlery/internal/routerlog"
)

// ClashSource polls the Clash API of sing-box (GET /connections) on a router and emits one
// routerlog record per connection when it first appears, again while its counters move, and a
// last time when it disappears. It only reads, and it holds one small entry per live connection.
type ClashSource struct {
	URL        string        // base URL, e.g. http://192.168.1.1:9090
	LeasesFile string        // optional dnsmasq leases file, to put names on devices
	Interval   time.Duration // poll period (default 2 s)
	Refresh    time.Duration // how often a changing connection is re-reported (default 30 s)
	Client     *http.Client
	Now        func() time.Time
	// Live, when set, gets a snapshot of the present speed after every poll (not spooled: a
	// snapshot that is not delivered is simply lost).
	Live func(ingestproto.Live)
}

type clashConn struct {
	ID       string `json:"id"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
	Start    string `json:"start"`
	Chains   []string
	Metadata struct {
		Network string `json:"network"`
		SrcIP   string `json:"sourceIP"`
		DstIP   string `json:"destinationIP"`
		DstPort string `json:"destinationPort"`
		Host    string `json:"host"`
	} `json:"metadata"`
}

type known struct {
	rec      routerlog.Record
	emitUp   int64
	emitDown int64
	emitAt   time.Time
	seenAt   time.Time
	lastUp   int64 // counters at the previous poll, for speeds
	lastDown int64
}

func (c *ClashSource) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func (c *ClashSource) interval() time.Duration {
	if c.Interval > 0 {
		return c.Interval
	}
	return 2 * time.Second
}

func (c *ClashSource) refresh() time.Duration {
	if c.Refresh > 0 {
		return c.Refresh
	}
	return 30 * time.Second
}

// fetch streams the connection list so that the whole JSON document is never held in memory.
func (c *ClashSource) fetch(ctx context.Context, yield func(clashConn)) error {
	cl := c.Client
	if cl == nil {
		cl = &http.Client{Timeout: 10 * time.Second}
	}
	u, err := url.JoinPath(c.URL, "connections")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("clash api: status %d", resp.StatusCode)
	}
	dec := json.NewDecoder(bufio.NewReaderSize(resp.Body, 1<<15))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return errors.New("clash api: unexpected response")
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return err
		}
		if key != "connections" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return err
			}
			continue
		}
		if t, err := dec.Token(); err != nil {
			return err
		} else if t == nil { // "connections": null
			continue
		}
		for dec.More() {
			var cc clashConn
			if err := dec.Decode(&cc); err != nil {
				return err
			}
			yield(cc)
		}
		if _, err := dec.Token(); err != nil {
			return err
		}
	}
	return nil
}

func (c *ClashSource) record(cc clashConn, names map[string]string) (routerlog.Record, bool) {
	start, err := time.Parse(time.RFC3339Nano, cc.Start)
	if err != nil || cc.ID == "" {
		return routerlog.Record{}, false
	}
	port, _ := strconv.Atoi(cc.Metadata.DstPort)
	r := routerlog.Record{V: routerlog.Version, ID: cc.ID, Start: start.UTC(), Seen: c.now(), Src: cc.Metadata.SrcIP,
		Name: names[cc.Metadata.SrcIP], Host: cc.Metadata.Host, DstIP: cc.Metadata.DstIP, Port: port,
		Proto: strings.ToLower(cc.Metadata.Network), Up: cc.Upload, Down: cc.Download}
	if n := len(cc.Chains); n > 0 {
		r.Out = cc.Chains[n-1]
	}
	if r.Seen.Before(r.Start) {
		r.Seen = r.Start
	}
	return r, true
}

func (c *ClashSource) emit(em Emitter, r routerlog.Record) {
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	em.Line(string(b))
}

func (c *ClashSource) Run(ctx context.Context, em Emitter) error {
	if c.URL == "" {
		return errors.New("agent: empty clash api url")
	}
	live := map[string]*known{}
	var names map[string]string
	var leasesMod time.Time
	down := false
	var prevPoll time.Time // when the last good poll was; speeds need two
	tick := time.NewTicker(c.interval())
	defer tick.Stop()
	for {
		if c.LeasesFile != "" {
			if st, err := os.Stat(c.LeasesFile); err == nil && !st.ModTime().Equal(leasesMod) {
				names, leasesMod = readLeases(c.LeasesFile), st.ModTime()
			}
		}
		now := c.now()
		seen := map[string]bool{}
		speeds := map[string]*ingestproto.LiveDevice{}
		err := c.fetch(ctx, func(cc clashConn) {
			r, ok := c.record(cc, names)
			if !ok {
				return
			}
			seen[r.ID] = true
			k := live[r.ID]
			var dUp, dDown int64
			if k == nil {
				dUp, dDown = r.Up, r.Down
			} else {
				dUp, dDown = max(0, r.Up-k.lastUp), max(0, r.Down-k.lastDown)
			}
			d := speeds[r.Src]
			if d == nil {
				d = &ingestproto.LiveDevice{IP: r.Src, Name: r.Name}
				speeds[r.Src] = d
			}
			d.Up, d.Down, d.Conn = d.Up+dUp, d.Down+dDown, d.Conn+1
			switch {
			case k == nil:
				live[r.ID] = &known{rec: r, emitUp: r.Up, emitDown: r.Down, emitAt: now, seenAt: now, lastUp: r.Up, lastDown: r.Down}
				c.emit(em, r)
			default:
				k.rec, k.seenAt, k.lastUp, k.lastDown = r, now, r.Up, r.Down
				if (r.Up != k.emitUp || r.Down != k.emitDown) && now.Sub(k.emitAt) >= c.refresh() {
					k.emitUp, k.emitDown, k.emitAt = r.Up, r.Down, now
					c.emit(em, r)
				}
			}
		})
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if !down {
				em.Gap("source_unreachable")
				down = true
			}
		} else {
			down = false
			if c.Live != nil && !prevPoll.IsZero() {
				c.Live(liveFrame(speeds, now.Sub(prevPoll)))
			}
			prevPoll = now
			for id, k := range live { // closed since the last poll: report the final counters once
				if seen[id] {
					continue
				}
				if k.rec.Up != k.emitUp || k.rec.Down != k.emitDown {
					k.rec.Seen = k.seenAt
					c.emit(em, k.rec)
				}
				delete(live, id)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// liveFrame turns byte deltas over an interval into speeds in bytes per second.
func liveFrame(by map[string]*ingestproto.LiveDevice, dt time.Duration) ingestproto.Live {
	secs := max(dt.Seconds(), 0.2)
	f := ingestproto.Live{Type: "live"}
	devs := make([]ingestproto.LiveDevice, 0, len(by))
	for _, d := range by {
		d.Up, d.Down = int64(float64(d.Up)/secs), int64(float64(d.Down)/secs)
		f.Up, f.Down, f.Conns = f.Up+d.Up, f.Down+d.Down, f.Conns+d.Conn
		devs = append(devs, *d)
	}
	sort.Slice(devs, func(i, j int) bool {
		a, b := devs[i].Up+devs[i].Down, devs[j].Up+devs[j].Down
		if a != b {
			return a > b
		}
		return devs[i].IP < devs[j].IP
	})
	if len(devs) > ingestproto.MaxLiveDevices {
		devs = devs[:ingestproto.MaxLiveDevices]
	}
	f.Devices = devs
	return f
}

// readLeases parses dnsmasq's leases file: "<expiry> <mac> <ip> <hostname> <client id>".
func readLeases(path string) map[string]string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) >= 4 && p[3] != "*" && len(p[3]) <= 64 {
			out[p[2]] = p[3]
		}
	}
	return out
}
