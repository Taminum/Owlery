package demo

import (
	"errors"
	"hash/fnv"
	"math"
	"sort"
	"strconv"
	"time"
)

var (
	ErrUnknownPanel   = errors.New("panel is not available")
	ErrNodeOutOfScope = errors.New("node does not belong to the selected panels")
	ErrBadRange       = errors.New("invalid time range")
)

const maxBuckets = 400

func noise(parts ...string) float64 {
	h := fnv.New64a()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return float64(h.Sum64()%10000) / 10000
}

// GranularityFor is the bucket size the overview uses for a window of length d.
func GranularityFor(d time.Duration) time.Duration { return granularity(d) }

func granularity(d time.Duration) time.Duration {
	switch {
	case d <= 20*time.Minute:
		return time.Minute
	case d <= 90*time.Minute:
		return 2 * time.Minute
	case d <= 36*time.Hour:
		return 30 * time.Minute
	case d <= 8*24*time.Hour:
		return 3 * time.Hour
	default:
		return 12 * time.Hour
	}
}

// ListPanels returns panel/node metadata for the selectors.
func ListPanels() []PanelInfo {
	out := make([]PanelInfo, 0, len(Panels))
	for _, p := range Panels {
		pi := PanelInfo{ID: p.ID, Name: p.Name}
		for _, n := range p.Nodes {
			st := "ok"
			if n.LagSec > 30 {
				st = "lagging"
			}
			pi.Nodes = append(pi.Nodes, NodeInfo{ID: n.ID, PanelID: p.ID, Name: n.Name, AgentStatus: st, LagSeconds: n.LagSec})
		}
		out = append(out, pi)
	}
	return out
}

func resolve(q Query) ([]*Panel, []Node, error) {
	var panels []*Panel
	if len(q.PanelIDs) == 0 {
		for i := range Panels {
			panels = append(panels, &Panels[i])
		}
	} else {
		seen := map[string]bool{}
		for _, id := range q.PanelIDs {
			p := panelByID(id)
			if p == nil {
				return nil, nil, ErrUnknownPanel
			}
			if !seen[id] {
				seen[id] = true
				panels = append(panels, p)
			}
		}
		sort.SliceStable(panels, func(i, j int) bool { return panelIdx(panels[i].ID) < panelIdx(panels[j].ID) })
	}
	inScope := map[string]bool{}
	for _, p := range panels {
		inScope[p.ID] = true
	}
	var nodes []Node
	if len(q.NodeIDs) == 0 {
		for _, p := range panels {
			nodes = append(nodes, p.Nodes...)
		}
		return panels, nodes, nil
	}
	want := map[string]bool{}
	for _, id := range q.NodeIDs {
		np := nodePanel(id)
		if np == nil || !inScope[np.ID] {
			return nil, nil, ErrNodeOutOfScope
		}
		want[id] = true
	}
	for _, p := range panels {
		for _, n := range p.Nodes {
			if want[n.ID] {
				nodes = append(nodes, n)
			}
		}
	}
	return panels, nodes, nil
}

func panelIdx(id string) int {
	for i := range Panels {
		if Panels[i].ID == id {
			return i
		}
	}
	return -1
}

type window struct{ from, to time.Time }

func gapWindow(now time.Time) window {
	h := now.UTC().Truncate(time.Hour)
	return window{from: h.Add(-4 * time.Hour), to: h.Add(-90 * time.Minute)}
}

func inGap(n Node, ts time.Time, now time.Time) bool {
	if n.ID != GapNodeID {
		return false
	}
	g := gapWindow(now)
	return !ts.Before(g.from) && ts.Before(g.to)
}

func bucketCount(n Node, ts time.Time, g time.Duration) int {
	hour := float64(ts.UTC().Hour()) + float64(ts.UTC().Minute())/60
	diurnal := 0.55 + 0.45*math.Sin((hour-9)*math.Pi/12)
	nz := 0.75 + 0.5*noise(n.ID, strconv.FormatInt(ts.Unix(), 10))
	return int(math.Round(n.RatePerMn * g.Minutes() * diurnal * nz))
}

func splitUDP(n Node, ts time.Time, total int) (tcp, udp int) {
	share := 0.013 + 0.012*noise(n.ID, "udp", strconv.FormatInt(ts.Unix(), 10))
	udp = int(math.Round(float64(total) * share))
	return total - udp, udp
}

type bucket struct {
	ts       time.Time
	tcp, udp int
	up, down int64
	gap      bool
}

func buckets(nodes []Node, from, to, now time.Time, g time.Duration) []bucket {
	var out []bucket
	for ts := from.Truncate(g); ts.Before(to); ts = ts.Add(g) {
		b := bucket{ts: ts}
		for _, n := range nodes {
			if inGap(n, ts, now) {
				b.gap = true
				continue
			}
			c := bucketCount(n, ts, g)
			t, u := splitUDP(n, ts, c)
			b.tcp += t
			b.udp += u
			dn := int64(float64(c) * (150000 + 100000*noise(n.ID, "b", strconv.FormatInt(ts.Unix(), 10))))
			b.down += dn
			b.up += dn / 9
		}
		out = append(out, b)
	}
	return out
}

func panelTotals(nodes []Node, bs []bucket, from, to, now time.Time, g time.Duration) map[string]int {
	out := map[string]int{}
	for ts := from.Truncate(g); ts.Before(to); ts = ts.Add(g) {
		for _, n := range nodes {
			if inGap(n, ts, now) {
				continue
			}
			out[n.PanelID] += bucketCount(n, ts, g)
		}
	}
	return out
}

// BuildOverview builds the synthetic dashboard payload for the requested scope.
// Every list is derived from the same per-node totals so cards, charts and
// tables always agree with each other.
func BuildOverview(q Query) (Overview, error) {
	if !q.To.After(q.From) {
		return Overview{}, ErrBadRange
	}
	dur := q.To.Sub(q.From)
	g := granularity(dur)
	if int(dur/g)+1 > maxBuckets {
		return Overview{}, ErrBadRange
	}
	panels, nodes, err := resolve(q)
	if err != nil {
		return Overview{}, err
	}

	ov := skeleton(q, g, panelIDsOf(panels), nodeIDsOf(nodes), true)
	ov.Nodes = NodesKPI{Total: len(nodes)}

	if q.State == "empty" || q.State == "pending" {
		ov.Meta.State = "no_data"
		if q.State == "pending" {
			ov.Meta.State = "sync_pending"
		}
		ov.Meta.Coverage.Pct = 0
		return ov, nil
	}

	bs := buckets(nodes, q.From, q.To, q.Now, g)
	ts := Series{TS: []int64{}, V: []float64{}}
	hs := Series{TS: []int64{}, V: []float64{}}
	ips := Series{TS: []int64{}, V: []float64{}}
	var upT, downT int64
	for _, b := range bs {
		tot := b.tcp + b.udp
		ov.Connections.Total += tot
		ov.Connections.TCP += b.tcp
		ov.Connections.UDP += b.udp
		upT += b.up
		downT += b.down
		unix := b.ts.Unix()
		ov.Timeline = append(ov.Timeline, TimelinePoint{TS: unix, TCP: b.tcp, UDP: b.udp, Gap: b.gap})
		ov.Traffic.Series = append(ov.Traffic.Series, TrafficPoint{TS: unix, Up: b.up, Down: b.down})
		ts.TS, ts.V = append(ts.TS, unix), append(ts.V, float64(tot))
		hs.TS, hs.V = append(hs.TS, unix), append(hs.V, math.Pow(float64(tot), 0.62))
		ips.TS, ips.V = append(ips.TS, unix), append(ips.V, math.Pow(float64(tot), 0.66))
	}
	ov.Connections.Series, ov.UniqueHosts.Series, ov.UniqueIPs.Series = ts, hs, ips
	total := ov.Connections.Total
	ov.UniqueHosts.Value = int(math.Pow(float64(total), 0.62))
	ov.UniqueIPs.Value = int(math.Pow(float64(total), 0.66))
	ov.Traffic.UpBytes, ov.Traffic.DownBytes = upT, downT

	// Delta against the previous window of the same length.
	prevFrom, prevTo := q.From.Add(-dur), q.From
	prev := 0
	for _, v := range panelTotals(nodes, nil, prevFrom, prevTo, q.Now, g) {
		prev += v
	}
	if prev > 0 {
		d := (float64(total) - float64(prev)) / float64(prev) * 100
		ov.Connections.DeltaPct = &d
	}

	// Coverage and gap markers.
	cells, covered := 0, 0
	gw := gapWindow(q.Now)
	for _, n := range nodes {
		for t := q.From.Truncate(g); t.Before(q.To); t = t.Add(g) {
			cells++
			if !inGap(n, t, q.Now) {
				covered++
			}
		}
		if n.ID == GapNodeID && gw.from.Before(q.To) && gw.to.After(q.From) {
			ov.Meta.Coverage.Gaps = append(ov.Meta.Coverage.Gaps, Gap{
				NodeID: n.ID, NodeName: n.Name, PanelID: n.PanelID,
				From: maxTime(gw.from, q.From), To: minTime(gw.to, q.To),
			})
		}
	}
	if cells > 0 {
		ov.Meta.Coverage.Pct = math.Round(float64(covered)/float64(cells)*1000) / 10
	}
	ov.Traffic.CoveragePct = ov.Meta.Coverage.Pct

	// Nodes reporting + freshness from fixtures.
	maxLag := 0
	for _, n := range nodes {
		lag := n.LagSec
		if lag > maxLag {
			maxLag = lag
		}
		ov.Nodes.Reporting++
	}
	ov.Freshness.LagSeconds = maxLag
	ov.Freshness.LastEventAt = q.Now.UTC().Add(-time.Duration(maxLag) * time.Second)
	if maxLag > 120 {
		ov.Freshness.Status = "stale"
	}

	pt := panelTotals(nodes, bs, q.From, q.To, q.Now, g)
	ov.TopHosts = distribute(panels, pt, total, 5, func(p *Panel) []Dest { return p.Hosts })
	ov.TopIPs = distribute(panels, pt, total, 5, func(p *Panel) []Dest { return p.IPs })
	ov.TopPorts = distribute(panels, pt, total, 5, func(p *Panel) []Dest { return p.Ports })
	ov.Services = distribute(panels, pt, total, 5, func(p *Panel) []Dest { return p.Svc })
	ov.Users = userRows(panels, pt, total)
	ov.Recent = recent(panels, nodes, q)
	return ov, nil
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func distribute(panels []*Panel, pt map[string]int, total, top int, pick func(*Panel) []Dest) []Row {
	if total == 0 {
		return []Row{}
	}
	idx := map[string]*Row{}
	var order []string
	for _, p := range panels {
		for _, d := range pick(p) {
			c := int(math.Round(float64(pt[p.ID]) * d.Weight / 100))
			if r, ok := idx[d.Key]; ok {
				r.Count += c
				if d.Confidence != "" && confRank(d.Confidence) < confRank(r.Confidence) {
					r.Confidence = d.Confidence
				}
				continue
			}
			idx[d.Key] = &Row{Key: d.Key, Label: d.Label, Count: c, Confidence: d.Confidence}
			order = append(order, d.Key)
		}
	}
	rows := make([]Row, 0, len(order))
	for _, k := range order {
		rows = append(rows, *idx[k])
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Count > rows[j].Count })
	if len(rows) > top {
		rows = rows[:top]
	}
	shown := 0
	for i := range rows {
		shown += rows[i].Count
		rows[i].Share = share(rows[i].Count, total)
	}
	if rest := total - shown; rest > 0 {
		rows = append(rows, Row{Key: "_other", Label: "остальные", Count: rest, Share: share(rest, total), Other: true})
	}
	return rows
}

func confRank(c string) int {
	switch c {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func share(c, total int) float64 {
	return math.Round(float64(c)/float64(total)*1000) / 10
}

func userRows(panels []*Panel, pt map[string]int, total int) []Row {
	if total == 0 {
		return []Row{}
	}
	var rows []Row
	for _, p := range panels {
		left := pt[p.ID]
		for i, u := range p.Users {
			c := int(math.Round(float64(pt[p.ID]) * u.Share))
			if i == len(p.Users)-1 {
				c = left
			}
			left -= c
			rows = append(rows, Row{Key: u.ID, Label: u.Label, Note: u.Note, PanelID: p.ID, PanelName: p.Name,
				Count: c, Share: share(c, total)})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Count > rows[j].Count })
	return rows
}

func recent(panels []*Panel, nodes []Node, q Query) []Recent {
	if len(nodes) == 0 {
		return []Recent{}
	}
	out := make([]Recent, 0, 10)
	ts := q.Now.UTC().Add(-time.Duration(nodes[0].LagSec+3) * time.Second)
	if ts.After(q.To) {
		ts = q.To.UTC()
	}
	for i := 0; i < 10; i++ {
		k := strconv.Itoa(i) + strconv.FormatInt(q.To.Unix()/60, 10)
		n := nodes[int(noise("rn", k)*float64(len(nodes)))%len(nodes)]
		p := panelByID(n.PanelID)
		r := Recent{TS: ts, PanelID: p.ID, PanelName: p.Name, NodeName: n.Name, Protocol: "tcp"}
		if noise("proto", k) < 0.14 {
			r.Protocol, r.UserLabel, r.Dest, r.DestType = "udp", "система", "1.1.1.1", "ip"
		} else {
			r.UserLabel = p.Users[int(noise("ru", k)*float64(len(p.Users)))%len(p.Users)].Label
			if noise("kind", k) < 0.7 {
				r.Dest, r.DestType = p.Hosts[int(noise("rh", k)*float64(len(p.Hosts)))%len(p.Hosts)].Label, "domain"
			} else {
				r.Dest, r.DestType = p.IPs[int(noise("ri", k)*float64(len(p.IPs)))%len(p.IPs)].Label, "ip"
			}
		}
		out = append(out, r)
		ts = ts.Add(-time.Duration(2+int(noise("dt", k)*45)) * time.Second)
	}
	return out
}

func panelIDsOf(ps []*Panel) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p.ID)
	}
	return out
}

func nodeIDsOf(ns []Node) []string {
	out := []string{}
	for _, n := range ns {
		out = append(out, n.ID)
	}
	return out
}

// skeleton is an overview with every list present but empty and no numbers.
func skeleton(q Query, g time.Duration, panelIDs, nodeIDs []string, demo bool) Overview {
	ov := Overview{}
	ov.Meta = Meta{Demo: demo, State: "ok", GeneratedAt: q.Now.UTC(), From: q.From.UTC(), To: q.To.UTC(),
		GranularitySeconds: int(g.Seconds()), PanelIDs: panelIDs, NodeIDs: nodeIDs}
	ov.Meta.Coverage = Coverage{Pct: 100, Gaps: []Gap{}}
	ov.Timeline = []TimelinePoint{}
	ov.Traffic = TrafficKPI{MetricKind: KindBytes, Source: Source, Unit: "bytes", Series: []TrafficPoint{}}
	empty := func() Series { return Series{TS: []int64{}, V: []float64{}} }
	ov.Connections = ConnectionsKPI{MetricKind: KindConnections, Source: Source, Series: empty()}
	ov.UniqueHosts = CountKPI{MetricKind: KindConnections, Source: Source, Series: empty()}
	ov.UniqueIPs = CountKPI{MetricKind: KindConnections, Source: Source, Series: empty()}
	ov.TopHosts, ov.TopIPs, ov.TopPorts, ov.Services, ov.Users = []Row{}, []Row{}, []Row{}, []Row{}, []Row{}
	ov.Recent = []Recent{}
	ov.Freshness = Freshness{LastEventAt: q.Now.UTC(), Status: "ok"}
	return ov
}

// Empty is the honest answer for panels that have no event data yet: a real,
// non-demo overview with state no_data and the reason spelled out.
func Empty(q Query, panelIDs []string, reason string) (Overview, error) {
	if !q.To.After(q.From) {
		return Overview{}, ErrBadRange
	}
	dur := q.To.Sub(q.From)
	g := granularity(dur)
	if int(dur/g)+1 > maxBuckets {
		return Overview{}, ErrBadRange
	}
	ov := skeleton(q, g, panelIDs, []string{}, false)
	ov.Meta.State, ov.Meta.Reason = "no_data", reason
	ov.Meta.Coverage.Pct = 0
	return ov, nil
}
