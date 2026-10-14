package httpapi

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/demo"
	"github.com/Taminum/RemnaScope/internal/store"
)

const agentStaleAfter = 2 * time.Minute

// realOverview builds the dashboard payload from stored events for real (non-demo) panels.
// Counts are accepted log lines; bytes are not derived from them. Usernames are masked for
// roles below operator, exactly as in the user list.
func (s *Server) realOverview(ctx context.Context, a auth.Actor, panels []store.Panel, panelIDs, nodeIDs []string, q demo.Query) (demo.Overview, error) {
	dur := q.To.Sub(q.From)
	nodes, err := s.Store.NodesInScope(ctx, panelIDs, nodeIDs)
	if err != nil {
		return demo.Overview{}, err
	}
	withAgent := 0
	for _, n := range nodes {
		if n.HasAgent {
			withAgent++
		}
	}
	// The skeleton also validates the range; with no agent anywhere there is nothing to collect.
	ov, err := demo.Empty(q, panelIDs, "agents_not_connected")
	if err != nil || withAgent == 0 {
		return ov, err
	}
	g := demo.GranularityFor(dur)
	ev, err := s.Store.EventsOverview(ctx, store.EventsQuery{PanelIDs: panelIDs, NodeIDs: nodeIDs, From: q.From, To: q.To, Granularity: g, Top: 5})
	if err != nil {
		return ov, err
	}

	names := map[string]string{}
	for _, p := range panels {
		names[p.ID] = p.Name
	}
	for _, n := range nodes {
		ov.Meta.NodeIDs = append(ov.Meta.NodeIDs, n.NodeID)
	}
	ov.Meta.Reason = ""
	ov.Meta.State = "ok"
	total := ev.TCP + ev.UDP
	if total == 0 {
		ov.Meta.State, ov.Meta.Reason = "no_data", "no_events"
	}

	// coverage: how many nodes have a live agent, plus every gap the agents reported
	ov.Meta.Coverage.Pct = math.Round(float64(withAgent)/float64(len(nodes))*1000) / 10
	for _, gp := range ev.Gaps {
		ov.Meta.Coverage.Gaps = append(ov.Meta.Coverage.Gaps, demo.Gap{NodeID: gp.NodeID, NodeName: gp.NodeName + " (" + gp.Reason + ")", PanelID: gp.PanelID, From: gp.From, To: gp.To})
	}
	for _, n := range nodes {
		if !n.HasAgent {
			ov.Meta.Coverage.Gaps = append(ov.Meta.Coverage.Gaps, demo.Gap{NodeID: n.NodeID, NodeName: n.NodeName + " (no_agent)", PanelID: n.PanelID, From: q.From, To: q.To})
		}
	}

	// timeline, with empty buckets filled in
	byTS := map[int64]store.Bucket{}
	for _, b := range ev.Buckets {
		byTS[b.TS.Unix()] = b
	}
	series := demo.Series{TS: []int64{}, V: []float64{}}
	for ts := q.From.Truncate(g); ts.Before(q.To); ts = ts.Add(g) {
		b := byTS[ts.Unix()]
		gap := false
		for _, gp := range ev.Gaps {
			if gp.From.Before(ts.Add(g)) && !gp.To.Before(ts) {
				gap = true
			}
		}
		ov.Timeline = append(ov.Timeline, demo.TimelinePoint{TS: ts.Unix(), TCP: b.TCP, UDP: b.UDP, Gap: gap})
		series.TS, series.V = append(series.TS, ts.Unix()), append(series.V, float64(b.TCP+b.UDP))
	}
	ov.Meta.GranularitySeconds = int(g.Seconds())

	ov.Connections.Total, ov.Connections.TCP, ov.Connections.UDP = total, ev.TCP, ev.UDP
	ov.Connections.Source = "agent_access_log"
	ov.Connections.Series = series
	ov.UniqueHosts = demo.CountKPI{MetricKind: demo.KindConnections, Source: "agent_access_log", Value: ev.UniqueHosts, Series: demo.Series{TS: []int64{}, V: []float64{}}}
	ov.UniqueIPs = demo.CountKPI{MetricKind: demo.KindConnections, Source: "agent_access_log", Value: ev.UniqueIPs, Series: demo.Series{TS: []int64{}, V: []float64{}}}
	ov.Nodes = demo.NodesKPI{Reporting: ev.NodesWithEvents, Total: len(nodes)}
	// Bytes come only from the panel's own counters (M3); until then the card says so.
	ov.Traffic = demo.TrafficKPI{MetricKind: demo.KindBytes, Source: "panel_api_counters", Unit: "bytes", Series: []demo.TrafficPoint{}, TotalSeries: []demo.TotalPoint{}}
	if sum, err := s.Store.TrafficSummaryFor(ctx, store.AnalyticsQuery{PanelIDs: panelIDs, NodeIDs: nodeIDs, From: q.From, To: q.To, Granularity: g}); err == nil && sum.Samples > 0 {
		total := sum.NodeBytes
		ov.Traffic.TotalBytes, ov.Traffic.ResetCount = &total, sum.Resets
		for _, p := range sum.Timeline {
			ov.Traffic.TotalSeries = append(ov.Traffic.TotalSeries, demo.TotalPoint{TS: p.TS.Unix(), Bytes: p.Bytes})
		}
	}

	// freshness: stale if any selected agent has been silent too long
	now := q.Now
	last := now
	if ev.LastEventAt != nil {
		last = *ev.LastEventAt
	}
	ov.Freshness = demo.Freshness{LastEventAt: last.UTC(), LagSeconds: int(now.Sub(last).Seconds()), Status: "ok"}
	for _, n := range nodes {
		if n.HasAgent && (n.LastSeen == nil || now.Sub(*n.LastSeen) > agentStaleAfter) {
			ov.Freshness.Status = "stale"
		}
	}

	label := func(panelID, name, email string, internal bool) (label, note string) {
		switch {
		case internal:
			return "система", ""
		case name != "":
			if !a.Can(panelID, auth.PermOperate) {
				name = auth.MaskUsername(name)
			}
			return name, ""
		default:
			return "id " + email, "не сопоставлен"
		}
	}

	rows := func(in []store.CountRow, showOther bool) []demo.Row {
		out := make([]demo.Row, 0, len(in)+1)
		shown := 0
		for _, r := range in {
			shown += r.Count
			out = append(out, demo.Row{Key: r.Key, Label: r.Label, Count: r.Count, Share: pct(r.Count, total)})
		}
		if rest := total - shown; showOther && rest > 0 && len(in) > 0 {
			out = append(out, demo.Row{Key: "_other", Label: "остальные", Count: rest, Share: pct(rest, total), Other: true})
		}
		return out
	}
	ov.TopHosts, ov.TopIPs, ov.TopPorts = rows(ev.Hosts, true), rows(ev.IPs, true), rows(ev.Ports, true)
	ov.Services = []demo.Row{} // classification by versioned rules is a later step; nothing is guessed

	for _, u := range ev.Users {
		name := ""
		email := ""
		if !u.Internal && u.UserID != "" {
			name = u.Label
		} else {
			email = strings.TrimPrefix(u.Label, "")
		}
		l, note := label(u.PanelID, name, email, u.Internal)
		ov.Users = append(ov.Users, demo.Row{Key: u.Key, Label: l, Note: note, PanelID: u.PanelID, PanelName: names[u.PanelID], Count: u.Count, Share: pct(u.Count, total)})
	}
	for _, r := range ev.Recent {
		l, _ := label(r.PanelID, r.User, r.Email, r.Internal)
		dest, kind := r.Host, "domain"
		if dest == "" {
			dest, kind = r.IP, "ip"
		}
		ov.Recent = append(ov.Recent, demo.Recent{TS: r.TS.UTC(), PanelID: r.PanelID, PanelName: names[r.PanelID], NodeName: r.NodeName, UserLabel: l, Protocol: r.Protocol, Dest: dest, DestType: kind})
	}
	return ov, nil
}

func pct(c, total int) float64 {
	if total == 0 {
		return 0
	}
	return math.Round(float64(c)/float64(total)*1000) / 10
}
