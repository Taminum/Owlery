package store_test

import (
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/ingestproto"
	"github.com/Taminum/RemnaScope/internal/store"
)

func flowEnv(t *testing.T) (*agentEnv, store.Agent) {
	t.Helper()
	e := newAgentEnv(t)
	ag := awgAgent(t, e)
	snap := ingestproto.AWG{Type: "awg", Instances: []ingestproto.AWGInstance{{Container: "c1", Interface: "awg0",
		Peers: []ingestproto.AWGPeer{{Key: keyA, Name: "RouterOne", IP: "10.8.1.2/32"}, {Key: keyB, Name: "Laptop2", IP: "10.8.1.18/32"}}}}}
	if err := e.s.SaveAWG(ctx, ag, snap, time.Now()); err != nil {
		t.Fatal(err)
	}
	return e, ag
}

func window(flows ...ingestproto.AWGFlow) ingestproto.AWGFlows {
	now := time.Now().Unix()
	return ingestproto.AWGFlows{Type: "awg_flows", Container: "c1", Start: now - 60, End: now, Flows: flows}
}

func rangeNow() store.AnalyticsQuery {
	now := time.Now().UTC()
	return store.AnalyticsQuery{From: now.Add(-3 * time.Hour), To: now.Add(3 * time.Hour), Limit: 100}
}

func joinSrc(src []string) string {
	out := ""
	for i, s := range src {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

func TestAmneziaWGTrafficJoinsSitesAndDomainsWithItsOwnSourceMark(t *testing.T) {
	e, ag := flowEnv(t)
	now := time.Now()
	// what the nodes saw of the same site: one connection, no byte counts
	if _, err := e.s.Pool().Exec(ctx, `INSERT INTO connection_events (event_id, panel_id, node_id, agent_id, ts, destination_host, destination_port, protocol, raw_fingerprint, site, xray_email)
		VALUES (gen_random_uuid(), $1, $2, $3, now(), 'cdn.video.example', 443, 'tcp', '\x01', 'video.example', '2')`, e.panel.ID, e.nodeID, e.agent.ID); err != nil {
		t.Fatal(err)
	}
	w := window(
		ingestproto.AWGFlow{Client: "10.8.1.2", Proto: 6, Remote: "1.2.3.4", Port: 443, Up: 100, Down: 9000, Name: "Video.Example", How: "sni", New: 1},
		ingestproto.AWGFlow{Client: "10.8.1.2", Proto: 6, Remote: "1.2.3.5", Port: 443, Up: 10, Down: 1000, Name: "video.example", How: "dns", New: 1},
		ingestproto.AWGFlow{Client: "10.8.1.2", Proto: 6, Remote: "1.2.3.4", Port: 443, Up: 5, Down: 50, Name: "video.example", How: "sni", New: 0}, // a long stream that began earlier
		ingestproto.AWGFlow{Client: "10.8.1.18", Proto: 6, Remote: "5.6.7.8", Port: 8443, Up: 5, Down: 500, New: 1},                                 // nothing named it
	)
	if err := e.s.SaveAWGFlows(ctx, ag, w, now); err != nil {
		t.Fatal(err)
	}
	if err := e.s.SaveAWGFlows(ctx, ag, w, now); err != nil { // the next minute adds up
		t.Fatal(err)
	}
	q := rangeNow()
	q.PanelIDs = []string{e.panel.ID}

	rows, _, _, err := e.s.Sites(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	var site *store.SiteRow
	for i := range rows {
		if rows[i].Site == "video.example" {
			site = &rows[i]
		}
	}
	if site == nil {
		t.Fatalf("the site is missing: %+v", rows)
	}
	if got := joinSrc(site.Sources); got != "awg,node" {
		t.Fatalf("both sources are named: %q", got)
	}
	// 1 node connection + the connections that BEGAN (2 per window, 2 windows); the long stream adds bytes, not a connection
	if site.Connections != 1+4 {
		t.Fatalf("connections %d", site.Connections)
	}
	if site.Visits != 1 {
		t.Fatalf("an hour of AmneziaWG activity must not count as visits: %d", site.Visits)
	}
	if site.Bytes != 2*(9100+1010+55) || site.RouterConns == 0 {
		t.Fatalf("bytes come from the sums: %d (router/awg rows %d)", site.Bytes, site.RouterConns)
	}

	// Domains: grouped by host; the AWG rows keep their own mark
	dq := q
	dq.GroupBy = "host"
	drows, _, _, err := e.s.Destinations(ctx, dq)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]store.DestRow{}
	for _, d := range drows {
		by[d.Key] = d
	}
	if d := by["video.example"]; joinSrc(d.Sources) != "awg" || d.Connections != 4 || d.Kind != "domain" {
		t.Fatalf("%+v", d)
	}
	if d := by["5.6.7.8"]; joinSrc(d.Sources) != "awg" || d.Kind != "ip" || d.Connections != 2 {
		t.Fatalf("an unnamed destination stays an IP: %+v", d)
	}
	if d := by["cdn.video.example"]; joinSrc(d.Sources) != "node" || d.Connections != 1 {
		t.Fatalf("%+v", d)
	}

	// who went there: the AmneziaWG device shows under its name and is not mistaken for a LAN device or a panel user
	det, err := e.s.SiteDetailFor(ctx, q, "video.example")
	if err != nil {
		t.Fatal(err)
	}
	var awgWho, others int
	for _, u := range det.Who {
		if u.AWG != "" {
			awgWho++
			if u.AWG != "awg:10.8.1.2" || u.DeviceName != "RouterOne" || u.Device != "" || u.UserID != "" {
				t.Fatalf("%+v", u)
			}
		} else {
			others++
		}
	}
	if awgWho != 1 || others != 1 {
		t.Fatalf("who: %+v", det.Who)
	}

	// a view narrowed to a person, a node or an inbound has nothing from AmneziaWG
	pq := q
	pq.Subject = store.Subject{Kind: "raw", PanelID: e.panel.ID, ID: "2"}
	prows, _, _, _ := e.s.Sites(ctx, pq)
	if len(prows) == 0 {
		t.Fatal("the person's own view lost its rows")
	}
	for _, r := range prows {
		if joinSrc(r.Sources) != "node" {
			t.Fatalf("a person's view contains %v", r.Sources)
		}
	}
	nq := q
	nq.NodeIDs = []string{e.nodeID}
	nrows, _, _, _ := e.s.Sites(ctx, nq)
	for _, r := range nrows {
		if joinSrc(r.Sources) != "node" {
			t.Fatalf("a node's view contains %v", r.Sources)
		}
	}
	subs, _ := e.s.Subjects(ctx, q)
	for _, s := range subs {
		if s.Kind != "awg" && (s.ID == "10.8.1.2" || s.ID == "awg:10.8.1.2" || s.Name == "RouterOne") {
			t.Fatalf("an AmneziaWG device was offered as a person or LAN device to narrow the view: %+v", s)
		}
	}
}

func TestFlowReportsAreValidatedAndScoped(t *testing.T) {
	e, ag := flowEnv(t)
	bad := window(
		ingestproto.AWGFlow{Client: "not-an-ip", Proto: 6, Remote: "1.2.3.4", Port: 443, Up: 1},
		ingestproto.AWGFlow{Client: "10.8.1.2", Proto: 99, Remote: "1.2.3.4", Port: 443, Up: 1},      // not TCP, UDP or ICMP
		ingestproto.AWGFlow{Client: "10.8.1.2", Proto: 6, Remote: "1.2.3.4", Port: 443},              // no bytes at all
		ingestproto.AWGFlow{Client: "10.8.1.2", Proto: 6, Remote: "1.2.3.4", Port: 443, Up: 1 << 60}, // an impossible minute
		ingestproto.AWGFlow{Client: "10.8.1.2", Proto: 6, Remote: "1.2.3.4", Port: 443, Up: 7, Name: "evil name; drop table", How: "sni"},
		ingestproto.AWGFlow{Client: "10.8.1.2", Proto: 6, Remote: "1.2.3.4", Port: 443, Up: 3, Name: "fine.example", How: "magic"}, // an unknown source of the name
	)
	if err := e.s.SaveAWGFlows(ctx, ag, bad, time.Now()); err != nil {
		t.Fatal(err)
	}
	rows, err := e.s.Pool().Query(ctx, `SELECT name, name_src, up_bytes FROM awg_flow_hourly`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n, up := 0, int64(0)
	for rows.Next() {
		var name, src string
		var u int64
		if err := rows.Scan(&name, &src, &u); err != nil {
			t.Fatal(err)
		}
		if name != "" || src != "" {
			t.Fatalf("an invalid name was kept: %q %q", name, src)
		}
		n, up = n+1, up+u
	}
	if n != 1 || up != 10 {
		t.Fatalf("only the two valid byte counts remain (7+3, one row since the bad names were dropped): %d rows, %d bytes", n, up)
	}
	// a window for a container the agent never announced is ignored without an error
	if err := e.s.SaveAWGFlows(ctx, ag, ingestproto.AWGFlows{Type: "awg_flows", Container: "other", End: time.Now().Unix(), Flows: bad.Flows}, time.Now()); err != nil {
		t.Fatal(err)
	}
	// another panel's scope sees nothing
	other := mkPanel(t, e.s, "other")
	q := rangeNow()
	q.PanelIDs = []string{other.ID}
	if r, _, _, _ := e.s.Sites(ctx, q); len(r) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestOldFlowSumsAreRemoved(t *testing.T) {
	e, ag := flowEnv(t)
	if err := e.s.SaveAWGFlows(ctx, ag, window(ingestproto.AWGFlow{Client: "10.8.1.2", Proto: 6, Remote: "1.2.3.4", Port: 443, Up: 5}), time.Now()); err != nil {
		t.Fatal(err)
	}
	_, _ = e.s.Pool().Exec(ctx, `UPDATE awg_flow_hourly SET hour = hour - interval '40 days'`)
	if n, err := e.s.PruneAWGFlows(ctx, 30*24*time.Hour); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestAWGSubjectFilterShowsOnlyAmneziaWG(t *testing.T) {
	e, ag := flowEnv(t)
	if _, err := e.s.Pool().Exec(ctx, `INSERT INTO connection_events (event_id, panel_id, node_id, agent_id, ts, destination_host, destination_port, protocol, raw_fingerprint, site, xray_email)
		VALUES (gen_random_uuid(), $1, $2, $3, now(), 'node.example', 443, 'tcp', '\x02', 'node.example', '2')`, e.panel.ID, e.nodeID, e.agent.ID); err != nil {
		t.Fatal(err)
	}
	w := window(
		ingestproto.AWGFlow{Client: "10.8.1.2", Proto: 6, Remote: "1.2.3.4", Port: 443, Up: 1, Down: 10, Name: "a.example", How: "sni", New: 1},
		ingestproto.AWGFlow{Client: "10.8.1.18", Proto: 6, Remote: "1.2.3.5", Port: 443, Up: 1, Down: 10, Name: "b.example", How: "sni", New: 1},
	)
	if err := e.s.SaveAWGFlows(ctx, ag, w, time.Now()); err != nil {
		t.Fatal(err)
	}
	q := rangeNow()
	q.PanelIDs = []string{e.panel.ID}
	subs, err := e.s.Subjects(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, s := range subs {
		if s.Kind == "awg" {
			have[s.ID] = true
		}
	}
	if !have["*"] || !have["10.8.1.2"] || !have["10.8.1.18"] {
		t.Fatalf("awg choices: %+v", subs)
	}
	names := func(id string) string {
		sq := q
		sq.Subject = store.Subject{Kind: "awg", PanelID: e.panel.ID, ID: id}
		rows, _, _, err := e.s.Sites(ctx, sq)
		if err != nil {
			t.Fatal(err)
		}
		out := ""
		for _, r := range rows {
			out += r.Site + "|" + joinSrc(r.Sources) + ";"
		}
		return out
	}
	if got := names("*"); got != "a.example|awg;b.example|awg;" && got != "b.example|awg;a.example|awg;" {
		t.Fatalf("whole server: %q", got)
	}
	if got := names("10.8.1.2"); got != "a.example|awg;" {
		t.Fatalf("one device: %q", got)
	}
}
