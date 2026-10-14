package ingest

import (
	"fmt"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/ingestproto"
	"github.com/Taminum/RemnaScope/internal/live"
	"github.com/Taminum/RemnaScope/internal/store"
)

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Snapshots from a router agent reach the hub, are never answered, do not disturb the ordered
// stream on the same connection, and are ignored from a node agent or when malformed.
func TestLiveSnapshotsAreBestEffortAndOnlyFromRouterAgents(t *testing.T) {
	hub := live.New()
	e := newEnv(t, func(s *Server) { s.Live = hub })
	nodes, _ := e.st.ListNodes(ctx, store.Scope{All: true}, e.panel.ID, false)
	ra, err := e.st.CreateAgent(ctx, store.Scope{All: true}, e.panel.ID, nodes[0].ID, "OpenWrt", "router", "", store.HashAgentSecret(secret))
	if err != nil {
		t.Fatal(err)
	}
	panels := map[string]bool{e.panel.ID: true}

	rc, _, err := e.dial(t, ra.ID+"."+secret)
	if err != nil {
		t.Fatal(err)
	}
	hello(t, rc, "ep1")
	good := ingestproto.Live{Type: "live", Conns: 7, Up: 1000, Down: 9000, Devices: []ingestproto.LiveDevice{{IP: "192.168.1.5", Name: "Home", Up: 1000, Down: 9000, Conn: 7}}}
	write(t, rc, good)
	// Garbage in the same shape, and an unrelated frame, are dropped without closing the connection.
	write(t, rc, ingestproto.Live{Type: "live", Down: -5})
	write(t, rc, ingestproto.Live{Type: "live", Devices: []ingestproto.LiveDevice{{IP: "8.8.8.8"}}})
	waitFor(t, "the snapshot", func() bool { return len(hub.Views(panels)) == 1 })
	v := hub.Views(panels)[0]
	if v.Latest.Down != 9000 || v.Source.Name != "OpenWrt" || len(v.Series) != 1 || v.Devices[0].Name != "Home" {
		t.Fatalf("%+v", v)
	}
	// The connection still works for the ordered stream: a batch is acknowledged as usual, and no
	// reply to the snapshots shows up in front of it.
	line := fmt.Sprintf(`{"v":1,"id":"c1","t":%q,"u":%q,"src":"192.168.1.5","h":"a.test","dp":443,"p":"tcp","up":1,"dn":2}`,
		time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	write(t, rc, ingestproto.Batch{Type: "batch", BatchID: "b1", Items: []ingestproto.Item{{Seq: 1, Line: line}}})
	if ack := read[ingestproto.Ack](t, rc); ack.Type != "ack" || ack.Accepted != 1 {
		t.Fatalf("%+v", ack)
	}
	if len(hub.Views(panels)[0].Series) != 1 {
		t.Fatal("refused frames must leave nothing behind")
	}

	// A node agent's snapshot is ignored.
	nc, _, err := e.dial(t, e.token())
	if err != nil {
		t.Fatal(err)
	}
	hello(t, nc, "ep2")
	write(t, nc, good)
	write(t, nc, ingestproto.Ping{Type: "ping"})
	if p := read[ingestproto.Pong](t, nc); p.Type != "pong" {
		t.Fatalf("%+v", p)
	}
	if got := hub.Views(panels); len(got) != 1 || got[0].Source.AgentID != ra.ID {
		t.Fatalf("a node agent must not appear in the live view: %+v", got)
	}
}
