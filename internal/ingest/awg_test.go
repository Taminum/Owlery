package ingest

import (
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/ingestproto"
	"github.com/Taminum/RemnaScope/internal/store"
)

const (
	wgKeyA = "AAAA111111111111111111111111111111111111111="
	wgKeyB = "BBBB222222222222222222222222222222222222222="
)

func awgFrame() ingestproto.AWG {
	return ingestproto.AWG{Type: "awg", Instances: []ingestproto.AWGInstance{{Container: "amnezia-awg2", Interface: "awg0", Port: 49587, Fields: []string{"Jc", "S3", "S4"},
		Peers: []ingestproto.AWGPeer{{Key: wgKeyA, Name: "RouterOne", IP: "10.8.1.2/32", RX: 1, TX: 2, Handshake: time.Now().Unix()}, {Key: "garbage", RX: 1}}}}}
}

// An AmneziaWG snapshot is stored when it comes from an AWG agent, never answered, never disturbs
// the connection, and is ignored from any other kind of agent.
func TestAWGSnapshotsAreStoredOnlyFromAWGAgents(t *testing.T) {
	e := newEnv(t, nil)
	nodes, _ := e.st.ListNodes(ctx, store.Scope{All: true}, e.panel.ID, false)
	aa, err := e.st.CreateAgent(ctx, store.Scope{All: true}, e.panel.ID, nodes[0].ID, "awg", "awg", "", store.HashAgentSecret(secret))
	if err != nil {
		t.Fatal(err)
	}
	// from a node agent: ignored
	nc, _, err := e.dial(t, e.token())
	if err != nil {
		t.Fatal(err)
	}
	hello(t, nc, "ep-node")
	write(t, nc, awgFrame())
	write(t, nc, ingestproto.Ping{Type: "ping"})
	if p := read[ingestproto.Pong](t, nc); p.Type != "pong" {
		t.Fatalf("%+v", p)
	}
	if insts, _ := e.st.AWGInstances(ctx, store.Scope{All: true}, time.Hour); len(insts) != 0 {
		t.Fatal("a node agent's AWG frame was stored")
	}
	// from the AWG agent: stored, the invalid peer is skipped, and the connection stays usable
	ac, _, err := e.dial(t, aa.ID+"."+secret)
	if err != nil {
		t.Fatal(err)
	}
	hello(t, ac, "ep-awg")
	write(t, ac, awgFrame())
	write(t, ac, ingestproto.Ping{Type: "ping"})
	if p := read[ingestproto.Pong](t, ac); p.Type != "pong" {
		t.Fatalf("%+v", p)
	}
	waitFor(t, "the snapshot", func() bool {
		insts, _ := e.st.AWGInstances(ctx, store.Scope{All: true}, time.Hour)
		return len(insts) == 1 && len(insts[0].Peers) == 1
	})
	insts, _ := e.st.AWGInstances(ctx, store.Scope{All: true}, time.Hour)
	if insts[0].Peers[0].Label != "RouterOne" || insts[0].Variant != "AWG 2.0" {
		t.Fatalf("%+v", insts[0])
	}
}

func TestAWGFlowWindowsAreStoredOnlyFromAWGAgents(t *testing.T) {
	e := newEnv(t, nil)
	nodes, _ := e.st.ListNodes(ctx, store.Scope{All: true}, e.panel.ID, false)
	aa, err := e.st.CreateAgent(ctx, store.Scope{All: true}, e.panel.ID, nodes[0].ID, "awg", "awg", "", store.HashAgentSecret(secret))
	if err != nil {
		t.Fatal(err)
	}
	ac, _, err := e.dial(t, aa.ID+"."+secret)
	if err != nil {
		t.Fatal(err)
	}
	hello(t, ac, "ep-flows")
	write(t, ac, awgFrame()) // announces the container and its devices
	waitFor(t, "the snapshot", func() bool { i, _ := e.st.AWGInstances(ctx, store.Scope{All: true}, time.Hour); return len(i) == 1 })
	fr := ingestproto.AWGFlows{Type: "awg_flows", Container: "amnezia-awg2", End: time.Now().Unix(),
		Flows: []ingestproto.AWGFlow{{Client: "10.8.1.2", Proto: 6, Remote: "1.2.3.4", Port: 443, Up: 10, Down: 90, Name: "site.example", How: "sni"}}}
	write(t, ac, fr)
	write(t, ac, ingestproto.Ping{Type: "ping"})
	if p := read[ingestproto.Pong](t, ac); p.Type != "pong" {
		t.Fatalf("%+v", p)
	}
	sumOf := func() int64 {
		var n int64
		_ = e.st.Pool().QueryRow(ctx, `SELECT COALESCE(sum(down_bytes), 0) FROM awg_flow_hourly WHERE name = 'site.example'`).Scan(&n)
		return n
	}
	waitFor(t, "the window", func() bool { return sumOf() == 90 })
	// from a node agent: ignored
	nc, _, err := e.dial(t, e.token())
	if err != nil {
		t.Fatal(err)
	}
	hello(t, nc, "ep-node2")
	write(t, nc, fr)
	write(t, nc, ingestproto.Ping{Type: "ping"})
	if p := read[ingestproto.Pong](t, nc); p.Type != "pong" {
		t.Fatalf("%+v", p)
	}
	if sumOf() != 90 {
		t.Fatalf("a node agent's window was stored: %d", sumOf())
	}
}
