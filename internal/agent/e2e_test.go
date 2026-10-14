package agent_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/agent"
	"github.com/Taminum/RemnaScope/internal/ingest"
	"github.com/Taminum/RemnaScope/internal/store"
	"github.com/Taminum/RemnaScope/internal/store/storetest"
)

var ctx = context.Background()

const secret = "agent-secret-0123456789abcdef"

type rig struct {
	t     *testing.T
	st    *store.Store
	panel store.Panel
	agent store.Agent
	srv   *httptest.Server
	dir   string
	log   string
	token string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	st := storetest.New(t)
	p, err := st.CreatePanel(ctx, store.NewPanelID(), store.PanelInput{Name: "home", BaseURL: "https://home.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = st.UpsertNodes(ctx, p.ID, time.Now().UTC(), []store.NodeRecord{{RemoteUUID: "n", Name: "node-1"}})
	_, _ = st.UpsertUsers(ctx, p.ID, time.Now().UTC(), []store.UserRecord{{RemoteUUID: "2", Username: "alice"}})
	nodes, _ := st.ListNodes(ctx, store.Scope{All: true}, p.ID, false)
	a, err := st.CreateAgent(ctx, store.Scope{All: true}, p.ID, nodes[0].ID, "a", "node", "", store.HashAgentSecret(secret))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer((&ingest.Server{Store: st}).Handler())
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	_ = os.WriteFile(tok, []byte(a.ID+"."+secret+"\n"), 0o600)
	return &rig{t: t, st: st, panel: p, agent: a, srv: srv, dir: dir, log: filepath.Join(dir, "current"), token: tok}
}

func (r *rig) cfg() agent.Config {
	return agent.Config{ServerURL: "ws" + strings.TrimPrefix(r.srv.URL, "http"), TokenFile: r.token, AllowInsecure: true,
		StateDir: filepath.Join(r.dir, "state"), Kind: agent.SourceFile, Path: r.log, FromStart: true, Poll: 10 * time.Millisecond,
		BatchLines: 200, BatchWait: 30 * time.Millisecond, Version: "test", SourceID: "test", Log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))}
}

// start runs an agent and returns a function that stops it and waits.
func (r *rig) start(cfg agent.Config) (stop func()) {
	c, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- agent.Run(c, cfg) }()
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			r.t.Fatal("agent did not stop")
		}
	}
}

func (r *rig) write(prefix string, from, to int) {
	f, err := os.OpenFile(r.log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		r.t.Fatal(err)
	}
	defer f.Close()
	for i := from; i <= to; i++ {
		fmt.Fprintf(f, "2026/10/09 12:00:%02d.000001 from 198.51.100.7:4000 accepted tcp:%s-%d.example.test:443 [Steal -> DIRECT] email: 2\n", i%60, prefix, i)
	}
}

func (r *rig) count() int {
	var n int
	_ = r.st.Pool().QueryRow(ctx, `SELECT count(*) FROM connection_events`).Scan(&n)
	return n
}

func (r *rig) distinctHosts() int {
	var n int
	_ = r.st.Pool().QueryRow(ctx, `SELECT count(DISTINCT destination_host) FROM connection_events`).Scan(&n)
	return n
}

func (r *rig) waitCount(want int) {
	r.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if r.count() == want {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	r.t.Fatalf("want %d events in the database, have %d", want, r.count())
}

func (r *rig) settle() { time.Sleep(400 * time.Millisecond) }

func TestLinesFlowFromAFileToTheDatabase(t *testing.T) {
	r := newRig(t)
	r.write("a", 1, 300)
	stop := r.start(r.cfg())
	defer stop()
	r.waitCount(300)
	r.write("b", 1, 50)
	r.waitCount(350)
	var resolved int
	_ = r.st.Pool().QueryRow(ctx, `SELECT count(*) FROM connection_events WHERE user_id IS NOT NULL`).Scan(&resolved)
	if resolved != 350 {
		t.Fatalf("every event carries email 2, which is a panel user: %d resolved", resolved)
	}
	a, _ := r.st.ListAgents(ctx, store.Scope{All: true}, r.panel.ID)
	if a[0].LastAckSeq != 350 || a[0].EventsTotal != 350 || a[0].Status != "active" || a[0].LastEventAt == nil {
		t.Fatalf("%+v", a[0])
	}
}

func TestADroppedConnectionNeitherLosesNorRepeatsLines(t *testing.T) {
	r := newRig(t)
	stop := r.start(r.cfg())
	defer stop()
	r.write("a", 1, 400)
	r.waitCount(400)
	r.srv.CloseClientConnections() // the network drops
	r.write("b", 1, 400)
	r.waitCount(800)
	r.srv.CloseClientConnections()
	r.write("c", 1, 400)
	r.waitCount(1200)
	r.settle()
	if n := r.count(); n != 1200 || r.distinctHosts() != 1200 {
		t.Fatalf("%d events, %d distinct hosts: duplicates or losses after reconnects", n, r.distinctHosts())
	}
}

func TestRestartingTheAgentContinuesExactlyWhereItLeftOff(t *testing.T) {
	r := newRig(t)
	cfg := r.cfg()
	stop := r.start(cfg)
	r.write("a", 1, 250)
	r.waitCount(250)
	stop()
	r.write("b", 1, 100) // appears while the agent is down
	stop2 := r.start(cfg)
	defer stop2()
	r.waitCount(350)
	r.settle()
	if r.count() != 350 || r.distinctHosts() != 350 {
		t.Fatalf("%d events, %d distinct hosts", r.count(), r.distinctHosts())
	}
}

func TestLostStateStartsANewEpochWithoutConfusingTheServer(t *testing.T) {
	r := newRig(t)
	cfg := r.cfg()
	stop := r.start(cfg)
	r.write("a", 1, 100)
	r.waitCount(100)
	stop()
	_ = os.RemoveAll(cfg.StateDir) // the disk was wiped
	cfg.FromStart = false
	stop2 := r.start(cfg)
	defer stop2()
	time.Sleep(300 * time.Millisecond)
	r.write("z", 1, 60)
	r.waitCount(160)
	r.settle()
	if r.count() != 160 || r.distinctHosts() != 160 {
		t.Fatalf("a new epoch restarts numbering at 1; those lines must be added, not mistaken for old ones: %d events", r.count())
	}
}

func TestACrashBetweenSpoolAndAckReplaysSafely(t *testing.T) {
	r := newRig(t)
	cfg := r.cfg()
	r.write("a", 1, 500)
	// The server is unreachable at first, so everything sits in the spool.
	badCfg := cfg
	badCfg.ServerURL = "ws://127.0.0.1:1/ingest/v1"
	stop := r.start(badCfg)
	time.Sleep(600 * time.Millisecond)
	stop() // "crash" with 500 unsent lines in the spool

	stop2 := r.start(cfg)
	defer stop2()
	r.waitCount(500)
	r.settle()
	if r.count() != 500 || r.distinctHosts() != 500 {
		t.Fatalf("%d events", r.count())
	}
}

func TestAFullSpoolDropsNewLinesAndReportsTheGap(t *testing.T) {
	r := newRig(t)
	cfg := r.cfg()
	cfg.SpoolMaxBytes = 4096
	cfg.ServerURL = "ws://127.0.0.1:1/ingest/v1" // unreachable: nothing drains the spool
	stop := r.start(cfg)
	r.write("a", 1, 200) // ~25 KB into a 4 KB spool
	time.Sleep(500 * time.Millisecond)
	stop()

	cfg.ServerURL = "ws" + strings.TrimPrefix(r.srv.URL, "http")
	cfg.FromStart = false
	stop2 := r.start(cfg)
	defer stop2()
	deadline := time.Now().Add(10 * time.Second)
	var gapLines, dropped int64
	for time.Now().Before(deadline) {
		_ = r.st.Pool().QueryRow(ctx, `SELECT COALESCE(sum(lines),0) FROM agent_gaps WHERE reason='spool_full'`).Scan(&gapLines)
		_ = r.st.Pool().QueryRow(ctx, `SELECT dropped_total FROM agents WHERE id=$1`, r.agent.ID).Scan(&dropped)
		if gapLines > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	n := int64(r.count())
	if gapLines == 0 || dropped != gapLines || n+dropped != 200 || n == 0 {
		t.Logf("note: the drop counters live in memory, so a restart between drop and report forgets them")
		t.Fatalf("stored %d, dropped %d, gap lines %d: loss must be reported exactly", n, dropped, gapLines)
	}
}

func TestARevokedAgentStopsDeliveringAndStoresNothing(t *testing.T) {
	r := newRig(t)
	stop := r.start(r.cfg())
	defer stop()
	r.write("a", 1, 50)
	r.waitCount(50)
	if err := r.st.RevokeAgent(ctx, store.Scope{All: true}, r.panel.ID, r.agent.ID); err != nil {
		t.Fatal(err)
	}
	r.srv.CloseClientConnections()
	r.write("b", 1, 50)
	time.Sleep(1500 * time.Millisecond)
	if r.count() != 50 {
		t.Fatalf("a revoked agent must not add data: %d", r.count())
	}
}

func TestOnlyWholeLinesAreShippedAndMalformedOnesAreCountedNotStored(t *testing.T) {
	r := newRig(t)
	stop := r.start(r.cfg())
	defer stop()
	r.write("a", 1, 10)
	f, _ := os.OpenFile(r.log, os.O_APPEND|os.O_WRONLY, 0)
	fmt.Fprintln(f, "this is not an access log line")
	f.Close()
	r.write("b", 1, 10)
	r.waitCount(20)
	deadline := time.Now().Add(5 * time.Second)
	var pe int64
	for time.Now().Before(deadline) && pe == 0 {
		_ = r.st.Pool().QueryRow(ctx, `SELECT parse_errors FROM agents WHERE id=$1`, r.agent.ID).Scan(&pe)
		time.Sleep(25 * time.Millisecond)
	}
	if pe != 1 {
		t.Fatalf("parse_errors=%d", pe)
	}
}

func TestExecSourceDeliversThroughTheWholePipeline(t *testing.T) {
	r := newRig(t)
	cfg := r.cfg()
	cfg.Kind = agent.SourceExec
	cfg.Argv = []string{os.Args[0], "-test.run=^TestHelperProcessE2E$", "remnascope-e2e-helper", "30"}
	stop := r.start(cfg)
	defer stop()
	r.waitCount(30)
}

func TestHelperProcessE2E(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "remnascope-e2e-helper" {
		return
	}
	var n int
	fmt.Sscanf(os.Args[len(os.Args)-1], "%d", &n)
	for i := 1; i <= n; i++ {
		fmt.Printf("2026/10/09 12:00:%02d.000001 from 198.51.100.7:4000 accepted tcp:exec-%d.example.test:443 [Steal -> DIRECT] email: 2\n", i%60, i)
	}
	time.Sleep(2 * time.Second) // stay up like `tail -F` would
	os.Exit(0)
}

func TestShipperReportsAnUnrecoverableGap(t *testing.T) {
	r := newRig(t)
	dir := t.TempDir()
	sp, err := agent.OpenSpool(dir, 1<<20, 10) // numbering starts at 10; the server has acked nothing
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Close()
	for i := 0; i < 5; i++ {
		_, _ = sp.Append(fmt.Sprintf("2026/10/09 12:00:00.000001 from 198.51.100.7:4000 accepted tcp:x-%d.example.test:443 [Steal -> DIRECT] email: 2", i))
	}
	s := &agent.Shipper{URL: "ws" + strings.TrimPrefix(r.srv.URL, "http"), TokenFile: r.token, AllowInsecure: true, Spool: sp, Counters: &agent.Counters{},
		Epoch: "e", SourceID: "t", Version: "t", BatchWait: 10 * time.Millisecond, Log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))}
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = s.Run(c)
	if err != agent.ErrUnrecoverableGap {
		t.Fatalf("%v", err)
	}
	if r.count() != 0 {
		t.Fatal("nothing may be stored from lines the server cannot place")
	}
}

func TestPlainWSIsRefusedUnlessExplicitlyAllowed(t *testing.T) {
	sp, _ := agent.OpenSpool(t.TempDir(), 1<<20, 1)
	defer sp.Close()
	s := &agent.Shipper{URL: "ws://example.com/ingest/v1", TokenFile: "x", Spool: sp, Counters: &agent.Counters{}, Epoch: "e"}
	if err := s.Run(ctx); err == nil || !strings.Contains(err.Error(), "wss://") {
		t.Fatalf("%v", err)
	}
	s.URL = "http://example.com/ingest/v1"
	s.AllowInsecure = true
	if err := s.Run(ctx); err == nil {
		t.Fatal("a non-websocket scheme must be refused even in insecure mode")
	}
}
