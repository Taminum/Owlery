package store_test

import (
	"crypto/sha256"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/store"
	"github.com/Taminum/RemnaScope/internal/store/storetest"
	"github.com/Taminum/RemnaScope/internal/xraylog"
)

type agentEnv struct {
	s       *store.Store
	panel   store.Panel
	nodeID  string
	agent   store.Agent
	userID2 string
}

func newAgentEnv(t *testing.T) *agentEnv {
	t.Helper()
	s := storetest.New(t)
	p := mkPanel(t, s, "home")
	start := time.Now().UTC()
	if _, err := s.UpsertNodes(ctx, p.ID, start, []store.NodeRecord{{RemoteUUID: "n1", Name: "node-1"}}); err != nil {
		t.Fatal(err)
	}
	nodes, _ := s.ListNodes(ctx, store.Scope{All: true}, p.ID, false)
	if _, err := s.UpsertUsers(ctx, p.ID, start, []store.UserRecord{{RemoteUUID: "2", Username: "alice"}, {RemoteUUID: "3", Username: "bob"}}); err != nil {
		t.Fatal(err)
	}
	us, _, _ := s.ListUsers(ctx, store.Scope{All: true}, p.ID, "", 10)
	var u2 string
	for _, u := range us {
		if u.RemoteUUID == "2" {
			u2 = u.ID
		}
	}
	a, err := s.CreateAgent(ctx, store.Scope{All: true}, p.ID, nodes[0].ID, "agent-1", "node", "", store.HashAgentSecret("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AgentHello(ctx, a.ID, "epoch-1", "0.1", "src"); err != nil {
		t.Fatal(err)
	}
	return &agentEnv{s: s, panel: p, nodeID: nodes[0].ID, agent: a, userID2: u2}
}

func ev(sec int, email, host string) *xraylog.Event {
	return &xraylog.Event{Time: time.Date(2026, 10, 9, 12, 0, sec, 0, time.UTC), ClientIP: netip.MustParseAddr("198.51.100.7"), ClientPort: 4000,
		Protocol: "tcp", DestHost: host, DestPort: 443, InboundTag: "Steal", OutboundTag: "DIRECT", Arrow: "->", Email: email}
}

func line(seq int64, e *xraylog.Event) store.Line {
	fp := sha256.Sum256([]byte{byte(seq)})
	return store.Line{Seq: seq, Event: e, FP: fp[:]}
}

func countEvents(t *testing.T, s *store.Store, panelID string) int {
	t.Helper()
	var n int
	_ = s.Pool().QueryRow(ctx, `SELECT count(*) FROM connection_events WHERE panel_id=$1`, panelID).Scan(&n)
	return n
}

func TestBatchIsStoredAndUserResolvedThroughThePanelOnly(t *testing.T) {
	e := newAgentEnv(t)
	internal := &xraylog.Event{Time: time.Date(2026, 10, 9, 12, 0, 5, 0, time.UTC), Internal: true, Protocol: "udp", DestIP: netip.MustParseAddr("9.9.9.9"),
		DestPort: 53, InboundTag: "xray.system.x", OutboundTag: "DIRECT", Arrow: ">>"}
	res, err := e.s.CommitBatch(ctx, store.Commit{AgentID: e.agent.ID, Lines: []store.Line{
		line(1, ev(1, "2", "a.example.test")), line(2, ev(2, "99", "b.example.test")), line(3, nil), line(4, internal),
	}})
	if err != nil || res.Accepted != 3 || res.ParseErrs != 1 || res.AckSeq != 4 {
		t.Fatalf("%+v %v", res, err)
	}
	var resolved, unresolved, internalN int
	_ = e.s.Pool().QueryRow(ctx, `SELECT count(*) FROM connection_events WHERE user_id=$1 AND xray_email='2'`, e.userID2).Scan(&resolved)
	_ = e.s.Pool().QueryRow(ctx, `SELECT count(*) FROM connection_events WHERE user_id IS NULL AND xray_email='99'`).Scan(&unresolved)
	_ = e.s.Pool().QueryRow(ctx, `SELECT count(*) FROM connection_events WHERE internal AND user_id IS NULL AND xray_email IS NULL`).Scan(&internalN)
	if resolved != 1 || unresolved != 1 || internalN != 1 {
		t.Fatalf("resolved=%d unresolved=%d internal=%d", resolved, unresolved, internalN)
	}
	a, _ := e.s.ListAgents(ctx, store.Scope{All: true}, e.panel.ID)
	if a[0].LastAckSeq != 4 || a[0].EventsTotal != 3 || a[0].ParseErrors != 1 || a[0].LastEventAt == nil {
		t.Fatalf("%+v", a[0])
	}
}

func TestReplayedBatchDoesNotDoubleCountButIdenticalLinesAreKept(t *testing.T) {
	e := newAgentEnv(t)
	same := ev(1, "2", "same.example.test") // identical content, different sequence numbers
	batch := store.Commit{AgentID: e.agent.ID, Lines: []store.Line{line(1, same), line(2, same), line(3, same)}}
	if res, err := e.s.CommitBatch(ctx, batch); err != nil || res.Accepted != 3 {
		t.Fatalf("%+v %v", res, err)
	}
	res, err := e.s.CommitBatch(ctx, batch) // the ack was lost and the agent resends everything
	if err != nil || res.Accepted != 0 || res.Duplicates != 3 || res.AckSeq != 3 {
		t.Fatalf("%+v %v", res, err)
	}
	if n := countEvents(t, e.s, e.panel.ID); n != 3 {
		t.Fatalf("expected 3 legitimate identical lines and no extras, got %d", n)
	}
	res, err = e.s.CommitBatch(ctx, store.Commit{AgentID: e.agent.ID, Lines: []store.Line{line(2, same), line(3, same), line(4, same), line(5, same)}})
	if err != nil || res.Accepted != 2 || res.Duplicates != 2 || res.AckSeq != 5 {
		t.Fatalf("%+v %v", res, err)
	}
	if n := countEvents(t, e.s, e.panel.ID); n != 5 {
		t.Fatalf("got %d", n)
	}
}

func TestSequenceGapIsRefusedAndNothingIsStored(t *testing.T) {
	e := newAgentEnv(t)
	_, err := e.s.CommitBatch(ctx, store.Commit{AgentID: e.agent.ID, Lines: []store.Line{line(1, ev(1, "2", "a.example.test")), line(3, ev(3, "2", "b.example.test"))}})
	var gap *store.ErrSeqGap
	if !errors.As(err, &gap) || gap.Expected != 1 {
		t.Fatalf("%v", err)
	}
	if n := countEvents(t, e.s, e.panel.ID); n != 0 {
		t.Fatal("a rejected batch must leave no rows")
	}
	if _, err := e.s.CommitBatch(ctx, store.Commit{AgentID: e.agent.ID, Lines: []store.Line{line(5, ev(1, "2", "a.example.test"))}}); err == nil {
		t.Fatal("a batch that starts ahead of the ack must be refused")
	}
}

func TestNewEpochRestartsNumberingWithoutLosingOrMixingEvents(t *testing.T) {
	e := newAgentEnv(t)
	_, _ = e.s.CommitBatch(ctx, store.Commit{AgentID: e.agent.ID, Lines: []store.Line{line(1, ev(1, "2", "a.example.test")), line(2, ev(2, "2", "b.example.test"))}})
	ack, err := e.s.AgentHello(ctx, e.agent.ID, "epoch-1", "0.1", "src")
	if err != nil || ack != 2 {
		t.Fatalf("same epoch keeps the ack: %d %v", ack, err)
	}
	ack, err = e.s.AgentHello(ctx, e.agent.ID, "epoch-2", "0.1", "src") // agent lost its state
	if err != nil || ack != 0 {
		t.Fatalf("new epoch resets the ack: %d %v", ack, err)
	}
	if res, err := e.s.CommitBatch(ctx, store.Commit{AgentID: e.agent.ID, Lines: []store.Line{line(1, ev(1, "2", "a.example.test"))}}); err != nil || res.Accepted != 1 {
		t.Fatalf("seq 1 of the new epoch must be accepted, not mistaken for the old seq 1: %+v %v", res, err)
	}
	if n := countEvents(t, e.s, e.panel.ID); n != 3 {
		t.Fatalf("got %d", n)
	}
}

func TestAgentBoundToItsNodeAndPanel(t *testing.T) {
	s := storetest.New(t)
	home, work := mkPanel(t, s, "home"), mkPanel(t, s, "work")
	now := time.Now().UTC()
	_, _ = s.UpsertNodes(ctx, home.ID, now, []store.NodeRecord{{RemoteUUID: "h", Name: "h"}})
	_, _ = s.UpsertNodes(ctx, work.ID, now, []store.NodeRecord{{RemoteUUID: "w", Name: "w"}})
	hn, _ := s.ListNodes(ctx, store.Scope{All: true}, home.ID, false)
	wn, _ := s.ListNodes(ctx, store.Scope{All: true}, work.ID, false)

	if _, err := s.CreateAgent(ctx, store.Scope{All: true}, home.ID, wn[0].ID, "x", "node", "", store.HashAgentSecret("s")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a node of another panel must not take an agent: %v", err)
	}
	if _, err := s.CreateAgent(ctx, store.Scope{IDs: []string{work.ID}}, home.ID, hn[0].ID, "x", "node", "", store.HashAgentSecret("s")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("out of scope: %v", err)
	}
	a, err := s.CreateAgent(ctx, store.Scope{All: true}, home.ID, hn[0].ID, "x", "node", "", store.HashAgentSecret("s"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAgent(ctx, store.Scope{All: true}, home.ID, hn[0].ID, "y", "node", "", store.HashAgentSecret("s2")); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("one live agent per node: %v", err)
	}
	if _, err := s.ListAgents(ctx, store.Scope{IDs: []string{work.ID}}, home.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("list across scope: %v", err)
	}
	_, _ = s.AgentHello(ctx, a.ID, "e", "v", "s")
	_, _ = s.CommitBatch(ctx, store.Commit{AgentID: a.ID, Lines: []store.Line{line(1, ev(1, "2", "a.example.test"))}})
	var panel, node string
	_ = s.Pool().QueryRow(ctx, `SELECT panel_id::text, node_id::text FROM connection_events LIMIT 1`).Scan(&panel, &node)
	if panel != home.ID || node != hn[0].ID {
		t.Fatalf("event stored under %s/%s", panel, node)
	}
}

func TestRevokedAgentCannotConnectOrCommitAndNodeCanBeReEnrolled(t *testing.T) {
	e := newAgentEnv(t)
	if err := e.s.RevokeAgent(ctx, store.Scope{All: true}, e.panel.ID, e.agent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.AgentHello(ctx, e.agent.ID, "e", "v", "s"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("hello after revoke: %v", err)
	}
	if _, err := e.s.CommitBatch(ctx, store.Commit{AgentID: e.agent.ID, Lines: []store.Line{line(1, ev(1, "2", "a.example.test"))}}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("commit after revoke: %v", err)
	}
	if err := e.s.RevokeAgent(ctx, store.Scope{All: true}, e.panel.ID, e.agent.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
	if _, err := e.s.CreateAgent(ctx, store.Scope{All: true}, e.panel.ID, e.nodeID, "again", "node", "", store.HashAgentSecret("s3")); err != nil {
		t.Fatalf("a revoked agent frees its node: %v", err)
	}
	list, _ := e.s.ListAgents(ctx, store.Scope{All: true}, e.panel.ID)
	if len(list) != 1 || list[0].ID == e.agent.ID {
		t.Fatalf("only live agents are listed: %+v", list)
	}
}

func TestGapsAndDropsAreRecorded(t *testing.T) {
	e := newAgentEnv(t)
	from, to := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC), time.Date(2026, 10, 9, 12, 5, 0, 0, time.UTC)
	_, err := e.s.CommitBatch(ctx, store.Commit{AgentID: e.agent.ID, Dropped: 120, SpoolBytes: 4096,
		Lines: []store.Line{line(1, ev(1, "2", "a.example.test"))}, Gaps: []store.GapReport{{From: &from, To: &to, Lines: 120, Reason: "spool_full"}}})
	if err != nil {
		t.Fatal(err)
	}
	var reason string
	var lines int64
	_ = e.s.Pool().QueryRow(ctx, `SELECT reason, lines FROM agent_gaps WHERE agent_id=$1`, e.agent.ID).Scan(&reason, &lines)
	a, _ := e.s.ListAgents(ctx, store.Scope{All: true}, e.panel.ID)
	if reason != "spool_full" || lines != 120 || a[0].Dropped != 120 || a[0].SpoolBytes != 4096 {
		t.Fatalf("%s %d %+v", reason, lines, a[0])
	}
}

func TestRetentionPurgesOnlyExpiredEvents(t *testing.T) {
	e := newAgentEnv(t)
	old := ev(1, "2", "old.example.test")
	old.Time = time.Now().UTC().AddDate(0, 0, -40)
	fresh := ev(2, "2", "new.example.test")
	fresh.Time = time.Now().UTC().Add(-time.Hour)
	_, _ = e.s.CommitBatch(ctx, store.Commit{AgentID: e.agent.ID, Lines: []store.Line{line(1, old), line(2, fresh)}})
	n, err := e.s.PurgeExpiredEvents(ctx, time.Now().UTC()) // retention is 30 days
	if err != nil || n != 1 {
		t.Fatalf("purged %d %v", n, err)
	}
	if got := countEvents(t, e.s, e.panel.ID); got != 1 {
		t.Fatalf("%d left", got)
	}
}

func TestDeletingAPanelRemovesItsEventsAndAgents(t *testing.T) {
	e := newAgentEnv(t)
	_, _ = e.s.CommitBatch(ctx, store.Commit{AgentID: e.agent.ID, Lines: []store.Line{line(1, ev(1, "2", "a.example.test"))}})
	if err := e.s.DeletePanel(ctx, e.panel.ID, "purge"); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = e.s.Pool().QueryRow(ctx, `SELECT (SELECT count(*) FROM connection_events)+(SELECT count(*) FROM agents)+(SELECT count(*) FROM agent_gaps)`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d rows survived a purge", n)
	}
}
