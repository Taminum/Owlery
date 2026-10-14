package store_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/ingestproto"
	"github.com/Taminum/RemnaScope/internal/store"
)

const (
	keyA = "AAAA111111111111111111111111111111111111111="
	keyB = "BBBB222222222222222222222222222222222222222="
)

func awgAgent(t *testing.T, e *agentEnv) store.Agent {
	t.Helper()
	a, err := e.s.CreateAgent(ctx, store.Scope{All: true}, e.panel.ID, e.nodeID, "awg", "awg", "", store.HashAgentSecret("awg-secret"))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func snap(rxA, txA, rxB, txB int64, hsA int64, fields ...string) ingestproto.AWG {
	return ingestproto.AWG{Type: "awg", Instances: []ingestproto.AWGInstance{{Container: "c1", Interface: "awg0", Port: 49587, Fields: fields,
		Peers: []ingestproto.AWGPeer{{Key: keyA, Name: "RouterOne", IP: "10.8.1.2/32", RX: rxA, TX: txA, Handshake: hsA}, {Key: keyB, IP: "10.8.1.18/32", RX: rxB, TX: txB}}}}}
}

func TestAWGSnapshotsBuildInstancesPeersAndCountersWithResets(t *testing.T) {
	e := newAgentEnv(t)
	ag := awgAgent(t, e)
	now := time.Now().UTC().Truncate(time.Second)
	hs := now.Add(-30 * time.Second).Unix()
	if err := e.s.SaveAWG(ctx, ag, snap(1000, 5000, 0, 0, hs, "Jc", "S3", "S4", "H1"), now.Add(-30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// grows by 500/2000, then the interface restarts (counters fall), then grows again
	steps := []struct {
		at             time.Duration
		rx, tx         int64
		wantRX, wantTX int64 // expected totals of the period so far
	}{{-20 * time.Minute, 1500, 7000, 500, 2000}, {-10 * time.Minute, 100, 300, 600, 2300}, {-1 * time.Minute, 400, 900, 900, 2900}}
	for _, st := range steps {
		if err := e.s.SaveAWG(ctx, ag, snap(st.rx, st.tx, 0, 0, hs, "Jc", "S3", "S4", "H1"), now.Add(st.at)); err != nil {
			t.Fatal(err)
		}
	}
	insts, err := e.s.AWGInstances(ctx, store.Scope{All: true}, time.Hour)
	if err != nil || len(insts) != 1 {
		t.Fatalf("%v %+v", err, insts)
	}
	in := insts[0]
	if in.Container != "c1" || in.Port != 49587 || in.Variant != "AWG 2.0" || in.Mode != "read_only" || len(in.Peers) != 2 {
		t.Fatalf("%+v", in)
	}
	var a, b store.AWGPeerRow
	for _, p := range in.Peers {
		if p.Key == keyA {
			a = p
		} else {
			b = p
		}
	}
	if a.Label != "RouterOne" || a.TunnelIP != "10.8.1.2/32" || a.RX != 400 || a.TX != 900 || a.Handshake == nil {
		t.Fatalf("%+v", a)
	}
	// 1000->1500 (+500), reset to 100 (counts as 100), 100->400 (+300): 900; tx 2000+300+600 = 2900
	if a.PeriodRX != 900 || a.PeriodTX != 2900 {
		t.Fatalf("period totals with a reset: rx %d tx %d", a.PeriodRX, a.PeriodTX)
	}
	if b.PeriodRX != 0 || b.PeriodTX != 0 || b.Handshake != nil {
		t.Fatalf("a peer that never connected: %+v", b)
	}
	pts, err := e.s.AWGSeries(ctx, store.Scope{All: true}, a.ID, now.Add(-time.Hour), now, 15*time.Minute)
	if err != nil || len(pts) == 0 {
		t.Fatalf("%v %+v", err, pts)
	}
	var rx, tx int64
	for _, p := range pts {
		rx, tx = rx+p.RX, tx+p.TX
	}
	if rx != 900 || tx != 2900 {
		t.Fatalf("series sums %d/%d", rx, tx)
	}
}

func TestAWGUnchangedSamplesAreNotStoredAndAGonePeerIsKept(t *testing.T) {
	e := newAgentEnv(t)
	ag := awgAgent(t, e)
	now := time.Now().UTC()
	for i := 0; i < 5; i++ { // five identical reports within the keep-alive window
		if err := e.s.SaveAWG(ctx, ag, snap(10, 20, 0, 0, 0), now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	_ = e.s.Pool().QueryRow(ctx, `SELECT count(*) FROM awg_samples`).Scan(&n)
	if n != 2 { // one per peer
		t.Fatalf("%d samples for five identical reports", n)
	}
	if err := e.s.SaveAWG(ctx, ag, snap(10, 20, 0, 0, 0), now.Add(30*time.Minute)); err != nil { // the old one is refreshed
		t.Fatal(err)
	}
	_ = e.s.Pool().QueryRow(ctx, `SELECT count(*) FROM awg_samples`).Scan(&n)
	if n != 4 {
		t.Fatalf("%d samples after the keep-alive interval", n)
	}
	// peer B disappears from the interface: it is marked gone, its history stays, its label survives
	only := ingestproto.AWG{Type: "awg", Instances: []ingestproto.AWGInstance{{Container: "c1", Interface: "awg0", Peers: []ingestproto.AWGPeer{{Key: keyA, RX: 10, TX: 20}}}}}
	if err := e.s.SaveAWG(ctx, ag, only, now.Add(31*time.Minute)); err != nil {
		t.Fatal(err)
	}
	insts, _ := e.s.AWGInstances(ctx, store.Scope{All: true}, time.Hour)
	var gone, kept int
	for _, p := range insts[0].Peers {
		if p.Gone {
			gone++
		} else {
			kept++
		}
	}
	if gone != 1 || kept != 1 || insts[0].Peers[0].Label != "RouterOne" {
		t.Fatalf("%+v", insts[0].Peers)
	}
}

func TestAWGInvalidInputIsSkippedAndTextIsCleaned(t *testing.T) {
	e := newAgentEnv(t)
	ag := awgAgent(t, e)
	bad := ingestproto.AWG{Type: "awg", Instances: []ingestproto.AWGInstance{
		{Container: "", Interface: "awg0"}, // no container: skipped
		{Container: "c1", Interface: "awg0", Peers: []ingestproto.AWGPeer{
			{Key: "not-a-key", RX: 1},  // bad key
			{Key: keyA, RX: -5, TX: 1}, // negative counter
			{Key: keyB, Name: "evil\x00name\n" + strings.Repeat("x", 200), RX: 1, TX: 2}, // kept, cleaned
		}},
	}}
	if err := e.s.SaveAWG(ctx, ag, bad, time.Now()); err != nil {
		t.Fatal(err)
	}
	insts, _ := e.s.AWGInstances(ctx, store.Scope{All: true}, time.Hour)
	if len(insts) != 1 || len(insts[0].Peers) != 1 {
		t.Fatalf("%+v", insts)
	}
	l := insts[0].Peers[0].Label
	if len(l) > 64 || strings.ContainsAny(l, "\x00\n") {
		t.Fatalf("label %q", l)
	}
}

func TestAWGIsScopedToThePanelsOfTheCaller(t *testing.T) {
	e := newAgentEnv(t)
	ag := awgAgent(t, e)
	if err := e.s.SaveAWG(ctx, ag, snap(1, 2, 0, 0, 0), time.Now()); err != nil {
		t.Fatal(err)
	}
	other := mkPanel(t, e.s, "other")
	if insts, _ := e.s.AWGInstances(ctx, store.Scope{IDs: []string{other.ID}}, time.Hour); len(insts) != 0 {
		t.Fatalf("another panel's scope saw %d instances", len(insts))
	}
	insts, _ := e.s.AWGInstances(ctx, store.Scope{All: true}, time.Hour)
	if _, err := e.s.AWGSeries(ctx, store.Scope{IDs: []string{other.ID}}, insts[0].Peers[0].ID, time.Now().Add(-time.Hour), time.Now(), time.Minute); err == nil {
		t.Fatal("a peer of another panel was readable")
	}
}

func TestAWGVariantComesFromParameterNames(t *testing.T) {
	for want, fields := range map[string][]string{
		"AWG 3.x": {"Jc", "S1", "S2", "S3", "S4", "H1", "I1"},
		"AWG 2.0": {"Jc", "S1", "S2", "S3", "S4", "H1"},
		"AWG 1.x": {"Jc", "S1", "S2", "H1"},
		"":        {"Address"},
	} {
		if got := store.AWGVariant(fields); got != want {
			t.Errorf("%v: %q want %q", fields, got, want)
		}
	}
}

func TestAWGRemembersLastSeenAndTheAmneziaPanelSnapshot(t *testing.T) {
	e := newAgentEnv(t)
	ag := awgAgent(t, e)
	now := time.Now().UTC().Truncate(time.Second)
	old := now.Add(-48 * time.Hour).Unix()
	snap1 := ingestproto.AWG{Type: "awg", Instances: []ingestproto.AWGInstance{{Container: "c1", Interface: "awg0", Started: now.Add(-6 * 24 * time.Hour).Unix(), LegacyAt: now.Add(-12 * 24 * time.Hour).Unix(),
		Peers: []ingestproto.AWGPeer{
			{Key: keyA, Name: "tablet", RX: 5, TX: 6, Handshake: old, LegacyDown: 83 << 30, LegacyUp: 2 << 30, LegacyHS: now.Add(-36 * 24 * time.Hour).Unix()},
			{Key: keyB, Name: "oldie", LegacyDown: 1 << 30, LegacyHS: now.Add(-40 * 24 * time.Hour).Unix()},
		}}}}
	if err := e.s.SaveAWG(ctx, ag, snap1, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	// later the interface restarted: tablet has no handshake now, oldie never had one
	snap2 := ingestproto.AWG{Type: "awg", Instances: []ingestproto.AWGInstance{{Container: "c1", Interface: "awg0", Peers: []ingestproto.AWGPeer{{Key: keyA, Name: "tablet"}, {Key: keyB, Name: "oldie"}}}}}
	if err := e.s.SaveAWG(ctx, ag, snap2, now); err != nil {
		t.Fatal(err)
	}
	insts, err := e.s.AWGInstances(ctx, store.Scope{All: true}, time.Hour)
	if err != nil || len(insts) != 1 {
		t.Fatal(err, insts)
	}
	in := insts[0]
	if in.Started == nil || in.LegacyAt == nil || in.Started.After(now.Add(-5*24*time.Hour)) {
		t.Fatalf("started/legacy_at not kept: %+v %+v", in.Started, in.LegacyAt)
	}
	for _, p := range in.Peers {
		switch p.Label {
		case "tablet":
			if p.EverHS == nil || p.EverHS.Unix() != old {
				t.Fatalf("a handshake once recorded must be remembered after the interface forgets it: %+v", p.EverHS)
			}
			if p.LegacyDown == nil || *p.LegacyDown != 83<<30 || p.LegacyHS == nil {
				t.Fatalf("legacy snapshot lost: %+v", p)
			}
		case "oldie":
			if p.EverHS != nil || p.LegacyHS == nil || p.LegacyDown == nil {
				t.Fatalf("%+v", p)
			}
		}
	}
	// a later snapshot that carries no legacy data must not erase it
	if insts2, _ := e.s.AWGInstances(ctx, store.Scope{All: true}, time.Hour); insts2[0].LegacyAt == nil {
		t.Fatal("legacy_at was erased")
	}
}

func TestAWGRunningTotalCountsWhatTheServerAlreadyHeldAtFirstSightAndFirstImportWins(t *testing.T) {
	e := newAgentEnv(t)
	ag := awgAgent(t, e)
	now := time.Now().UTC().Truncate(time.Second)
	created := now.Add(-100 * 24 * time.Hour).Unix()
	mk := func(rx, tx int64, legacyDown int64, legacyAt int64, hs int64) ingestproto.AWG {
		return ingestproto.AWG{Type: "awg", Instances: []ingestproto.AWGInstance{{Container: "c1", Interface: "awg0", LegacyAt: legacyAt,
			Peers: []ingestproto.AWGPeer{{Key: keyA, Name: "PhoneOne", RX: rx, TX: tx, LegacyDown: legacyDown, LegacyHS: hs, Created: created}}}}}
	}
	first := now.Add(-3 * time.Hour)
	// first sight: the counters already hold 1000 GB sent to the client; the old table said 5 GB
	if err := e.s.SaveAWG(ctx, ag, mk(10, 1000e9, 5e9, now.Add(-12*24*time.Hour).Unix(), now.Add(-30*24*time.Hour).Unix()), first); err != nil {
		t.Fatal(err)
	}
	// then +2 GB, then the counters restart and grow to 1 GB
	if err := e.s.SaveAWG(ctx, ag, mk(10, 1002e9, 0, 0, 0), first.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// the old table is rewritten later with another time and other numbers: it must not move the import
	if err := e.s.SaveAWG(ctx, ag, mk(10, 1e9, 99e9, now.Unix(), now.Unix()), first.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	insts, _ := e.s.AWGInstances(ctx, store.Scope{All: true}, time.Hour)
	p := insts[0].Peers[0]
	if p.TrackedTX != 1000e9+2e9+1e9 {
		t.Fatalf("tracked sent %d: the first reading (1000 GB) counts in full, then +2 GB, then a restart to 1 GB", p.TrackedTX)
	}
	if p.LegacyDown == nil || *p.LegacyDown != 5e9 {
		t.Fatalf("the first import was overwritten: %v", p.LegacyDown)
	}
	if p.LegacyHS == nil || p.LegacyHS.After(now.Add(-29*24*time.Hour)) {
		t.Fatalf("the imported handshake moved: %v", p.LegacyHS)
	}
	if insts[0].LegacyAt == nil || time.Since(*insts[0].LegacyAt) < 11*24*time.Hour {
		t.Fatal("legacy_at moved")
	}
	if p.CreatedHint == nil || p.CreatedHint.Unix() != created {
		t.Fatalf("created: %v", p.CreatedHint)
	}
}

func TestAWGGonePeersCanBeForgottenButLiveOnesCannot(t *testing.T) {
	e := newAgentEnv(t)
	ag := awgAgent(t, e)
	now := time.Now().UTC()
	if err := e.s.SaveAWG(ctx, ag, snap(1, 2, 3, 4, 0), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	only := ingestproto.AWG{Type: "awg", Instances: []ingestproto.AWGInstance{{Container: "c1", Interface: "awg0", Peers: []ingestproto.AWGPeer{{Key: keyA, RX: 1, TX: 2}}}}}
	if err := e.s.SaveAWG(ctx, ag, only, now); err != nil {
		t.Fatal(err)
	}
	insts, _ := e.s.AWGInstances(ctx, store.Scope{All: true}, time.Hour)
	var live, gone store.AWGPeerRow
	for _, p := range insts[0].Peers {
		if p.Gone {
			gone = p
		} else {
			live = p
		}
	}
	if err := e.s.DeleteGoneAWGPeer(ctx, store.Scope{All: true}, live.ID); err == nil {
		t.Fatal("a device that is still on the server was removed")
	}
	other := mkPanel(t, e.s, "other")
	if err := e.s.DeleteGoneAWGPeer(ctx, store.Scope{IDs: []string{other.ID}}, gone.ID); err == nil {
		t.Fatal("another panel's scope removed it")
	}
	if err := e.s.DeleteGoneAWGPeer(ctx, store.Scope{All: true}, gone.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = e.s.Pool().QueryRow(ctx, `SELECT count(*) FROM awg_peers`).Scan(&n)
	var samples int
	_ = e.s.Pool().QueryRow(ctx, `SELECT count(*) FROM awg_samples WHERE peer_id=$1`, gone.ID).Scan(&samples)
	if n != 1 || samples != 0 {
		t.Fatalf("%d peers left, %d samples of the removed one", n, samples)
	}
}
