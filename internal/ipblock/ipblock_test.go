package ipblock

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

type fakeFW struct {
	rules   map[netip.Addr]bool
	failAdd bool
	adds    int
}

func newFW() *fakeFW { return &fakeFW{rules: map[netip.Addr]bool{}} }
func (f *fakeFW) Block(_ context.Context, ip netip.Addr) error {
	if f.failAdd {
		return errors.New("no")
	}
	f.adds++
	f.rules[ip] = true
	return nil
}
func (f *fakeFW) Unblock(_ context.Context, ip netip.Addr) error { delete(f.rules, ip); return nil }
func (f *fakeFW) Blocked(context.Context) ([]netip.Addr, error) {
	var out []netip.Addr
	for ip := range f.rules {
		out = append(out, ip)
	}
	return out, nil
}

var (
	ctx = context.Background()
	t0  = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
)

func cfg(mode string) Config {
	c := DefaultConfig()
	c.Mode = mode
	return c
}

func engine(fw Firewall, path, mode string, allow bool) (*Engine, *time.Time) {
	now := t0
	e := New(fw, path, cfg(mode), allow)
	e.now = func() time.Time { return now }
	return e, &now
}

func failN(e *Engine, ip string, n int, start time.Time) {
	for i := 0; i < n; i++ {
		e.Fail(ctx, ip, start.Add(time.Duration(i)*time.Second))
	}
}

func TestBlocksAtTheLimitAndNotBefore(t *testing.T) {
	fw := newFW()
	e, _ := engine(fw, "", secproto.BlockOn, true)
	failN(e, "203.0.113.5", 4, t0)
	if len(fw.rules) != 0 {
		t.Fatal("four failures are under the limit of five")
	}
	e.Fail(ctx, "203.0.113.5", t0.Add(5*time.Second))
	if !fw.rules[netip.MustParseAddr("203.0.113.5")] {
		t.Fatal("the fifth failure must block")
	}
	s := e.Snapshot()
	if len(s.Active) != 1 || s.Active[0].IP != "203.0.113.5" || s.Active[0].Failed != 5 || s.Active[0].Until == nil || s.Total != 1 {
		t.Errorf("snapshot: %+v", s)
	}
}

func TestFailuresSpreadOverTooLongDoNotAddUpInTenMinutes(t *testing.T) {
	fw := newFW()
	e, _ := engine(fw, "", secproto.BlockOn, true)
	for i := 0; i < 9; i++ { // one every 3 minutes: never five inside ten minutes, and under ten in a day
		e.Fail(ctx, "203.0.113.6", t0.Add(time.Duration(i)*3*time.Minute))
	}
	if len(fw.rules) != 0 {
		t.Errorf("nine slow failures are not blocked: %v", fw.rules)
	}
}

func TestASlowGuesserIsBlockedByTheCountOfADay(t *testing.T) {
	fw := newFW()
	e, _ := engine(fw, "", secproto.BlockOn, true)
	for i := 0; i < SlowThreshold-1; i++ { // one every 15 minutes, like 89.34.90.66
		e.Fail(ctx, "203.0.113.9", t0.Add(time.Duration(i)*15*time.Minute))
	}
	if len(fw.rules) != 0 {
		t.Fatal("nine in a day are under the limit")
	}
	e.Fail(ctx, "203.0.113.9", t0.Add(time.Duration(SlowThreshold-1)*15*time.Minute))
	if !fw.rules[netip.MustParseAddr("203.0.113.9")] {
		t.Fatal("the tenth failure in a day must block")
	}
	if s := e.Snapshot(); len(s.Active) != 1 || s.Active[0].Failed != SlowThreshold {
		t.Errorf("snapshot: %+v", s)
	}
}

func TestFailuresOlderThanADayAreForgotten(t *testing.T) {
	fw := newFW()
	e, _ := engine(fw, "", secproto.BlockOn, true)
	for i := 0; i < SlowThreshold-1; i++ { // one every 3 hours: ten of them take 27 hours
		e.Fail(ctx, "203.0.113.10", t0.Add(time.Duration(i)*3*time.Hour))
	}
	e.Fail(ctx, "203.0.113.10", t0.Add(time.Duration(SlowThreshold-1)*3*time.Hour))
	if len(fw.rules) != 0 {
		t.Errorf("the first failures are more than a day old: %v", fw.rules)
	}
}

func TestASignInClearsTheCountOfADay(t *testing.T) {
	fw := newFW()
	e, _ := engine(fw, "", secproto.BlockOn, true)
	for i := 0; i < SlowThreshold-1; i++ {
		e.Fail(ctx, "203.0.113.11", t0.Add(time.Duration(i)*15*time.Minute))
	}
	e.OK("203.0.113.11", t0.Add(3*time.Hour))
	e.Fail(ctx, "203.0.113.11", t0.Add(4*time.Hour))
	if len(fw.rules) != 0 {
		t.Errorf("somebody who signed in is left alone: %v", fw.rules)
	}
}

func TestWatchModeSaysWhatItWouldDoAndTouchesNothing(t *testing.T) {
	fw := newFW()
	e, _ := engine(fw, "", secproto.BlockWatch, true)
	failN(e, "203.0.113.7", 6, t0)
	s := e.Snapshot()
	if fw.adds != 0 || len(s.Active) != 0 || len(s.Would) != 1 || s.Would[0].IP != "203.0.113.7" {
		t.Errorf("watch: adds %d, %+v", fw.adds, s)
	}
	if s.Mode != secproto.BlockWatch {
		t.Errorf("mode %q", s.Mode)
	}
}

func TestWithoutThePermissionBlockModeFallsBackToWatch(t *testing.T) {
	fw := newFW()
	e, _ := engine(fw, "", secproto.BlockOn, false)
	failN(e, "203.0.113.8", 6, t0)
	if fw.adds != 0 || e.Snapshot().Mode != secproto.BlockWatch {
		t.Errorf("a machine not installed with -allow-block must not block: adds %d, mode %s", fw.adds, e.Snapshot().Mode)
	}
}

func TestNeverBlocksWhatItMustNot(t *testing.T) {
	fw := newFW()
	c := cfg(secproto.BlockOn)
	c.Whitelist = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	e := New(fw, "", c, true)
	e.now = func() time.Time { return t0 }
	for _, ip := range []string{"10.1.2.3", "192.168.0.9", "127.0.0.1", "169.254.1.1", "fe80::1", "198.51.100.77", "::"} {
		failN(e, ip, 20, t0)
	}
	// Somebody who signed in is left alone, even if they then mistype a lot.
	e.OK("203.0.113.9", t0.Add(-time.Hour))
	failN(e, "203.0.113.9", 20, t0)
	if len(fw.rules) != 0 {
		t.Errorf("blocked what is private, local, whitelisted or a known user: %v", fw.rules)
	}
}

func TestASuccessfulSignInProtectsOnlyForADay(t *testing.T) {
	fw := newFW()
	e, now := engine(fw, "", secproto.BlockOn, true)
	e.OK("203.0.113.10", t0)
	*now = t0.Add(25 * time.Hour)
	e.Tick(ctx)
	failN(e, "203.0.113.10", 5, *now)
	if !fw.rules[netip.MustParseAddr("203.0.113.10")] {
		t.Error("a day later the protection is over")
	}
}

func TestABlockEndsWhenItsTimeIsUp(t *testing.T) {
	fw := newFW()
	e, now := engine(fw, "", secproto.BlockOn, true)
	failN(e, "203.0.113.11", 5, t0)
	*now = t0.Add(23 * time.Hour)
	e.Tick(ctx)
	if len(fw.rules) != 1 {
		t.Fatal("still blocked after 23 hours")
	}
	*now = t0.Add(25 * time.Hour)
	e.Tick(ctx)
	if len(fw.rules) != 0 || len(e.Snapshot().Active) != 0 {
		t.Errorf("must be lifted after 24 hours: %v", fw.rules)
	}
}

func TestZeroHoursMeansForGood(t *testing.T) {
	fw := newFW()
	c := cfg(secproto.BlockOn)
	c.TTL = 0
	e := New(fw, "", c, true)
	e.now = func() time.Time { return t0 }
	failN(e, "203.0.113.12", 5, t0)
	e.now = func() time.Time { return t0.Add(400 * 24 * time.Hour) }
	e.Tick(ctx)
	if len(fw.rules) != 1 || e.Snapshot().Active[0].Until != nil {
		t.Error("a block with no end stays")
	}
}

func TestUnblockByHandLeavesTheAddressAloneForADay(t *testing.T) {
	fw := newFW()
	e, _ := engine(fw, "", secproto.BlockOn, true)
	failN(e, "203.0.113.13", 5, t0)
	if !e.Unblock(ctx, "203.0.113.13") || len(fw.rules) != 0 {
		t.Fatal("unblock must remove the rule")
	}
	failN(e, "203.0.113.13", 20, t0.Add(time.Minute))
	if len(fw.rules) != 0 {
		t.Error("the same address must not be blocked again right after somebody lifted it")
	}
	if e.Unblock(ctx, "203.0.113.99") {
		t.Error("an address that was never blocked cannot be unblocked")
	}
}

func TestTurningBlockingOffLiftsWhatWasBlocked(t *testing.T) {
	fw := newFW()
	e, _ := engine(fw, "", secproto.BlockOn, true)
	failN(e, "203.0.113.14", 5, t0)
	c := e.Config()
	c.Mode = secproto.BlockWatch
	e.SetConfig(ctx, c)
	if len(fw.rules) != 0 || len(e.Snapshot().Active) != 0 {
		t.Errorf("leaving block mode must lift the blocks: %v", fw.rules)
	}
}

func TestAFirewallThatRefusesIsReportedAndNothingIsClaimed(t *testing.T) {
	fw := newFW()
	fw.failAdd = true
	e, _ := engine(fw, "", secproto.BlockOn, true)
	failN(e, "203.0.113.15", 5, t0)
	s := e.Snapshot()
	if len(s.Active) != 0 || s.Error == "" {
		t.Errorf("must not claim a block that was not made: %+v", s)
	}
}

func TestStateAndSettingsSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ipblock.json")
	fw := newFW()
	c := cfg(secproto.BlockOn)
	c.Threshold, c.Whitelist = 3, []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	e := New(fw, path, c, true)
	e.now = func() time.Time { return t0 }
	e.SetConfig(ctx, c)
	failN(e, "203.0.113.16", 3, t0)

	again := New(fw, path, DefaultConfig(), true) // a restart starts from the defaults, and what was saved wins
	again.now = func() time.Time { return t0.Add(time.Hour) }
	s := again.Snapshot()
	if s.Mode != secproto.BlockOn || s.Threshold != 3 || len(s.Active) != 1 || s.Active[0].IP != "203.0.113.16" {
		t.Errorf("after a restart: %+v", s)
	}
	if len(again.Config().Whitelist) != 1 {
		t.Error("the whitelist must survive")
	}
}

func TestAfterARestartTheFirewallIsMatchedWithTheState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ipblock.json")
	fw := newFW()
	e, _ := engine(fw, path, secproto.BlockOn, true)
	failN(e, "203.0.113.17", 5, t0)
	delete(fw.rules, netip.MustParseAddr("203.0.113.17")) // the rule went missing
	fw.rules[netip.MustParseAddr("203.0.113.18")] = true  // a rule nobody remembers

	again := New(fw, path, DefaultConfig(), true)
	again.now = func() time.Time { return t0.Add(time.Minute) }
	again.Tick(ctx)
	if !fw.rules[netip.MustParseAddr("203.0.113.17")] {
		t.Error("a missing rule must be made again")
	}
	if fw.rules[netip.MustParseAddr("203.0.113.18")] {
		t.Error("a leftover rule of ours that the state does not know must go")
	}
}

func TestWindowAndLimitsAreHeldToSaneValues(t *testing.T) {
	c := Config{Mode: "weird", Threshold: 0, Window: 0, TTL: -1}.normalised(true)
	if c.Mode != secproto.BlockWatch || c.Threshold != 2 || c.Window != time.Minute || c.TTL != 0 {
		t.Errorf("%+v", c)
	}
	c = Config{Mode: secproto.BlockOn, Threshold: 99999, Window: 1000 * time.Hour, TTL: 1000 * 24 * time.Hour}.normalised(true)
	if c.Threshold != 1000 || c.Window != 24*time.Hour || c.TTL != 365*24*time.Hour {
		t.Errorf("%+v", c)
	}
}

func TestASharedBlockIsMadeOnlyInBlockModeAndNeverOnWhatIsProtected(t *testing.T) {
	fw := newFW()
	e, _ := engine(fw, "", secproto.BlockOn, true)
	if !e.AddShared(ctx, "203.0.113.50", 2*time.Hour) || !fw.rules[netip.MustParseAddr("203.0.113.50")] {
		t.Fatal("a block that another machine made must be made here too")
	}
	s := e.Snapshot()
	if len(s.Active) != 1 || !s.Active[0].Shared || s.Total != 0 || s.Active[0].Until == nil {
		t.Errorf("a shared block is marked, is not counted as made here, and ends: %+v", s)
	}
	if e.AddShared(ctx, "203.0.113.50", time.Hour) {
		t.Error("an address already blocked is not blocked twice")
	}
	e.OK("203.0.113.51", t0)
	for _, ip := range []string{"10.0.0.5", "203.0.113.51", "127.0.0.1"} {
		if e.AddShared(ctx, ip, time.Hour) {
			t.Errorf("must not block %s: private, or somebody who signed in", ip)
		}
	}
	// This machine's own limit is the longest a block may last.
	e.AddShared(ctx, "203.0.113.52", 500*time.Hour)
	for _, a := range e.Snapshot().Active {
		if a.IP == "203.0.113.52" && a.Until.Sub(a.Since) > 24*time.Hour+time.Second {
			t.Errorf("a shared block outlasts the local limit: %v", a.Until.Sub(a.Since))
		}
	}

	watch, _ := engine(newFW(), "", secproto.BlockWatch, true)
	if watch.AddShared(ctx, "203.0.113.53", time.Hour) {
		t.Error("a machine that only watches must not block")
	}
}
