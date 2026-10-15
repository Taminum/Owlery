package secagent

import (
	"context"
	"errors"
	"testing"

	"github.com/Taminum/RemnaScope/internal/seccollect"
)

type listing struct{ out, err string }

func (l *listing) Run(_ context.Context, _ string, args ...string) seccollect.Result {
	if len(args) != 1 || args[0] != "banned" {
		return seccollect.Result{ExitCode: 1}
	}
	if l.err != "" {
		return seccollect.Result{Err: errors.New(l.err), ExitCode: 1}
	}
	return seccollect.Result{Stdout: l.out}
}

func TestBanWatchSeesAMoveAndIgnoresReordering(t *testing.T) {
	l := &listing{out: "[{'sshd': ['203.0.113.5', '203.0.113.6']}]"}
	var w banWatch
	ctx := context.Background()
	if w.changed(ctx, l, "f2b") {
		t.Fatal("the first listing is the baseline, not a change")
	}
	l.out = "[{'sshd': ['203.0.113.6', '203.0.113.5']}]" // same set, other order
	if w.changed(ctx, l, "f2b") {
		t.Fatal("a reordered listing is not a change")
	}
	l.out = "[{'sshd': ['203.0.113.5', '203.0.113.6', '198.51.100.9']}]"
	if !w.changed(ctx, l, "f2b") {
		t.Fatal("a new ban was not noticed")
	}
	if w.changed(ctx, l, "f2b") {
		t.Fatal("a change was reported twice")
	}
	l.out = "[{'sshd': []}]"
	if !w.changed(ctx, l, "f2b") {
		t.Fatal("the unbans were not noticed")
	}
}

func TestBanWatchSwitchesItselfOffWhereTheListingDoesNotExist(t *testing.T) {
	l := &listing{err: "unknown command"}
	var w banWatch
	if w.changed(context.Background(), l, "f2b") || !w.off {
		t.Fatal("a Fail2ban without the listing must turn the watch off, not report changes")
	}
	l.err, l.out = "", "[{'sshd': ['1.2.3.4']}]"
	if w.changed(context.Background(), l, "f2b") {
		t.Fatal("an off watch reported a change")
	}
}
