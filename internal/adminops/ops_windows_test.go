//go:build windows

package adminops

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

func do(t *testing.T, op string, args any) (json.RawMessage, error) {
	t.Helper()
	var raw json.RawMessage
	if args != nil {
		raw, _ = json.Marshal(args)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	return Do(ctx, op, raw)
}

func TestReadsReturnSomething(t *testing.T) {
	for _, op := range []string{secproto.AdminProcs, secproto.AdminServices, secproto.AdminStartup, secproto.AdminConns} {
		b, err := do(t, op, nil)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if op != secproto.AdminStartup && !strings.HasPrefix(string(b), "[{") {
			t.Fatalf("%s: %.80s", op, b)
		}
	}
	if _, err := do(t, secproto.AdminSessions, nil); err != nil {
		t.Fatalf("sessions: %v", err)
	}
	b, err := do(t, secproto.AdminEvents, map[string]any{"log": "System", "level": 3, "limit": 5})
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	var evs []eventInfo
	if json.Unmarshal(b, &evs) != nil || len(evs) > 5 {
		t.Fatalf("%.200s", b)
	}
}

func TestOwnProcessIsInTheList(t *testing.T) {
	b, err := do(t, secproto.AdminProcs, nil)
	if err != nil {
		t.Fatal(err)
	}
	var ps []procInfo
	if err := json.Unmarshal(b, &ps); err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		if int(p.PID) == os.Getpid() {
			return
		}
	}
	t.Fatal("the test's own process is not listed")
}

func TestDangerousRequestsAreRefused(t *testing.T) {
	for _, pid := range []int{0, 4, os.Getpid()} {
		if _, err := do(t, secproto.AdminProcKill, map[string]any{"pid": pid}); err == nil {
			t.Fatalf("killing pid %d was allowed", pid)
		}
	}
	// The agent's own service cannot be stopped or disabled from the page.
	for _, op := range []string{secproto.AdminSvcStop, secproto.AdminSvcRestart} {
		if _, err := do(t, op, map[string]any{"name": "OwlerySecAgent"}); err == nil || !strings.Contains(err.Error(), "агент") {
			t.Fatalf("%s: %v", op, err)
		}
	}
	if _, err := do(t, secproto.AdminSvcStartup, map[string]any{"name": "OwlerySecAgent", "start": "disabled"}); err == nil {
		t.Fatal("disabling the agent's service was allowed")
	}
	if _, err := do(t, secproto.AdminSvcStartup, map[string]any{"name": "Spooler", "start": "bogus"}); err == nil {
		t.Fatal("a bogus start type was accepted")
	}
	// Only entries the list could have shown may be removed.
	if _, err := do(t, secproto.AdminStartupRemove, map[string]any{"kind": "reg", "where": `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "name": "Shell"}); err == nil {
		t.Fatal("a value outside the Run keys was deletable")
	}
	if _, err := do(t, secproto.AdminStartupRemove, map[string]any{"kind": "file", "where": `C:\Windows\System32`, "name": "cmd.exe"}); err == nil {
		t.Fatal("a file outside the Startup folders was deletable")
	}
	if _, err := do(t, secproto.AdminEvents, map[string]any{"log": "System\" /q:*", "level": 3}); err == nil {
		t.Fatal("an arbitrary log name was accepted")
	}
}
