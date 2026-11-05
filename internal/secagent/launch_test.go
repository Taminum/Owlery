package secagent

import (
	"context"
	"encoding/json"
	"runtime"
	"testing"

	"github.com/Taminum/Owlery/internal/secproto"
)

func TestAConsoleOnTheScreenIsAnAuditedWriteAndNeedsAShell(t *testing.T) {
	if !secproto.AdminWrites[secproto.AdminLaunch] || secproto.AdminReads[secproto.AdminLaunch] {
		t.Fatal("opening a console changes what is on the machine: it must be written to the audit log")
	}
	// Management is allowed but a shell is not: no console.
	a := &agent{cfg: Config{AllowAdmin: true, AllowShell: false}, admins: make(chan struct{}, 2)}
	res := a.admin(context.Background(), secproto.AdminReq{ID: "1", Op: secproto.AdminLaunch, Args: json.RawMessage(`{"shell":"cmd"}`)})
	if res.OK || res.Error == "" {
		t.Errorf("a machine without a shell must refuse: %+v", res)
	}
	// Management is not allowed at all: refused before anything else.
	a = &agent{cfg: Config{AllowShell: true}, admins: make(chan struct{}, 2)}
	if res := a.admin(context.Background(), secproto.AdminReq{ID: "2", Op: secproto.AdminLaunch}); res.OK {
		t.Errorf("a machine without management must refuse: %+v", res)
	}
}

func TestOnlyTwoShellsCanBeOpenedAndNothingElse(t *testing.T) {
	for _, bad := range []string{`{"shell":"cmd.exe /c calc"}`, `{"shell":""}`, `{"shell":"powershell -enc AAAA"}`, `not json`, `{"shell":"bash"}`} {
		if err := launchConsole(json.RawMessage(bad)); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
	if runtime.GOOS != "windows" {
		if err := launchConsole(json.RawMessage(`{"shell":"cmd"}`)); err == nil {
			t.Error("there is no desktop to put a window on here")
		}
	}
}
