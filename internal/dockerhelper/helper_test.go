package dockerhelper

import (
	"context"
	"strings"
	"testing"

	"github.com/Taminum/Owlery/internal/seccollect"
)

type fake struct {
	calls [][]string
	logs  string
}

func (f *fake) Run(_ context.Context, _ string, args ...string) seccollect.Result {
	f.calls = append(f.calls, args)
	switch args[0] {
	case "ps":
		return seccollect.Result{Stdout: "remnascope-api\nremnascope-db\n"}
	case "logs":
		return seccollect.Result{Stdout: f.logs}
	case "inspect":
		return seccollect.Result{Stdout: "true\n"}
	}
	return seccollect.Result{}
}

func TestOnlyKnownContainersAndFixedArguments(t *testing.T) {
	f := &fake{logs: "line\n"}
	s := &Server{Runner: f, Bin: "docker"}
	ctx := context.Background()
	for _, bad := range []string{"", "-v", "a b", "a;rm -rf /", "../x", strings.Repeat("a", 200)} {
		if rs := s.Handle(ctx, Request{Op: OpRestart, Name: bad}); rs.OK || rs.Code != CodeBadRequest {
			t.Errorf("%q: %+v", bad, rs)
		}
	}
	if rs := s.Handle(ctx, Request{Op: "exec", Name: "remnascope-api"}); rs.Code != CodeBadRequest {
		t.Errorf("an unknown operation: %+v", rs)
	}
	if rs := s.Handle(ctx, Request{Op: OpRestart, Name: "ghost"}); rs.Code != CodeNoSuch {
		t.Errorf("a container that is not there: %+v", rs)
	}
	for _, c := range f.calls {
		if c[0] == "restart" || c[0] == "logs" {
			t.Fatalf("nothing may run for a bad name: %v", c)
		}
	}
	rs := s.Handle(ctx, Request{Op: OpRestart, Name: "remnascope-api"})
	if !rs.OK || !rs.Running {
		t.Fatalf("%+v", rs)
	}
	last := f.calls[len(f.calls)-2]
	if strings.Join(last, " ") != "restart --time 20 remnascope-api" {
		t.Fatalf("the restart must be exactly this: %v", last)
	}
}

func TestLogsAreBoundedAndDenyListStopsOnlyRestarts(t *testing.T) {
	f := &fake{logs: strings.Repeat("x", 100) + "\n" + strings.Repeat("y", MaxLog)}
	s := &Server{Runner: f, Bin: "docker", Deny: []string{"remnascope-db"}}
	ctx := context.Background()
	rs := s.Handle(ctx, Request{Op: OpLogs, Name: "remnascope-db", Tail: 99999})
	if !rs.OK || !rs.Truncated || len(rs.Log) > MaxLog {
		t.Fatalf("%v %v %d", rs.OK, rs.Truncated, len(rs.Log))
	}
	if got := strings.Join(f.calls[len(f.calls)-1], " "); got != "logs --tail 1000 --timestamps remnascope-db" {
		t.Fatalf("the tail is capped: %s", got)
	}
	if rs := s.Handle(ctx, Request{Op: OpRestart, Name: "remnascope-db"}); rs.Code != CodeNotAllowed {
		t.Fatalf("%+v", rs)
	}
}
