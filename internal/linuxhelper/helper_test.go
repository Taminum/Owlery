package linuxhelper

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Taminum/Owlery/internal/seccollect"
	"github.com/Taminum/Owlery/internal/secproto"
)

type fake struct{ calls [][]string }

const units = `nginx.service                loaded active   running A high performance web server
ssh.service                  loaded active   running OpenBSD Secure Shell server
remnawave-node.service       loaded failed   failed  Remnawave node
remnascope-secagent.service  loaded active   running Owlery agent
ghost.service                not-found inactive dead  ghost.service
`

func (f *fake) Run(_ context.Context, _ string, args ...string) seccollect.Result {
	f.calls = append(f.calls, args)
	switch args[0] {
	case "list-units":
		return seccollect.Result{Stdout: units}
	case "list-unit-files":
		return seccollect.Result{Stdout: "nginx.service enabled enabled\nssh.service enabled enabled\nremnawave-node.service disabled enabled\n"}
	case "is-active":
		return seccollect.Result{Stdout: "active\n"}
	case "-u":
		return seccollect.Result{Stdout: "2026-11-13T00:00:01+0500 host nginx[1]: started\n"}
	}
	return seccollect.Result{}
}

func (f *fake) ran(verb string) bool {
	for _, c := range f.calls {
		if c[0] == verb {
			return true
		}
	}
	return false
}

func TestListShowsEveryServiceAndMarksOnlyTheOwnersListAsManageable(t *testing.T) {
	f := &fake{}
	s := &Server{Runner: f, Units: []string{"nginx", "remnawave-node.service", "remnascope-secagent"}}
	rs := s.Handle(context.Background(), Request{Op: secproto.LinuxList})
	if !rs.OK || len(rs.Units) != 5 {
		t.Fatalf("%+v", rs)
	}
	m := map[string]secproto.LinuxUnit{}
	for _, u := range rs.Units {
		m[u.Name] = u
	}
	if !m["nginx.service"].Manage || !m["remnawave-node.service"].Manage {
		t.Errorf("listed units must be manageable: %+v", m)
	}
	if m["ssh.service"].Manage {
		t.Error("a unit that was not listed must be read only")
	}
	if m["remnascope-secagent.service"].Manage {
		t.Error("the agent's own unit must never be controlled from the panel")
	}
	if m["nginx.service"].Enabled != "enabled" || m["remnawave-node.service"].Enabled != "disabled" || m["remnawave-node.service"].Active != "failed" {
		t.Errorf("states: %+v", m)
	}
}

func TestControlNeedsTheListAnExistingUnitAndRunsExactArguments(t *testing.T) {
	f := &fake{}
	s := &Server{Runner: f, Systemctl: "systemctl", Units: []string{"nginx"}}
	ctx := context.Background()
	for _, bad := range []string{"", "-x.service", "a b.service", "nginx", "x;rm.service", "../x.service", strings.Repeat("a", 300) + ".service"} {
		if rs := s.Handle(ctx, Request{Op: secproto.LinuxRestart, Name: bad}); rs.OK || rs.Code != CodeBadRequest {
			t.Errorf("%q: %+v", bad, rs)
		}
	}
	if rs := s.Handle(ctx, Request{Op: secproto.LinuxRestart, Name: "ghost.service"}); rs.Code != CodeNoSuch {
		t.Errorf("a unit that is not there: %+v", rs)
	}
	if rs := s.Handle(ctx, Request{Op: secproto.LinuxStop, Name: "ssh.service"}); rs.Code != CodeNotAllowed {
		t.Errorf("a unit that is not on the list: %+v", rs)
	}
	if f.ran("stop") || f.ran("restart") {
		t.Fatalf("nothing may run for those: %v", f.calls)
	}
	rs := s.Handle(ctx, Request{Op: secproto.LinuxRestart, Name: "nginx.service"})
	if !rs.OK || rs.Active != "active" {
		t.Fatalf("%+v", rs)
	}
	var got string
	for _, c := range f.calls {
		if c[0] == "restart" {
			got = strings.Join(c, " ")
		}
	}
	if got != "restart nginx.service" {
		t.Fatalf("the restart must be exactly this: %q", got)
	}
	if rs := s.Handle(ctx, Request{Op: "exec", Name: "nginx.service"}); rs.Code != CodeBadRequest {
		t.Errorf("an unknown operation: %+v", rs)
	}
}

func TestJournalIsOpenForAnyExistingService(t *testing.T) {
	f := &fake{}
	s := &Server{Runner: f, Journalctl: "journalctl"}
	rs := s.Handle(context.Background(), Request{Op: secproto.LinuxJournal, Name: "ssh.service", Tail: 99999})
	if !rs.OK || !strings.Contains(rs.Text, "started") {
		t.Fatalf("%+v", rs)
	}
	var got string
	for _, c := range f.calls {
		if c[0] == "-u" {
			got = strings.Join(c, " ")
		}
	}
	if got != "-u ssh.service -n 2000 --no-pager -o short-iso" {
		t.Fatalf("%q", got)
	}
}

func put(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFilesStayInsideTheAllowedFoldersAndSecretsAreHidden(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "log")
	other := filepath.Join(root, "home")
	put(t, filepath.Join(logs, "nginx", "error.log"), "one\ntwo\nthree\n")
	put(t, filepath.Join(logs, "app.env"), "SECRET=1")
	put(t, filepath.Join(logs, "server.key"), "KEY")
	put(t, filepath.Join(logs, "private", "a.log"), "hidden")
	put(t, filepath.Join(other, "notes.txt"), "not allowed")
	put(t, filepath.Join(logs, "bin.dat"), "ab\x00cd")
	put(t, filepath.Join(logs, "color.log"), "\x1b[31mred\x1b[0m ok\r\n")
	s := &Server{Dirs: []string{logs, filepath.Join(root, "missing"), "relative/dir", "/"}}

	if rs := s.Handle(context.Background(), Request{Op: secproto.LinuxLs}); !rs.OK || len(rs.Dirs) != 1 {
		t.Fatalf("only the usable folders are offered: %+v", rs)
	}
	rs := s.Handle(context.Background(), Request{Op: secproto.LinuxLs, Path: logs})
	if !rs.OK {
		t.Fatalf("%+v", rs)
	}
	var names []string
	for _, e := range rs.Entries {
		names = append(names, e.Name)
	}
	if got := strings.Join(names, ","); got != "nginx,bin.dat,color.log" {
		t.Errorf("secrets must not be listed, and folders come first: %s", got)
	}
	cat := func(p string, tail int) Response {
		return s.Handle(context.Background(), Request{Op: secproto.LinuxCat, Path: p, Tail: tail})
	}
	if rs := cat(filepath.Join(logs, "nginx", "error.log"), 2); !rs.OK || rs.Text != "two\nthree\n" || !rs.Truncated {
		t.Errorf("tail: %+v", rs)
	}
	if rs := cat(filepath.Join(other, "notes.txt"), 0); rs.Code != CodeNotAllowed {
		t.Errorf("outside the folders: %+v", rs)
	}
	if rs := cat(filepath.Join(logs, "nginx", "..", "..", "home", "notes.txt"), 0); rs.Code != CodeNotAllowed {
		t.Errorf("a way out through ..: %+v", rs)
	}
	for _, p := range []string{filepath.Join(logs, "app.env"), filepath.Join(logs, "server.key"), filepath.Join(logs, "private", "a.log")} {
		if rs := cat(p, 0); rs.OK || rs.Code != CodeNotAllowed {
			t.Errorf("%s must not be read: %+v", p, rs)
		}
	}
	if rs := cat(filepath.Join(logs, "bin.dat"), 0); rs.Code != CodeBinary {
		t.Errorf("binary: %+v", rs)
	}
	if rs := cat(filepath.Join(logs, "color.log"), 0); !rs.OK || rs.Text != "red ok\n" {
		t.Errorf("colour codes and carriage returns are cleaned: %q", rs.Text)
	}
	if rs := cat("relative.txt", 0); rs.Code != CodeBadRequest {
		t.Errorf("relative: %+v", rs)
	}
	if rs := cat(logs, 0); rs.Code != CodeNotFile {
		t.Errorf("a folder: %+v", rs)
	}
	if rs := cat(filepath.Join(logs, "nope.log"), 0); rs.Code != CodeNoSuch {
		t.Errorf("missing: %+v", rs)
	}
}

func TestALinkCannotLeadOutOfTheAllowedFolders(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "log")
	put(t, filepath.Join(root, "home", "notes.txt"), "outside")
	put(t, filepath.Join(logs, "ok.log"), "inside")
	if err := os.Symlink(filepath.Join(root, "home", "notes.txt"), filepath.Join(logs, "out.log")); err != nil {
		t.Skip("symbolic links are not available here:", err)
	}
	s := &Server{Dirs: []string{logs}}
	if rs := s.Handle(context.Background(), Request{Op: secproto.LinuxCat, Path: filepath.Join(logs, "out.log")}); rs.OK || rs.Code != CodeNotAllowed {
		t.Fatalf("a link out must not be followed: %+v", rs)
	}
	rs := s.Handle(context.Background(), Request{Op: secproto.LinuxLs, Path: logs})
	for _, e := range rs.Entries {
		if e.Name == "out.log" {
			t.Error("a link that leads out must not be listed")
		}
	}
}

func TestBigFilesGiveTheirEnd(t *testing.T) {
	root := t.TempDir()
	body := "first line\n" + strings.Repeat("x", secproto.MaxLinuxText) + "\nlast line\n"
	put(t, filepath.Join(root, "big.log"), body)
	s := &Server{Dirs: []string{root}}
	rs := s.Handle(context.Background(), Request{Op: secproto.LinuxCat, Path: filepath.Join(root, "big.log")})
	if !rs.OK || !rs.Truncated || !strings.HasSuffix(rs.Text, "last line\n") || strings.Contains(rs.Text, "first line") || len(rs.Text) > secproto.MaxLinuxText {
		t.Fatalf("%v %v %d", rs.OK, rs.Truncated, len(rs.Text))
	}
}
