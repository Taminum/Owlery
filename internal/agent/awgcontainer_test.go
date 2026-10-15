package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/Taminum/RemnaScope/internal/ingestproto"
)

func TestContainerCommandsAreRefusedUnlessTheHostOptedInAndAreCheckedAgain(t *testing.T) {
	var ran [][]string
	l := &AWGLink{RunCmd: func(_ context.Context, argv []string) ([]byte, error) {
		ran = append(ran, argv)
		if argv[3] == "install" {
			return []byte("RESULT\tok\tamnezia-awg3\t" + strings.Repeat("A", 43) + "=\t55555\n"), nil
		}
		return []byte("RESULT\tok\tamnezia-awg3\n"), nil
	}}
	good := ingestproto.AWGOp{Op: "install", Container: "amnezia-awg3", Port: 55555, Subnet: "10.9.1.0/24"}

	// Not opted in: refused, nothing runs.
	if r := l.runOp(context.Background(), good); r.Code != "container_admin_off" || len(ran) != 0 {
		t.Fatalf("%+v %v", r, ran)
	}
	l.ContainerArgv = []string{"/usr/bin/sudo", "-n", "/usr/local/sbin/remnascope-awg-container"}
	for name, op := range map[string]ingestproto.AWGOp{
		"container": {Op: "install", Container: "nginx", Port: 55555, Subnet: "10.9.1.0/24"},
		"injection": {Op: "install", Container: "amnezia-awg3;id", Port: 55555, Subnet: "10.9.1.0/24"},
		"port":      {Op: "install", Container: "amnezia-awg3", Port: 22, Subnet: "10.9.1.0/24"},
		"subnet":    {Op: "install", Container: "amnezia-awg3", Port: 55555, Subnet: "10.9.300.0/24"},
		"private":   {Op: "install", Container: "amnezia-awg3", Port: 55555, Subnet: "192.168.1.0/24"},
		"confirm":   {Op: "remove", Container: "amnezia-awg3", Confirm: "yes"},
	} {
		if r := l.runOp(context.Background(), op); r.Status != "error" || len(ran) != 0 {
			t.Errorf("%s was not refused: %+v %v", name, r, ran)
		}
	}
	r := l.runOp(context.Background(), good)
	if r.Status != "ok" || r.Port != 55555 || r.Key == "" || len(ran) != 1 {
		t.Fatalf("%+v %v", r, ran)
	}
	want := []string{"/usr/bin/sudo", "-n", "/usr/local/sbin/remnascope-awg-container", "install", "amnezia-awg3", "55555", "10.9.1.0/24"}
	if strings.Join(ran[0], " ") != strings.Join(want, " ") {
		t.Fatalf("argv: %v", ran[0])
	}
	r = l.runOp(context.Background(), ingestproto.AWGOp{Op: "remove", Container: "amnezia-awg3", Confirm: "yes-delete-all-devices"})
	if r.Status != "ok" || len(ran) != 2 || ran[1][3] != "remove" {
		t.Fatalf("%+v %v", r, ran)
	}
}

func TestExportAndRestoreCarryOnlyKnownFilesAndAreRefusedWithoutOptIn(t *testing.T) {
	conf := "W0ludGVyZmFjZV0K" // "[Interface]\n"
	var gotStdin []byte
	l := &AWGLink{RunCmdIn: func(_ context.Context, argv []string, stdin []byte) ([]byte, error) {
		gotStdin = stdin
		if argv[3] == "export" {
			return []byte("RESULT\tok\tamnezia-awg2\nFILE\tawg0.conf\t" + conf + "\nFILE\tclientsTable\t" + conf + "\n"), nil
		}
		return []byte("RESULT\tok\tamnezia-awg2\t" + strings.Repeat("A", 43) + "=\t55424\n"), nil
	}}
	exp := ingestproto.AWGOp{Op: "export", Container: "amnezia-awg2"}
	if r := l.runOp(context.Background(), exp); r.Code != "container_admin_off" {
		t.Fatalf("an export was run without the opt-in: %+v", r)
	}
	l.ContainerArgv = []string{"/usr/bin/sudo", "-n", "/usr/local/sbin/remnascope-awg-container"}
	r := l.runOp(context.Background(), exp)
	if r.Status != "ok" || len(r.Files) != 2 || r.Files[0].Name != "awg0.conf" {
		t.Fatalf("%+v", r)
	}

	files := []ingestproto.AWGFile{{Name: "awg0.conf", Data: conf}, {Name: "wireguard_psk.key", Data: conf}}
	r = l.runOp(context.Background(), ingestproto.AWGOp{Op: "restore", Container: "amnezia-awg2", Files: files})
	if r.Status != "ok" || r.Port != 55424 || !strings.HasPrefix(string(gotStdin), "FILE\tawg0.conf\t") {
		t.Fatalf("%+v %q", r, gotStdin)
	}
	for name, bad := range map[string][]ingestproto.AWGFile{
		"unknown file": {{Name: "awg0.conf", Data: conf}, {Name: "../etc/passwd", Data: conf}},
		"not base64":   {{Name: "awg0.conf", Data: "x; rm -rf /"}},
		"no config":    {{Name: "clientsTable", Data: conf}},
		"duplicate":    {{Name: "awg0.conf", Data: conf}, {Name: "awg0.conf", Data: conf}},
	} {
		if r := l.runOp(context.Background(), ingestproto.AWGOp{Op: "restore", Container: "amnezia-awg2", Files: bad}); r.Status != "error" {
			t.Errorf("%s was accepted: %+v", name, r)
		}
	}
	// A helper that prints a file the backup does not know is not believed.
	l.RunCmdIn = func(context.Context, []string, []byte) ([]byte, error) {
		return []byte("RESULT\tok\tamnezia-awg2\nFILE\tawg0.conf\t" + conf + "\nFILE\t/etc/shadow\t" + conf + "\n"), nil
	}
	if r := l.runOp(context.Background(), exp); r.Status != "error" {
		t.Fatalf("%+v", r)
	}
}
