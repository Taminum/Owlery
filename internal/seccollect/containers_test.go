package seccollect

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

func TestContainerPortsNameTheDockerProxyListeners(t *testing.T) {
	file := filepath.Join(t.TempDir(), "containers.tsv")
	list := "0123456789ab\tkomodo\t9120,8081\nba9876543210\tkarakeep\t\nshort\tbad name\t80\n"
	if err := os.WriteFile(file, []byte(list), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ContainerPorts(file)
	if len(got) != 2 || got[9120] != "komodo" || got[8081] != "komodo" {
		t.Fatalf("%v", got)
	}
	if len(ContainerPorts("")) != 0 || len(ContainerPorts(filepath.Join(t.TempDir(), "none"))) != 0 {
		t.Fatal("a missing list is empty")
	}
	w := NewSocketWatch(0)
	w.Containers = func() map[int]string { return got }
	r := fake{"ss -H -tulnp": {Stdout: "tcp LISTEN 0 4096 0.0.0.0:9120 0.0.0.0:* users:((\"docker-proxy\",pid=1,fd=4))\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=2,fd=3))\n"}}
	snap := w.Collect(context.Background(), r, "ss", time.Now())
	l := snap.Data.(secproto.Sockets).Listeners
	if len(l) != 2 {
		t.Fatalf("%+v", l)
	}
	for _, x := range l {
		if (x.Port == 9120) != (x.Container == "komodo") {
			t.Errorf("%+v", x)
		}
	}
}
