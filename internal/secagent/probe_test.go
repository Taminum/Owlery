package secagent

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/Taminum/RemnaScope/internal/secprobe"
	"github.com/Taminum/RemnaScope/internal/secproto"
)

func TestProbeRefusesWhatItShouldNotRun(t *testing.T) {
	a := &agent{}
	long := strings.Repeat("a", 300)
	for name, p := range map[string]secproto.Probe{
		"unknown kind":  {Type: "probe", ID: "1", Kind: "udp", Host: "203.0.113.5", Port: 53},
		"port zero":     {Type: "probe", ID: "1", Kind: "tcp", Host: "203.0.113.5", Port: 0},
		"port too big":  {Type: "probe", ID: "1", Kind: "tcp", Host: "203.0.113.5", Port: 70000},
		"empty host":    {Type: "probe", ID: "1", Kind: "tcp", Host: "", Port: 80},
		"host with url": {Type: "probe", ID: "1", Kind: "tcp", Host: "evil.example/../x", Port: 80},
		"long host":     {Type: "probe", ID: "1", Kind: "tcp", Host: long, Port: 80},
		"tcp with sni":  {Type: "probe", ID: "1", Kind: "tcp", Host: "203.0.113.5", Port: 80, SNI: "x.example"},
		"no id":         {Type: "probe", ID: "", Kind: "tcp", Host: "203.0.113.5", Port: 80},
	} {
		if r := a.probe(context.Background(), p, false); r.Refused != "bad_request" || r.Result != "" {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// A request that is fine is still refused when the agent is already at its limit.
	if r := a.probe(context.Background(), secproto.Probe{Type: "probe", ID: "1", Kind: "tcp", Host: "203.0.113.5", Port: 80}, true); r.Refused != "busy" {
		t.Errorf("%+v", r)
	}
}

func TestProbeNeverDialsAPrivateAddressWhateverTheServerAsks(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	a := &agent{}
	r := a.probe(context.Background(), secproto.Probe{Type: "probe", ID: "1", Kind: "tcp", Host: "127.0.0.1", Port: port}, false)
	if r.Refused != "" || r.Result != "error" || r.Error != "blocked_address" {
		t.Fatalf("a loopback target must be blocked on the agent itself: %+v", r)
	}

	// With the rule relaxed (as only a test may), the same probe does connect.
	old := secprobe.AllowAddr
	secprobe.AllowAddr = func(x netip.Addr) bool { return x.IsLoopback() }
	defer func() { secprobe.AllowAddr = old }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	r = a.probe(context.Background(), secproto.Probe{Type: "probe", ID: "2", Kind: "tcp", Host: "127.0.0.1", Port: port}, false)
	if r.Result != "reachable" || r.IP != "127.0.0.1" || r.ID != "2" || r.Kind != "tcp" {
		t.Fatalf("%+v", r)
	}
}
