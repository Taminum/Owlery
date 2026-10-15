package httpapi

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/secagent"
	"github.com/Taminum/RemnaScope/internal/seccollect"
	"github.com/Taminum/RemnaScope/internal/secprobe"
	"github.com/Taminum/RemnaScope/internal/secproto"
)

func TestAnAgentSetUpAsACheckerAnswersProbesOverItsConnection(t *testing.T) {
	// The agent refuses private addresses on its own; the test server is on loopback, so relax that here only.
	old := secprobe.AllowAddr
	secprobe.AllowAddr = func(a netip.Addr) bool { return a.IsLoopback() }
	t.Cleanup(func() { secprobe.AllowAddr = old })

	w := newAgentWorld(t)
	v := mkVPS(t, w, "Exit", "203.0.113.20", "")
	_, ab := w.owner.do("POST", "/api/v1/security/vps/"+v+"/agent", nil)
	token := parse[struct {
		Token string `json:"token"`
	}](t, ab).Token
	agentID, _, _ := strings.Cut(token, ".")

	dir := t.TempDir()
	tokFile := filepath.Join(dir, "token")
	_ = os.WriteFile(tokFile, []byte(token), 0o600)
	host := &secFakeHost{out: map[string]seccollect.Result{"ss -H -tulnp": {Stdout: ""}, "nft list ruleset": {Stdout: "table inet filter {\n}\n"}}}
	actx, astop := context.WithCancel(context.Background())
	adone := make(chan struct{})
	go func() {
		defer close(adone)
		_ = secagent.Run(actx, secagent.Config{ServerURL: "ws" + strings.TrimPrefix(w.h.ts.URL, "http"), TokenFile: tokFile, AllowInsecure: true,
			Interval: 150 * time.Millisecond, Version: "test", Runner: host, Probe: true})
	}()
	t.Cleanup(func() { astop(); <-adone })

	eventually(t, "the agent to be a known checker", func() bool {
		cs, err := w.h.st.SecCheckers(ctx)
		return err == nil && len(cs) == 1 && cs[0].AgentID == agentID && cs[0].VPSName == "Exit" && w.h.srv.SecOps.Online(agentID)
	})

	open, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := open.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	openPort := open.Addr().(*net.TCPAddr).Port
	shut, _ := net.Listen("tcp", "127.0.0.1:0")
	shutPort := shut.Addr().(*net.TCPAddr).Port
	shut.Close()

	pctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r, err := w.h.srv.SecOps.Probe(pctx, agentID, secproto.Probe{Kind: "tcp", Host: "127.0.0.1", Port: openPort})
	if err != nil || r.Result != "reachable" || r.IP != "127.0.0.1" || r.Refused != "" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = w.h.srv.SecOps.Probe(pctx, agentID, secproto.Probe{Kind: "tcp", Host: "127.0.0.1", Port: shutPort})
	if err != nil || r.Result != "refused" {
		t.Fatalf("a closed port is a refusal, not a guess: %+v %v", r, err)
	}
	// What the agent will not do, it says so and does not dial.
	r, err = w.h.srv.SecOps.Probe(pctx, agentID, secproto.Probe{Kind: "tcp", Host: "bad host/x", Port: 80})
	if err != nil || r.Refused != "bad_request" {
		t.Fatalf("%+v %v", r, err)
	}
}
