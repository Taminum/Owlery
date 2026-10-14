package netintel

import (
	"context"
	"os"
	"testing"
	"time"
)

// Real network access: run with NETINTEL_LIVE=1, ideally as the same unprivileged user and in the
// same kind of container as production. It checks that ICMP works without raw-socket privileges.
func TestLiveICMPAndPorts(t *testing.T) {
	if os.Getenv("NETINTEL_LIVE") == "" {
		t.Skip("set NETINTEL_LIVE=1")
	}
	tool := &Tool{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	env := tool.Ping(ctx, mustTarget(t, "1.1.1.1"), 3)
	if len(env.Sources) != 1 || !env.Sources[0].OK {
		t.Fatalf("ping: %+v", env.Sources)
	}
	p := env.Data.(PingResult)
	t.Logf("ping %s: sent %d received %d avg %v ms", p.Address, p.Sent, p.Received, p.AvgMs)
	if p.Received == 0 {
		t.Fatalf("no replies: %+v", p)
	}
	env = tool.Ports(ctx, mustTarget(t, "1.1.1.1"), []int{53, 80, 443, 22})
	for _, r := range env.Data.(PortsResult).Results {
		t.Logf("port %d open=%v err=%s ms=%d", r.Port, r.Open, r.Error, r.Ms)
	}
}

func TestLiveTrace(t *testing.T) {
	if os.Getenv("NETINTEL_LIVE") == "" {
		t.Skip("set NETINTEL_LIVE=1")
	}
	tool := &Tool{}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	env := tool.Trace(ctx, mustTarget(t, "1.1.1.1"))
	if len(env.Sources) != 1 || !env.Sources[0].OK {
		t.Fatalf("trace: %+v", env.Sources)
	}
	for _, h := range env.Data.(TraceResult).Hops {
		t.Logf("hop %d %s rtt=%v lost=%d reached=%v", h.TTL, h.Addr, h.RTTms, h.Lost, h.Reached)
	}
	if !env.Data.(TraceResult).Reached {
		t.Log("the destination did not answer (a filtered route is possible)")
	}
}
