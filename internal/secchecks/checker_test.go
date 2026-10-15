package secchecks

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/Taminum/RemnaScope/internal/secproto"
	"github.com/Taminum/RemnaScope/internal/store"
	"github.com/Taminum/RemnaScope/internal/store/storetest"
)

type fakeProber struct {
	mu     sync.Mutex
	online map[string]bool
	reply  func(secproto.Probe) secproto.ProbeResult
	calls  []secproto.Probe
	agents []string
}

func (f *fakeProber) Online(id string) bool { return f.online[id] }
func (f *fakeProber) Probe(_ context.Context, agent string, p secproto.Probe) (secproto.ProbeResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, p)
	f.agents = append(f.agents, agent)
	f.mu.Unlock()
	r := f.reply(p)
	r.ID, r.Kind = "x", p.Kind
	return r, nil
}

func TestChecksRunFromAnIndependentCheckerWhenThereIsOne(t *testing.T) {
	allowLoopback(t)
	st := storetest.New(t)
	ctx := context.Background()
	all := store.Scope{All: true}

	target, err := st.CreateVPS(ctx, "", "Target", "", []store.VPSAddress{{Address: "127.0.0.1", Kind: "ipv4"}})
	if err != nil {
		t.Fatal(err)
	}
	exit, err := st.CreateVPS(ctx, "", "Exit", "", []store.VPSAddress{{Address: "203.0.113.9", Kind: "ipv4"}})
	if err != nil {
		t.Fatal(err)
	}
	ag, err := st.CreateSecAgent(ctx, exit.ID, "", store.HashAgentSecret("s"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SecAgentHello(ctx, ag.ID, "e", "t", "h", []string{"probe"}); err != nil {
		t.Fatal(err)
	}
	// An open port on the target, so that a fallback to the server's own check has something to find.
	open, port := listen(t)
	accept(open)
	ep, err := st.AddPortEndpoint(ctx, all, target.ID, "127.0.0.1", port, true)
	if err != nil {
		t.Fatal(err)
	}
	get := func() store.PortEndpoint {
		items, err := st.ListPortEndpoints(ctx, all, target.ID)
		if err != nil || len(items) != 1 {
			t.Fatalf("%v %v", items, err)
		}
		return items[0]
	}
	fake := &fakeProber{online: map[string]bool{ag.ID: true}, reply: func(secproto.Probe) secproto.ProbeResult {
		return secproto.ProbeResult{Result: "reachable", IP: "127.0.0.1", RTTms: 7}
	}}
	w := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w.Probes = fake
	run := func() {
		if _, err := st.RequestChecks(ctx, all, target.ID, "ports"); err != nil {
			t.Fatal(err)
		}
		w.Round(ctx)
	}

	// 1. Another machine checks: the result says so and is independent.
	run()
	p := get()
	if len(fake.calls) != 1 || fake.calls[0].Kind != "tcp" || fake.calls[0].Host != "127.0.0.1" || fake.calls[0].Port != port {
		t.Fatalf("%+v", fake.calls)
	}
	if p.LastResult == nil || *p.LastResult != "reachable" || p.Vantage == nil || !p.Vantage.Independent || p.Vantage.Name != "Exit" || p.Vantage.ID != "agent:"+exit.ID {
		t.Fatalf("%+v %+v", p, p.Vantage)
	}

	// 2. The checker is not reachable: the server checks itself and says that it is not independent.
	fake.online[ag.ID] = false
	run()
	p = get()
	if len(fake.calls) != 1 || p.Vantage == nil || p.Vantage.Independent || p.Vantage.ID != VantageID {
		t.Fatalf("%+v %+v", p, p.Vantage)
	}

	// 3. An agent that refuses, or answers with something that is not a verdict, is not believed.
	fake.online[ag.ID] = true
	for name, r := range map[string]secproto.ProbeResult{
		"busy":     {Refused: "busy"},
		"nonsense": {Result: "open; DROP TABLE"},
	} {
		fake.reply = func(secproto.Probe) secproto.ProbeResult { return r }
		before := len(fake.calls)
		run()
		p = get()
		if len(fake.calls) != before+1 || p.Vantage == nil || p.Vantage.Independent || p.Vantage.ID != VantageID || p.LastResult == nil || *p.LastResult != "reachable" {
			t.Fatalf("%s: %+v %+v", name, p, p.Vantage)
		}
	}

	// 4. A checker that lives on the target's own server is never independent of it.
	own, err := st.CreateSecAgent(ctx, target.ID, "", store.HashAgentSecret("t"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SecAgentHello(ctx, own.ID, "e", "t", "h", []string{"probe"}); err != nil {
		t.Fatal(err)
	}
	fake.online = map[string]bool{own.ID: true}
	before := len(fake.calls)
	run()
	if len(fake.calls) != before {
		t.Fatal("an agent on the target's own server must not be asked")
	}
	_ = ep
}
