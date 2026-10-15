package secchecks

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/store"
	"github.com/Taminum/RemnaScope/internal/store/storetest"
)

func TestATLSEndpointIsFoundOnlyWhereACertificateWasActuallyPresented(t *testing.T) {
	allowLoopback(t)
	st := storetest.New(t)
	ctx := context.Background()
	all := store.Scope{All: true}
	now := time.Now()
	w := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))

	v, err := st.CreateVPS(ctx, "", "Web", "", []store.VPSAddress{{Address: "127.0.0.1", Kind: "ipv4"}})
	if err != nil {
		t.Fatal(err)
	}
	tlsPort := serveTLS(t, selfSigned(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), "web.example"))
	plain, plainPort := listen(t)
	accept(plain)
	old := store.TLSDiscoveryPorts
	store.TLSDiscoveryPorts = append(append([]int{}, old...), tlsPort, plainPort)
	t.Cleanup(func() { store.TLSDiscoveryPorts = old })
	for _, p := range []int{tlsPort, plainPort} {
		if _, err := st.AddPortEndpoint(ctx, all, v.ID, "127.0.0.1", p, true); err != nil {
			t.Fatal(err)
		}
	}

	w.Round(ctx) // the port checks make both known to answer
	w.Round(ctx) // and now they are candidates
	eps, err := st.ListTLSEndpoints(ctx, all, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0].Port != tlsPort || eps[0].Source != "auto" {
		t.Fatalf("only the port that presented a certificate is an endpoint: %+v", eps)
	}
	if evs := eventTypes(t, st, v.ID); len(evs["tls.discovered"]) != 1 {
		t.Fatalf("%v", evs)
	}

	// Tried once, not again every round: the plain port is left alone until the retry time.
	cands, err := st.TLSCandidates(ctx, time.Now(), 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cands {
		if c.VPSID == v.ID {
			t.Fatalf("a candidate that was just tried comes up again: %+v", c)
		}
	}
}

func TestTheScanIsOptInBoundedAndNeverReAddsAKnownPort(t *testing.T) {
	allowLoopback(t)
	st := storetest.New(t)
	ctx := context.Background()
	all := store.Scope{All: true}
	w := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))

	v, err := st.CreateVPS(ctx, "", "Scanned", "", []store.VPSAddress{{Address: "127.0.0.1", Kind: "ipv4"}})
	if err != nil {
		t.Fatal(err)
	}
	known, knownPort := listen(t)
	accept(known)
	extra, extraPort := listen(t)
	accept(extra)
	shut, shutPort := listen(t)
	shut.Close()
	if _, err := st.AddPortEndpoint(ctx, all, v.ID, "127.0.0.1", knownPort, true); err != nil {
		t.Fatal(err)
	}
	w.ScanPorts, w.ScanPause = []int{knownPort, extraPort, shutPort}, time.Millisecond

	// Off by default: nothing is tried.
	w.Scan(ctx)
	if eps, _ := st.ListPortEndpoints(ctx, all, v.ID); len(eps) != 1 {
		t.Fatalf("a server that did not opt in was scanned: %+v", eps)
	}

	on := true
	if _, err := st.UpdateVPS(ctx, all, v.ID, store.VPSPatch{DiscoveryScan: &on}); err != nil {
		t.Fatal(err)
	}
	w.Scan(ctx)
	eps, err := st.ListPortEndpoints(ctx, all, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	var found *store.PortEndpoint
	for i := range eps {
		if eps[i].Port == extraPort {
			found = &eps[i]
		}
		if eps[i].Port == shutPort {
			t.Fatalf("a closed port became an endpoint: %+v", eps[i])
		}
	}
	if len(eps) != 2 || found == nil || found.Source != "discovered" || found.Expected {
		t.Fatalf("%+v", eps)
	}
	if evs := eventTypes(t, st, v.ID); len(evs["port.discovered"]) != 1 {
		t.Fatalf("%v", evs)
	}

	// Once a day, not once a round.
	got, err := st.ScanTargets(ctx, time.Now(), 10)
	if err != nil || len(got) != 0 {
		t.Fatalf("%+v %v", got, err)
	}
	vv, _ := st.GetVPS(ctx, all, v.ID)
	if !vv.DiscoveryScan || vv.DiscoveryScanAt == nil {
		t.Fatalf("%+v", vv)
	}
}
