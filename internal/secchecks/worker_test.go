package secchecks

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/store"
	"github.com/Taminum/Owlery/internal/store/storetest"
)

func eventTypes(t *testing.T, st *store.Store, vps string) map[string][]store.SecEvent {
	t.Helper()
	evs, err := st.SecEvents(context.Background(), store.Scope{All: true}, vps, "", nil, "", 200)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]store.SecEvent{}
	for _, e := range evs {
		out[e.Type] = append(out[e.Type], e)
	}
	return out
}

func accept(l net.Listener) {
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
}

func TestWorkerFindsKnownEndpointsAndExplainsChangesOnce(t *testing.T) {
	allowLoopback(t)
	st := storetest.New(t)
	ctx := context.Background()
	w := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	all := store.Scope{All: true}

	v, err := st.CreateVPS(ctx, "", "Test", "", []store.VPSAddress{{Address: "127.0.0.1", Kind: "ipv4"}})
	if err != nil {
		t.Fatal(err)
	}

	// Two TCP listeners on the host: one really there, one that has just gone. The agent's scan says both.
	open, openPort := listen(t)
	accept(open)
	gone, gonePort := listen(t)
	gone.Close()
	listeners, _ := json.Marshal(map[string]any{"process_info": true, "listeners": []map[string]any{
		{"proto": "tcp", "addr": "0.0.0.0", "port": openPort}, {"proto": "tcp", "addr": "0.0.0.0", "port": gonePort},
		{"proto": "tcp", "addr": "127.0.0.1", "port": 5432}, {"proto": "udp", "addr": "0.0.0.0", "port": 51820}}})
	if _, err := st.Pool().Exec(ctx, `INSERT INTO security_snapshot_state (vps_id, category, status, source_hash, observed_at, received_at, data)
		VALUES ($1,'sockets','ok','h',now(),now(),$2)`, v.ID, listeners); err != nil {
		t.Fatal(err)
	}

	w.Round(ctx)
	eps, err := st.ListPortEndpoints(ctx, all, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 {
		t.Fatalf("only non-loopback TCP listeners become candidates: %+v", eps)
	}
	by := map[int]store.PortEndpoint{}
	for _, e := range eps {
		by[e.Port] = e
		if e.Source != "local_listener" || e.Expected || e.LastResult == nil || e.LastCheckedAt == nil {
			t.Fatalf("%+v", e)
		}
	}
	if *by[openPort].LastResult != "reachable" || *by[gonePort].LastResult != "refused" {
		t.Fatalf("%v %v", *by[openPort].LastResult, *by[gonePort].LastResult)
	}
	if n := len(eventTypes(t, st, v.ID)); n != 0 {
		t.Fatalf("the first check is a baseline: %v", eventTypes(t, st, v.ID))
	}

	// An immediate second round does nothing: nothing is due yet.
	w.Round(ctx)
	if e, _ := st.ListPortEndpoints(ctx, all, v.ID); *e[0].LastResult == "" {
		t.Fatal("unreachable")
	}

	// The open port closes and the closed one opens. Both are explained, once.
	open.Close()
	reopened, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(gonePort)))
	if err != nil {
		t.Skipf("could not reuse the port: %v", err)
	}
	t.Cleanup(func() { reopened.Close() })
	accept(reopened)
	if _, err := st.RequestChecks(ctx, all, v.ID, "ports"); err != nil {
		t.Fatal(err)
	}
	w.Round(ctx)
	ev := eventTypes(t, st, v.ID)
	if len(ev["port.public_lost"]) != 1 || len(ev["port.public_reachable"]) != 1 {
		t.Fatalf("%v", ev)
	}
	if got := ev["port.public_reachable"][0]; got.Severity != "critical" {
		t.Fatalf("an unexpected port that opened must be critical: %+v", got)
	}
	var lost map[string]any
	_ = json.Unmarshal(ev["port.public_lost"][0].Payload, &lost)
	if lost["conclusive"] != true || lost["vantage"] != "api_server" {
		t.Fatalf("%v", lost)
	}
	// What the alert reads: the port that opened after the baseline is "unexpected since"; the one that was
	// answering from the start never was, and one that stopped answering has nothing pending.
	var sinceOpened, sinceBaseline *time.Time
	_ = st.Pool().QueryRow(ctx, `SELECT unexpected_since FROM security_port_endpoints WHERE vps_id=$1 AND port=$2`, v.ID, gonePort).Scan(&sinceOpened)
	_ = st.Pool().QueryRow(ctx, `SELECT unexpected_since FROM security_port_endpoints WHERE vps_id=$1 AND port=$2`, v.ID, openPort).Scan(&sinceBaseline)
	if sinceOpened == nil || sinceBaseline != nil {
		t.Fatalf("unexpected_since: opened %v, baseline %v", sinceOpened, sinceBaseline)
	}
	if _, err := st.RequestChecks(ctx, all, v.ID, "ports"); err != nil {
		t.Fatal(err)
	}
	w.Round(ctx)
	if ev2 := eventTypes(t, st, v.ID); len(ev2["port.public_lost"]) != 1 || len(ev2["port.public_reachable"]) != 1 {
		t.Fatalf("a repeated check repeated events: %v", ev2)
	}

	// The listener scan no longer lists the closed port's twin: the candidate is disabled, history kept.
	listeners, _ = json.Marshal(map[string]any{"process_info": true, "listeners": []map[string]any{{"proto": "tcp", "addr": "0.0.0.0", "port": gonePort}}})
	if _, err := st.Pool().Exec(ctx, `UPDATE security_snapshot_state SET data=$2 WHERE vps_id=$1 AND category='sockets'`, v.ID, listeners); err != nil {
		t.Fatal(err)
	}
	if err := st.SyncPortCandidates(ctx); err != nil {
		t.Fatal(err)
	}
	eps, _ = st.ListPortEndpoints(ctx, all, v.ID)
	enabled := 0
	for _, e := range eps {
		if e.Enabled {
			enabled++
		}
	}
	if len(eps) != 2 || enabled != 1 {
		t.Fatalf("%+v", eps)
	}
}

func TestWorkerTLSThresholdsAndValidationAreAnnouncedOnce(t *testing.T) {
	allowLoopback(t)
	st := storetest.New(t)
	ctx := context.Background()
	w := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	all := store.Scope{All: true}
	v, _ := st.CreateVPS(ctx, "", "Cert", "", []store.VPSAddress{{Address: "127.0.0.1", Kind: "ipv4"}})

	now := time.Now()
	port := serveTLS(t, selfSigned(t, now.Add(-time.Hour), now.Add(5*24*time.Hour), "a.example"))

	if _, err := st.AddTLSEndpoint(ctx, all, v.ID, "10.9.9.9", port, ""); err != store.ErrHostNotRegistered {
		t.Fatalf("an unregistered host must be refused: %v", err)
	}
	ep, err := st.AddTLSEndpoint(ctx, all, v.ID, "127.0.0.1", port, "a.example")
	if err != nil {
		t.Fatal(err)
	}
	w.Round(ctx)
	ev := eventTypes(t, st, v.ID)
	if len(ev["tls.expiry_threshold"]) != 1 || len(ev["tls.validation_error"]) != 1 {
		t.Fatalf("%v", ev)
	}
	var p map[string]any
	_ = json.Unmarshal(ev["tls.expiry_threshold"][0].Payload, &p)
	if p["threshold_days"] != float64(7) {
		t.Fatalf("5 days left is inside the 7 day threshold: %v", p)
	}

	// The next daily checks say nothing new.
	for i := 0; i < 2; i++ {
		if _, err := st.RequestChecks(ctx, all, v.ID, "tls"); err != nil {
			t.Fatal(err)
		}
		w.Round(ctx)
	}
	ev = eventTypes(t, st, v.ID)
	if len(ev["tls.expiry_threshold"]) != 1 || len(ev["tls.validation_error"]) != 1 {
		t.Fatalf("a threshold or an error was repeated: %v", ev)
	}
	eps, _ := st.ListTLSEndpoints(ctx, all, v.ID)
	if len(eps) != 1 || eps[0].ID != ep.ID || *eps[0].LastState != "untrusted" || eps[0].LastNotAfter == nil || *eps[0].LastFingerprint == "" {
		t.Fatalf("%+v", eps)
	}
	var n int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM security_tls_observations WHERE endpoint_id=$1`, ep.ID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("history is written only on change: %d %v", n, err)
	}
}
