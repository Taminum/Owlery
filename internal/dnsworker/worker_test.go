package dnsworker

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/Taminum/Owlery/internal/dnsmap"
	"github.com/Taminum/Owlery/internal/store"
	"github.com/Taminum/Owlery/internal/store/storetest"
)

// zoneState is the zone the fake network serves; the test changes it between runs.
type zoneState struct {
	mu sync.Mutex
	a  string
	mx string
}

func (z *zoneState) set(a, mx string) { z.mu.Lock(); z.a, z.mx = a, mx; z.mu.Unlock() }

func (z *zoneState) exchange(_ context.Context, _ netip.AddrPort, wire []byte) ([]byte, error) {
	z.mu.Lock()
	a, mx := z.a, z.mx
	z.mu.Unlock()
	var p dnsmessage.Parser
	h, err := p.Start(wire)
	if err != nil {
		return nil, err
	}
	q, _ := p.Question()
	name := strings.TrimSuffix(q.Name.String(), ".")
	hd := func(t dnsmessage.Type) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: q.Name, Type: t, Class: dnsmessage.ClassINET, TTL: 300}
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true})
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()
	switch {
	case name == "example.com" && q.Type == dnsmessage.TypeA:
		_ = b.AResource(hd(dnsmessage.TypeA), dnsmessage.AResource{A: netip.MustParseAddr(a).As4()})
	case name == "example.com" && q.Type == dnsmessage.TypeMX:
		_ = b.MXResource(hd(dnsmessage.TypeMX), dnsmessage.MXResource{Pref: 10, MX: dnsmessage.MustNewName(mx + ".")})
	case name == "example.com" && q.Type == dnsmessage.TypeNS:
		_ = b.NSResource(hd(dnsmessage.TypeNS), dnsmessage.NSResource{NS: dnsmessage.MustNewName("ns1.example.net.")})
	case name == "example.com" && q.Type == dnsmessage.TypeSOA:
		_ = b.SOAResource(hd(dnsmessage.TypeSOA), dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns1.example.net."), MBox: dnsmessage.MustNewName("h.example.net."), Serial: 1, Refresh: 1, Retry: 1, Expire: 1, MinTTL: 1})
	}
	return b.Finish()
}

func TestTheWorkerRunsAMapStoresItAndExplainsALaterChange(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	z := &zoneState{}
	z.set("93.184.216.34", "mail.example.com")
	w := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	w.Client = &dnsmap.Client{Exchange: z.exchange, Allow: func(netip.Addr) bool { return true }}
	w.Resolvers = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:53"), netip.MustParseAddrPort("192.0.2.2:53")}
	w.Retry = time.Millisecond

	m, err := st.CreateDNSMap(ctx, "", "example.com", "example.com", nil, false, 24, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	w.Round(ctx)

	got, _ := st.GetDNSMap(ctx, m.ID)
	if got.LastStatus == nil || *got.LastStatus == "failed" || !got.BaselineDone || got.LastRunAt == nil || got.NextRunAt == nil {
		t.Fatalf("%+v", got)
	}
	if d := got.NextRunAt.Sub(*got.LastRunAt); d < 22*time.Hour || d > 26*time.Hour {
		t.Fatalf("the next run is about a day away, with jitter: %v", d)
	}
	recs, _ := st.DNSRecords(ctx, m.ID, store.DNSRecordFilter{Limit: 100})
	byKey := map[string]store.DNSRecordRow{}
	for _, r := range recs {
		byKey[r.Name+"|"+r.Type] = r
	}
	if r := byKey["example.com|A"]; !r.Confirmed || len(r.Values) != 1 || r.Values[0] != "93.184.216.34" || r.TTL != 300 {
		t.Fatalf("%+v", r)
	}
	if r := byKey["example.com|MX"]; r.Values[0] != "10 mail.example.com" {
		t.Fatalf("%+v", r)
	}
	runs, _ := st.DNSRuns(ctx, m.ID, 5)
	if len(runs) != 1 || runs[0].FinishedAt == nil || runs[0].Status == "running" {
		t.Fatalf("a run's status is durable and final: %+v", runs)
	}
	if ch, _ := st.DNSChanges(ctx, m.ID, store.DNSChangeFilter{Limit: 50}); len(ch) != 0 {
		t.Fatalf("the first run is a baseline: %+v", ch)
	}

	// Not due again yet: a round does nothing.
	w.Round(ctx)
	if runs, _ := st.DNSRuns(ctx, m.ID, 5); len(runs) != 1 {
		t.Fatalf("a map that is not due was run: %d", len(runs))
	}

	// The zone changes; a refresh makes the map due, and the worker explains what changed.
	z.set("203.0.113.9", "mx.other.example.org")
	if err := st.RequestDNSRun(ctx, m.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	w.Round(ctx)
	kinds := map[string]bool{}
	ch, _ := st.DNSChanges(ctx, m.ID, store.DNSChangeFilter{Limit: 50})
	for _, c := range ch {
		kinds[c.Kind] = true
	}
	if !kinds[dnsmap.ChangeMX] || !kinds[dnsmap.ChangeAdded] || !kinds[dnsmap.ChangeRemoved] {
		t.Fatalf("%v", kinds)
	}
	if runs, _ := st.DNSRuns(ctx, m.ID, 5); len(runs) != 2 {
		t.Fatalf("%d runs", len(runs))
	}
}

func TestARunLeftRunningByADeadProcessIsSweptToFailed(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	m, err := st.CreateDNSMap(ctx, "", "example.com", "example.com", nil, false, 24, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.StartDNSRun(ctx, m.ID, "manual", time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	fresh, _ := st.StartDNSRun(ctx, m.ID, "manual", time.Now().UTC())
	if err := st.SweepDNSRuns(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	runs, _ := st.DNSRuns(ctx, m.ID, 5)
	status := map[string]string{}
	for _, r := range runs {
		status[r.ID] = r.Status
	}
	if status[fresh] != "running" {
		t.Fatalf("a run that is in progress must be left alone: %v", status)
	}
	failed := 0
	for _, r := range runs {
		if r.Status == "failed" && r.Error != nil && *r.Error == "interrupted" {
			failed++
		}
	}
	if failed != 1 {
		t.Fatalf("%+v", runs)
	}
	// While one is running, a map is not due again.
	if due, _ := st.DueDNSMaps(ctx, time.Now().UTC(), 10); len(due) != 0 {
		t.Fatalf("%+v", due)
	}
}
