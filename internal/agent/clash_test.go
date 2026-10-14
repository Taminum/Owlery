package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/ingestproto"
	"github.com/Taminum/RemnaScope/internal/routerlog"
)

type sink struct {
	mu    sync.Mutex
	lines []string
	gaps  []string
}

func (s *sink) Line(l string) { s.mu.Lock(); s.lines = append(s.lines, l); s.mu.Unlock() }
func (s *sink) Gap(r string)  { s.mu.Lock(); s.gaps = append(s.gaps, r); s.mu.Unlock() }
func (s *sink) recs(t *testing.T) []routerlog.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []routerlog.Record
	for _, l := range s.lines {
		var r routerlog.Record
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("bad line %q: %v", l, err)
		}
		out = append(out, r)
	}
	return out
}

func conn(id, src, host string, up, down int) string {
	return fmt.Sprintf(`{"id":%q,"upload":%d,"download":%d,"start":"2026-10-13T08:00:00.5Z","chains":["a-out","main-out"],
		"metadata":{"network":"tcp","sourceIP":%q,"destinationIP":"1.2.3.4","destinationPort":"443","host":%q}}`, id, up, down, src, host)
}

// run polls a fake Clash API that serves whatever body currently holds, with a fake clock.
func run(t *testing.T, leases string) (*sink, func(body string), func(d time.Duration), func()) {
	t.Helper()
	var mu sync.Mutex
	body := `{"connections":[]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if body == "FAIL" {
			http.Error(w, "x", 500)
			return
		}
		fmt.Fprint(w, body)
	}))
	var cmu sync.Mutex
	clock := time.Date(2026, 10, 13, 8, 0, 10, 0, time.UTC)
	s := &sink{}
	cs := &ClashSource{URL: srv.URL, LeasesFile: leases, Interval: 10 * time.Millisecond, Refresh: 30 * time.Second,
		Now: func() time.Time { cmu.Lock(); defer cmu.Unlock(); return clock }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = cs.Run(ctx, s); close(done) }()
	return s,
		func(b string) { mu.Lock(); body = b; mu.Unlock(); time.Sleep(80 * time.Millisecond) },
		func(d time.Duration) { cmu.Lock(); clock = clock.Add(d); cmu.Unlock() },
		func() { cancel(); <-done; srv.Close() }
}

func TestClashEmitsNewThenFinalCounters(t *testing.T) {
	dir := t.TempDir()
	leases := filepath.Join(dir, "leases")
	_ = os.WriteFile(leases, []byte("1 aa:bb 192.168.1.176 Home 01:aa\n1 cc:dd 192.168.1.9 * 01:cc\n"), 0o600)
	s, set, tick, stop := run(t, leases)
	defer stop()

	set(`{"connections":[` + conn("c1", "192.168.1.176", "Api.Example.com", 10, 20) + `],"downloadTotal":1}`)
	if r := s.recs(t); len(r) != 1 || r[0].ID != "c1" || r[0].Name != "Home" || r[0].Out != "main-out" || r[0].Port != 443 || r[0].Up != 10 {
		t.Fatalf("first record: %+v", r)
	}
	// Counters move but the refresh period has not passed: nothing new.
	set(`{"connections":[` + conn("c1", "192.168.1.176", "Api.Example.com", 100, 200) + `]}`)
	if n := len(s.recs(t)); n != 1 {
		t.Fatalf("expected no re-report yet, have %d", n)
	}
	// The connection closes: final counters are reported once.
	set(`{"connections":[]}`)
	r := s.recs(t)
	if len(r) != 2 || r[1].Up != 100 || r[1].Down != 200 {
		t.Fatalf("final record: %+v", r)
	}
	set(`{"connections":[]}`)
	if n := len(s.recs(t)); n != 2 {
		t.Fatalf("closed connection reported again: %d", n)
	}
	_ = tick
}

func TestClashRefreshesLongConnections(t *testing.T) {
	s, set, tick, stop := run(t, "")
	defer stop()
	set(`{"connections":[` + conn("c1", "192.168.1.5", "x.test", 1, 1) + `]}`)
	tick(31 * time.Second)
	set(`{"connections":[` + conn("c1", "192.168.1.5", "x.test", 500, 900) + `]}`)
	r := s.recs(t)
	if len(r) != 2 || r[1].Up != 500 || r[1].Down != 900 {
		t.Fatalf("refresh: %+v", r)
	}
}

func TestClashReportsGapWhenUnreachableAndRecovers(t *testing.T) {
	s, set, _, stop := run(t, "")
	defer stop()
	set("FAIL")
	set("FAIL")
	s.mu.Lock()
	gaps := append([]string(nil), s.gaps...)
	s.mu.Unlock()
	if len(gaps) != 1 || gaps[0] != "source_unreachable" {
		t.Fatalf("gaps: %v", gaps)
	}
	set(`{"connections":[` + conn("c9", "192.168.1.5", "y.test", 1, 1) + `]}`)
	if n := len(s.recs(t)); n != 1 {
		t.Fatalf("no recovery: %d", n)
	}
}

func TestClashIgnoresUnknownFieldsAndBadRecords(t *testing.T) {
	s, set, _, stop := run(t, "")
	defer stop()
	set(`{"extra":{"a":[1,2]},"connections":[{"id":"","start":"bad"},` + conn("ok", "192.168.1.5", "z.test", 0, 0) + `],"memory":5}`)
	if r := s.recs(t); len(r) != 1 || r[0].ID != "ok" {
		t.Fatalf("got %+v", r)
	}
	// And the lines it produces pass the server's validation.
	now := time.Date(2026, 10, 13, 8, 1, 0, 0, time.UTC)
	for _, l := range s.lines {
		if _, err := routerlog.Parse(l, now); err != nil {
			t.Fatalf("server rejects %q: %v", l, err)
		}
	}
}

func TestLiveFrameTurnsDeltasIntoSpeedsBusiestFirst(t *testing.T) {
	by := map[string]*ingestproto.LiveDevice{
		"192.168.1.5": {IP: "192.168.1.5", Name: "Home", Up: 2000, Down: 8000, Conn: 3},
		"192.168.1.9": {IP: "192.168.1.9", Up: 100, Down: 100, Conn: 1},
		"192.168.1.7": {IP: "192.168.1.7", Up: 0, Down: 50000, Conn: 2},
	}
	f := liveFrame(by, 2*time.Second)
	if f.Type != "live" || f.Up != 1050 || f.Down != 29050 || f.Conns != 6 {
		t.Fatalf("totals: %+v", f)
	}
	if f.Devices[0].IP != "192.168.1.7" || f.Devices[0].Down != 25000 || f.Devices[1].IP != "192.168.1.5" || f.Devices[1].Up != 1000 || f.Devices[1].Name != "Home" {
		t.Fatalf("devices: %+v", f.Devices)
	}
	// A very short interval is not allowed to blow the speed up.
	g := liveFrame(map[string]*ingestproto.LiveDevice{"192.168.1.5": {IP: "192.168.1.5", Down: 1000}}, 0)
	if g.Down != 5000 {
		t.Fatalf("floor of 0.2 s: %+v", g)
	}
	// Never more devices than the protocol allows.
	many := map[string]*ingestproto.LiveDevice{}
	for i := 0; i < ingestproto.MaxLiveDevices+20; i++ {
		ip := fmt.Sprintf("192.168.2.%d", i)
		many[ip] = &ingestproto.LiveDevice{IP: ip, Down: int64(i)}
	}
	if got := liveFrame(many, time.Second); len(got.Devices) != ingestproto.MaxLiveDevices || got.Devices[0].Down != int64(ingestproto.MaxLiveDevices+19) {
		t.Fatalf("cap: %d", len(got.Devices))
	}
}

func TestClashSourceReportsLiveFramesAfterTwoPolls(t *testing.T) {
	var mu sync.Mutex
	var frames []ingestproto.Live
	body := `{"connections":[` + conn("c1", "192.168.1.5", "a.test", 10, 20) + `,` + conn("c2", "192.168.1.5", "b.test", 1, 1) + `,` + conn("c3", "192.168.1.9", "c.test", 0, 0) + `]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	defer srv.Close()
	cs := &ClashSource{URL: srv.URL, Interval: 20 * time.Millisecond, Live: func(f ingestproto.Live) { mu.Lock(); frames = append(frames, f); mu.Unlock() }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = cs.Run(ctx, &sink{}); close(done) }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(frames) == 0 {
		t.Fatal("no live frame after several polls")
	}
	f := frames[len(frames)-1]
	if f.Conns != 3 || len(f.Devices) != 2 {
		t.Fatalf("the snapshot must count the connections and group them by device: %+v", f)
	}
	// Counters do not move between polls, so nothing is flowing.
	if f.Up != 0 || f.Down != 0 {
		t.Fatalf("unchanged counters mean zero speed: %+v", f)
	}
}
