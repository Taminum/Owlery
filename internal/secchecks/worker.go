package secchecks

import (
	"context"
	"encoding/json"
	"log/slog"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/Taminum/RemnaScope/internal/secevents"
	"github.com/Taminum/RemnaScope/internal/secprobe"
	"github.com/Taminum/RemnaScope/internal/secproto"
	"github.com/Taminum/RemnaScope/internal/store"
)

// The server's own point of view. It is never called independent: RemnaScope cannot tell whether the machine
// it runs on is the one being checked, and a result that cannot say so is labelled as such.
const (
	VantageID   = "api_server"
	Independent = false
)

// Prober asks a connected security agent to run a check from where it stands.
type Prober interface {
	Online(agentID string) bool
	Probe(ctx context.Context, agentID string, p secproto.Probe) (secproto.ProbeResult, error)
}

const probeWait = 25 * time.Second

const (
	PortEvery   = 60 * time.Minute
	TLSEvery    = 24 * time.Hour
	Concurrency = 4
	roundLimit  = 100
	tick        = 30 * time.Second
)

// jitter spreads the next check by up to 5% either way, so checks that started together drift apart.
func jitter(every time.Duration) time.Duration {
	return every + time.Duration((rand.Float64()*0.1-0.05)*float64(every))
}

// Worker runs the external checks. A manual request marks endpoints due and calls Nudge.
type Worker struct {
	Store *store.Store
	Log   *slog.Logger
	Now   func() time.Time
	// Probes, when set, lets a target be checked from a security agent that was set up as a checker. Without
	// it, or when no checker can see the target independently, the check runs on this server.
	Probes Prober
	// ScanPorts is the fixed list a scan tries; nil means DefaultScanPorts. ScanPause spaces the attempts.
	ScanPorts []int
	ScanPause time.Duration
	nudge     chan struct{}
}

// DefaultScanPorts is the bounded list of common service ports an opted-in scan tries on a server's own IP
// addresses. It is a list, not a range: a scan never walks 1-65535.
var DefaultScanPorts = []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 993, 995, 1080, 1433, 1723, 2049, 2082,
	2083, 2086, 2087, 2222, 3000, 3128, 3306, 3389, 4443, 5000, 5432, 5601, 5900, 5985, 6379, 7443, 8000, 8008, 8080, 8081, 8086, 8088,
	8443, 8444, 8888, 9000, 9090, 9200, 9443, 10000, 11211, 15672, 27017}

const scanEveryTick = 10 * time.Minute

func New(st *store.Store, log *slog.Logger) *Worker {
	return &Worker{Store: st, Log: log, nudge: make(chan struct{}, 1)}
}

// Nudge asks for a round now. It never blocks and never queues more than one.
func (w *Worker) Nudge() {
	select {
	case w.nudge <- struct{}{}:
	default:
	}
}

func (w *Worker) now() time.Time {
	if w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}

func (w *Worker) Run(ctx context.Context) {
	go w.scanLoop(ctx)
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		w.Round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-w.nudge:
		}
	}
}

// Round checks everything that is due, a few targets at a time.
func (w *Worker) Round(ctx context.Context) {
	// Commands that were not answered in time are called unknown, and ones the state read since has settled are closed.
	if _, err := w.Store.SettleCommands(ctx, w.now()); err != nil {
		w.Log.Error("settling commands", "err", err)
	}
	if err := w.Store.SyncPortCandidates(ctx); err != nil {
		w.Log.Error("syncing port candidates", "err", err)
	}
	now := w.now()
	ports, err := w.Store.DuePorts(ctx, now, roundLimit)
	if err != nil {
		w.Log.Error("due ports", "err", err)
	}
	tlss, err := w.Store.DueTLS(ctx, now, roundLimit)
	if err != nil {
		w.Log.Error("due tls", "err", err)
	}
	sem := make(chan struct{}, Concurrency)
	var wg sync.WaitGroup
	run := func(f func()) {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			f()
		}()
	}
	var checkers []store.Checker
	if w.Probes != nil && (len(ports) > 0 || len(tlss) > 0) {
		if checkers, err = w.Store.SecCheckers(ctx); err != nil {
			w.Log.Error("listing checkers", "err", err)
		}
	}
	for _, p := range ports {
		run(func() {
			r, v := w.tcp(ctx, checkers, p)
			at := w.now()
			if err := w.Store.RecordPortCheck(ctx, p.ID, store.PortObservation{Result: r.Result, IP: r.IP, RTTms: r.RTTms, Error: r.Error, Vantage: v}, at, at.Add(jitter(PortEvery))); err != nil {
				w.Log.Error("recording port check", "err", err)
			}
		})
	}
	for _, e := range tlss {
		run(func() {
			r, v := w.tls(ctx, checkers, e)
			data, _ := json.Marshal(map[string]any{
				"state": r.State, "ip": r.IP, "resolved": r.Resolved, "sni": r.SNI, "name_checked": r.NameChecked, "version": r.Version,
				"fingerprint": r.Fingerprint, "subject": r.Subject, "issuer": r.Issuer, "dns_names": r.DNSNames, "serial": r.Serial,
				"not_before": nilTime(r.NotBefore), "not_after": nilTime(r.NotAfter), "days_left": r.DaysLeft, "has_cert": r.HasCert, "error": r.Error,
				"vantage": v.ID, "independent": v.Independent, "checker": v.Name,
			})
			at := w.now()
			if err := w.Store.RecordTLSCheck(ctx, e.ID, store.TLSObservation{State: r.State, IP: r.IP, HasCert: r.HasCert, Fingerprint: r.Fingerprint,
				NotAfter: r.NotAfter, DaysLeft: r.DaysLeft, Data: data, Vantage: v}, at, at.Add(jitter(TLSEvery))); err != nil {
				w.Log.Error("recording tls check", "err", err)
			}
		})
	}
	// Look for TLS endpoints nobody listed, a few at a time. A candidate is a registered domain on 443 or a
	// known listener on a well-known TLS port; nothing else is handshaken with.
	cands, err := w.Store.TLSCandidates(ctx, now, 20)
	if err != nil {
		w.Log.Error("tls candidates", "err", err)
	}
	for _, c := range cands {
		run(func() { w.discoverTLS(ctx, checkers, c) })
	}
	wg.Wait()
}

func (w *Worker) discoverTLS(ctx context.Context, checkers []store.Checker, c store.TLSCandidate) {
	r, v := w.tls(ctx, checkers, store.DueTLS{VPSID: c.VPSID, Host: c.Host, Port: c.Port})
	at := w.now()
	if err := w.Store.MarkTLSTried(ctx, c, at); err != nil {
		w.Log.Error("marking a tls candidate", "err", err)
	}
	// Only a certificate that was actually presented confirms TLS. A refusal or a timeout confirms nothing.
	if !r.HasCert {
		return
	}
	if added, err := w.Store.AddAutoTLSEndpoint(ctx, c, r.State, at, v); err != nil {
		w.Log.Error("adding a discovered tls endpoint", "err", err)
	} else if added {
		w.Log.Info("tls endpoint discovered", "host", c.Host, "port", c.Port)
	}
}

// scanLoop runs the opt-in port scan on its own clock, so that a slow scan never holds up the checks.
func (w *Worker) scanLoop(ctx context.Context) {
	t := time.NewTicker(scanEveryTick)
	defer t.Stop()
	for {
		w.Scan(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Scan tries the fixed list of common ports on the registered IP addresses of servers that opted in, once a
// day each, a few at a time with a pause between attempts. What answers is recorded as an endpoint that is
// not expected, so it shows as unexpected until someone says otherwise.
func (w *Worker) Scan(ctx context.Context) {
	now := w.now()
	targets, err := w.Store.ScanTargets(ctx, now, 3)
	if err != nil {
		w.Log.Error("scan targets", "err", err)
		return
	}
	if len(targets) == 0 {
		return
	}
	var checkers []store.Checker
	if w.Probes != nil {
		if checkers, err = w.Store.SecCheckers(ctx); err != nil {
			w.Log.Error("listing checkers", "err", err)
		}
	}
	ports := w.ScanPorts
	if ports == nil {
		ports = DefaultScanPorts
	}
	for _, tg := range targets {
		var mu sync.Mutex
		var found []store.ScanFound
		v := store.Vantage{ID: VantageID, Independent: Independent}
		sem := make(chan struct{}, Concurrency)
		var wg sync.WaitGroup
		for _, addr := range tg.Addresses {
			for _, port := range ports {
				if ctx.Err() != nil {
					break
				}
				sem <- struct{}{}
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-sem }()
					r, vv := w.tcp(ctx, checkers, store.DuePort{VPSID: tg.VPSID, Host: addr, Port: port})
					if r.Result != secevents.PortReachable {
						return
					}
					mu.Lock()
					found = append(found, store.ScanFound{Host: addr, Port: port, IP: r.IP})
					v = vv
					mu.Unlock()
				}()
				if w.ScanPause > 0 {
					time.Sleep(w.ScanPause)
				} else {
					time.Sleep(50 * time.Millisecond)
				}
			}
		}
		wg.Wait()
		if ctx.Err() != nil {
			return
		}
		fresh, err := w.Store.RecordScan(ctx, tg.VPSID, w.now(), found, v)
		if err != nil {
			w.Log.Error("recording a scan", "err", err)
			continue
		}
		w.Log.Info("discovery scan done", "vps", tg.VPSID, "answered", len(found), "new", len(fresh))
	}
}

func nilTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// pick chooses a checker for a target: one that is connected, is not the target's own server, and does
// not own the address being checked. It returns false when none qualifies.
func (w *Worker) pick(checkers []store.Checker, vpsID, host string) (store.Checker, bool) {
	for _, c := range checkers {
		if c.VPSID == vpsID || slices.Contains(c.Addresses, host) || !w.Probes.Online(c.AgentID) {
			continue
		}
		return c, true
	}
	return store.Checker{}, false
}

func (w *Worker) probe(ctx context.Context, c store.Checker, p secproto.Probe) (secproto.ProbeResult, bool) {
	ctx, cancel := context.WithTimeout(ctx, probeWait)
	defer cancel()
	r, err := w.Probes.Probe(ctx, c.AgentID, p)
	if err != nil || r.Refused != "" || r.Kind != p.Kind {
		w.Log.Warn("a checker did not answer; the server will check itself", "checker", c.VPSName, "kind", p.Kind, "err", err, "refused", r.Refused)
		return r, false
	}
	return r, true
}

func agentVantage(c store.Checker, ip string) store.Vantage {
	// A target that turns out to be the checker's own address is not seen independently.
	return store.Vantage{ID: "agent:" + c.VPSID, Name: c.VPSName, Independent: ip == "" || !slices.Contains(c.Addresses, ip)}
}

var portResults = map[string]bool{secevents.PortReachable: true, secevents.PortRefused: true, secevents.PortTimeout: true, secevents.PortFiltered: true, secevents.PortError: true}

var tlsStates = map[string]bool{secevents.TLSOK: true, secevents.TLSExpired: true, secevents.TLSUntrusted: true, secevents.TLSHostname: true,
	secevents.TLSInvalid: true, secevents.TLSHandshake: true, secevents.TLSUnreachable: true, secevents.TLSBlocked: true}

func (w *Worker) tcp(ctx context.Context, checkers []store.Checker, p store.DuePort) (secprobe.TCPResult, store.Vantage) {
	if w.Probes != nil {
		if c, ok := w.pick(checkers, p.VPSID, p.Host); ok {
			if r, ok := w.probe(ctx, c, secproto.Probe{Kind: secproto.ProbeTCP, Host: p.Host, Port: p.Port}); ok && portResults[r.Result] {
				return secprobe.TCPResult{Result: r.Result, IP: r.IP, RTTms: r.RTTms, Error: r.Error}, agentVantage(c, r.IP)
			}
		}
	}
	return secprobe.TCP(ctx, p.Host, p.Port), store.Vantage{ID: VantageID, Independent: Independent}
}

func (w *Worker) tls(ctx context.Context, checkers []store.Checker, e store.DueTLS) (secprobe.TLSResult, store.Vantage) {
	if w.Probes != nil {
		if c, ok := w.pick(checkers, e.VPSID, e.Host); ok {
			r, ok := w.probe(ctx, c, secproto.Probe{Kind: secproto.ProbeTLS, Host: e.Host, Port: e.Port, SNI: e.SNI})
			if ok && r.TLS != nil && tlsStates[r.TLS.State] {
				x := r.TLS
				out := secprobe.TLSResult{State: x.State, IP: x.IP, Resolved: x.Resolved, SNI: x.SNI, NameChecked: x.NameChecked, Version: x.Version,
					Fingerprint: x.Fingerprint, Subject: x.Subject, Issuer: x.Issuer, DNSNames: x.DNSNames, Serial: x.Serial,
					NotBefore: x.NotBefore, NotAfter: x.NotAfter, DaysLeft: x.DaysLeft, HasCert: x.HasCert, Error: x.Error}
				if out.HasCert && !out.NotAfter.IsZero() {
					// The agent's clock is not trusted for what the days are counted from.
					out.DaysLeft = int(out.NotAfter.Sub(w.now()).Hours() / 24)
				}
				return out, agentVantage(c, x.IP)
			}
		}
	}
	return secprobe.TLS(ctx, e.Host, e.Port, e.SNI, w.now()), store.Vantage{ID: VantageID, Independent: Independent}
}
