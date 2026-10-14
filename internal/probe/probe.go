// Package probe measures the way in to a server from the outside: how long a TCP connection takes
// and, optionally, a TLS handshake. It sends no application data and presents no credentials.
//
// The server dials only public addresses: every address a name resolves to is checked, and the
// address actually connected to is checked again at dial time, so a name that changes its mind
// between the check and the connection cannot point the probe at an internal host.
package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Taminum/RemnaScope/internal/safehttp"
	"github.com/Taminum/RemnaScope/internal/store"
)

const (
	Timeout     = 5 * time.Second
	Concurrency = 4
	// ErrorBlocked is recorded when a target resolves only to addresses the probe may not dial.
	ErrorBlocked = "blocked_address"
)

// Result is one measurement.
type Result struct {
	OK        bool
	ConnectMS int
	TLSMS     int // 0 for tcp-only probes
	Error     string
}

var errBlocked = errors.New("probe: address not allowed")

// allowAddr decides which addresses may be dialled. Tests replace it; nothing else should.
var allowAddr = safehttp.PublicAddr

func dialer() *net.Dialer {
	return &net.Dialer{Timeout: Timeout, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil || !allowAddr(ap.Addr()) {
			return errBlocked
		}
		return nil
	}}
}

// Measure probes one target. A zero result time is never returned; failures carry a short code.
func Measure(ctx context.Context, host string, port int, mode, sni string) Result {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	var addr netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addr = a
	} else {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return Result{Error: "dns"}
		}
		blocked := true
		for _, ip := range ips {
			if allowAddr(ip) {
				addr, blocked = ip, false
				break
			}
		}
		if blocked {
			return Result{Error: ErrorBlocked}
		}
	}
	if !allowAddr(addr) {
		return Result{Error: ErrorBlocked}
	}
	target := netip.AddrPortFrom(addr.Unmap(), uint16(port)).String()

	start := time.Now()
	conn, err := dialer().DialContext(ctx, "tcp", target)
	if err != nil {
		return Result{Error: classify(err)}
	}
	defer conn.Close()
	res := Result{OK: true, ConnectMS: ms(time.Since(start))}
	if mode != "tls" {
		return res
	}
	name := sni
	if name == "" {
		if _, err := netip.ParseAddr(host); err != nil {
			name = host
		}
	}
	// Only the handshake time matters here. No data is sent, so nothing is lost by not verifying
	// the certificate: a target behind a CDN or in front of Reality may present any certificate.
	tc := tls.Client(conn, &tls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // see above
	hs := time.Now()
	if err := tc.HandshakeContext(ctx); err != nil {
		return Result{ConnectMS: res.ConnectMS, Error: "tls"}
	}
	res.TLSMS = ms(time.Since(hs))
	return res
}

func ms(d time.Duration) int {
	m := int(d.Round(time.Millisecond) / time.Millisecond)
	return max(m, 1)
}

func classify(err error) string {
	switch {
	case errors.Is(err, errBlocked):
		return ErrorBlocked
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	// Windows reports a refused connection with its own error number, which syscall.ECONNREFUSED
	// does not match; the message is the portable signal there.
	if strings.Contains(strings.ToLower(err.Error()), "refused") {
		return "refused"
	}
	return "unreachable"
}

// Run probes every enabled target once a minute, a few at a time, until ctx ends.
func Run(ctx context.Context, st *store.Store, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		round(ctx, st, time.Now().UTC(), log)
		_ = st.PurgeProbeResults(ctx, time.Now().UTC().AddDate(0, 0, -30))
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func round(ctx context.Context, st *store.Store, now time.Time, log *slog.Logger) {
	targets, err := st.AllProbeTargets(ctx)
	if err != nil {
		log.Error("probe targets", "err", err)
		return
	}
	sem := make(chan struct{}, Concurrency)
	var wg sync.WaitGroup
	for _, tg := range targets {
		sem <- struct{}{}
		wg.Add(1)
		go func(tg store.ProbeTarget) {
			defer wg.Done()
			defer func() { <-sem }()
			r := Measure(ctx, tg.Host, tg.Port, tg.Mode, tg.SNI)
			rec := store.ProbeResult{TS: now, OK: r.OK, Error: r.Error}
			if r.ConnectMS > 0 {
				v := r.ConnectMS
				rec.ConnectMS = &v
			}
			if r.TLSMS > 0 {
				v := r.TLSMS
				rec.TLSMS = &v
			}
			if err := st.RecordProbe(ctx, tg.ID, rec); err != nil {
				log.Error("recording probe", "err", err)
			}
		}(tg)
	}
	wg.Wait()
}
