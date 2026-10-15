// Package secchecks measures a VPS from the outside: whether a TCP port answers, and what certificate a
// TLS endpoint presents. It dials only public addresses, checks the address actually connected to, sends
// no data on a TCP probe, and never turns certificate verification off for its verdict.
//
// The same code runs in two places: on the RemnaScope server, and on a security agent that was set up as a
// checker, so that a target can be seen from a machine that is not the target.
package secprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/Taminum/RemnaScope/internal/netintel"
	"github.com/Taminum/RemnaScope/internal/safehttp"
	"github.com/Taminum/RemnaScope/internal/secevents"
)

const (
	dialTimeout = 5 * time.Second
	tlsTimeout  = 10 * time.Second
)

var errBlocked = errors.New("secchecks: address not allowed")

// AllowAddr and Lookup are replaced by tests; nothing else should touch them.
var (
	AllowAddr = safehttp.PublicAddr
	Lookup    = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
)

// Resolve returns the public addresses a host stands for, an IPv4 one first. A literal address is
// returned as it is when it is public. Nothing private, loopback or link-local is ever returned.
func Resolve(ctx context.Context, host string) (addrs []netip.Addr, resolved []string, err error) {
	if a, perr := netip.ParseAddr(host); perr == nil {
		a = a.Unmap()
		if !AllowAddr(a) {
			return nil, nil, errBlocked
		}
		return []netip.Addr{a}, []string{a.String()}, nil
	}
	ips, err := Lookup(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, nil, errors.New("dns")
	}
	var v4, v6 []netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		resolved = append(resolved, ip.String())
		if !AllowAddr(ip) {
			continue
		}
		if ip.Is4() {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	addrs = append(v4, v6...)
	if len(addrs) == 0 {
		return nil, resolved, errBlocked
	}
	return addrs, resolved, nil
}

func dialer() *net.Dialer {
	return &net.Dialer{Timeout: dialTimeout, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil || !AllowAddr(ap.Addr().Unmap()) {
			return errBlocked
		}
		return nil
	}}
}

// TCPResult is one connect attempt. Error is a short code and is only set for Result "error".
type TCPResult struct {
	Result string
	IP     string
	RTTms  int
	Error  string
}

func classifyDial(err error) string {
	switch {
	case errors.Is(err, errBlocked):
		return secevents.PortError
	case errors.Is(err, syscall.ECONNREFUSED):
		return secevents.PortRefused
	case errors.Is(err, context.DeadlineExceeded):
		return secevents.PortTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return secevents.PortTimeout
	}
	low := strings.ToLower(err.Error())
	switch {
	case strings.Contains(low, "refused"): // Windows reports a refusal with its own error number
		return secevents.PortRefused
	case strings.Contains(low, "unreachable"), strings.Contains(low, "no route"), strings.Contains(low, "prohibited"):
		return secevents.PortFiltered
	}
	return secevents.PortFiltered
}

// TCP connects to host:port and closes the connection without sending anything. Only a completed
// connection is "reachable" and only a refusal is "refused"; everything else is inconclusive.
func TCP(ctx context.Context, host string, port int) TCPResult {
	addrs, _, err := Resolve(ctx, host)
	if err != nil {
		return TCPResult{Result: secevents.PortError, Error: errCode(err)}
	}
	addr := addrs[0]
	ctx, cancel := context.WithTimeout(ctx, dialTimeout+time.Second)
	defer cancel()
	start := time.Now()
	conn, err := dialer().DialContext(ctx, "tcp", netip.AddrPortFrom(addr, uint16(port)).String())
	if err != nil {
		r := classifyDial(err)
		out := TCPResult{Result: r, IP: addr.String()}
		if r == secevents.PortError {
			out.Error = "blocked_address"
		}
		return out
	}
	_ = conn.Close()
	return TCPResult{Result: secevents.PortReachable, IP: addr.String(), RTTms: max(int(time.Since(start).Milliseconds()), 1)}
}

func errCode(err error) string {
	if errors.Is(err, errBlocked) {
		return "blocked_address"
	}
	return err.Error()
}

// TLSResult is what a TLS endpoint presented, judged against the system trust store and the name.
type TLSResult struct {
	State       string // a secevents.TLS* verdict
	IP          string
	Resolved    []string
	SNI         string
	NameChecked bool // false when there was no name to check against (an address with no SNI)
	Version     string
	Fingerprint string // SHA-256 of the leaf certificate
	Subject     string
	Issuer      string
	DNSNames    []string
	Serial      string
	NotBefore   time.Time
	NotAfter    time.Time
	DaysLeft    int
	HasCert     bool
	Error       string
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return ""
}

// TLS handshakes with host:port (SNI set, or the host when it is a name), reads the chain even when it is
// not trusted so the dates are never lost, and then judges the chain and the name separately.
func TLS(ctx context.Context, host string, port int, sni string, now time.Time) TLSResult {
	res := TLSResult{State: secevents.TLSUnreachable}
	if sni == "" {
		if _, err := netip.ParseAddr(host); err != nil {
			sni = host
		}
	}
	res.SNI, res.NameChecked = sni, sni != ""
	addrs, resolved, err := Resolve(ctx, host)
	res.Resolved = resolved
	if err != nil {
		res.State, res.Error = secevents.TLSBlocked, errCode(err)
		return res
	}
	addr := addrs[0]
	res.IP = addr.String()
	ctx, cancel := context.WithTimeout(ctx, tlsTimeout)
	defer cancel()
	raw, err := dialer().DialContext(ctx, "tcp", netip.AddrPortFrom(addr, uint16(port)).String())
	if err != nil {
		res.Error = classifyDial(err)
		return res
	}
	defer raw.Close()
	// Verification is done by hand below so that an untrusted certificate still yields its dates.
	conn := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) //nolint:gosec // verified below
	if err := conn.HandshakeContext(ctx); err != nil {
		res.State, res.Error = secevents.TLSHandshake, "handshake_failed"
		return res
	}
	st := conn.ConnectionState()
	res.Version = tlsVersion(st.Version)
	if len(st.PeerCertificates) == 0 {
		res.State, res.Error = secevents.TLSInvalid, "no_certificate"
		return res
	}
	leaf := st.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	info := netintel.DescribeCert(leaf, now)
	res.HasCert, res.Fingerprint = true, hex.EncodeToString(sum[:])
	res.Subject, res.Issuer, res.DNSNames, res.Serial = info.Subject, info.Issuer, info.DNSNames, info.Serial
	res.NotBefore, res.NotAfter, res.DaysLeft = leaf.NotBefore.UTC(), leaf.NotAfter.UTC(), info.DaysLeft
	res.State = verdict(st.PeerCertificates, sni, now, res.DaysLeft)
	return res
}

// verdict puts an expired certificate first: it is a fact of the dates and holds whether or not the chain
// is trusted, and an expired self-signed certificate must not read as merely "untrusted".
func verdict(chain []*x509.Certificate, sni string, now time.Time, daysLeft int) string {
	if daysLeft < 0 {
		return secevents.TLSExpired
	}
	ok, why := netintel.VerifyChain(chain, sni, now)
	if ok {
		return secevents.TLSOK
	}
	switch why {
	case "expired":
		return secevents.TLSExpired
	case "untrusted":
		return secevents.TLSUntrusted
	case "hostname_mismatch":
		return secevents.TLSHostname
	}
	return secevents.TLSInvalid
}
