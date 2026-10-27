package netintel

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"syscall"
	"time"
)

// guardedDialer connects only to public addresses. The check is made on the address actually being
// connected to, after resolution, so a name that changes its answer cannot slip past an earlier check.
func guardedDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, _ := net.SplitHostPort(address)
		if a, err := netip.ParseAddr(host); err != nil || publicCheck(a) != nil {
			return ErrNotPublic
		}
		return nil
	}}
}

// ---- TLS certificate -------------------------------------------------------------------------------

type CertInfo struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	DaysLeft  int       `json:"days_left"`
	DNSNames  []string  `json:"dns_names,omitempty"`
	Serial    string    `json:"serial"`
	SigAlg    string    `json:"sig_alg"`
	KeyType   string    `json:"key_type"`
	CA        bool      `json:"ca"`
}

type TLSResult struct {
	Address     string     `json:"address"`
	Port        int        `json:"port"`
	SNI         string     `json:"sni,omitempty"`
	Version     string     `json:"version"`
	Cipher      string     `json:"cipher"`
	ALPN        string     `json:"alpn,omitempty"`
	Verified    bool       `json:"verified"`
	VerifyError string     `json:"verify_error,omitempty"` // expired | untrusted | hostname_mismatch | invalid
	HandshakeMs int        `json:"handshake_ms"`
	Chain       []CertInfo `json:"chain"`
}

// TLS connects, completes a handshake and describes the certificate chain the server presents. The
// chain is inspected even if it is not trusted (that is the point), and whether it is trusted is
// reported separately. Nothing is sent over the connection. Never cached.
func (t *Tool) TLS(ctx context.Context, tg Target, port int) Envelope {
	now := t.now().UTC()
	env := Envelope{Kind: "tls", Target: tg.Value, Display: tg.Display, FetchedAt: now, ExpiresAt: now, Vantage: "server"}
	if port <= 0 || port > 65535 {
		port = 443
	}
	addrs, err := t.publicAddrs(ctx, tg)
	if err != nil {
		env.Sources = []Source{{Name: "tls", OK: false, Error: codeOf(err)}}
		return env
	}
	addr := addrs[0]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	start := time.Now()
	raw, err := guardedDialer(5*time.Second).DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), fmt.Sprint(port)))
	if err != nil {
		env.Sources = []Source{{Name: "tls", OK: false, Error: classifyDial(err)}}
		return env
	}
	defer raw.Close()
	sni := ""
	if tg.Kind == KindDomain {
		sni = tg.Value
	}
	conn := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, NextProtos: []string{"h2", "http/1.1"}}) //nolint:gosec // inspection: trust is judged below
	if err := conn.HandshakeContext(ctx); err != nil {
		env.Sources = []Source{{Name: "tls", OK: false, Error: "handshake_failed"}}
		return env
	}
	st := conn.ConnectionState()
	res := TLSResult{Address: addr.String(), Port: port, SNI: sni, Version: tlsVersion(st.Version), Cipher: tls.CipherSuiteName(st.CipherSuite), ALPN: st.NegotiatedProtocol,
		HandshakeMs: int(time.Since(start).Milliseconds()), Chain: []CertInfo{}}
	for _, c := range st.PeerCertificates {
		res.Chain = append(res.Chain, certInfo(c, now))
	}
	res.Verified, res.VerifyError = verifyChain(st.PeerCertificates, sni, now)
	env.Sources = []Source{{Name: "tls", OK: true}}
	env.Data = res
	return env
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
	return "?"
}

func verifyChain(certs []*x509.Certificate, host string, now time.Time) (bool, string) {
	if len(certs) == 0 {
		return false, "invalid"
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter, CurrentTime: now})
	if err == nil {
		return true, ""
	}
	var inv x509.CertificateInvalidError
	var unk x509.UnknownAuthorityError
	var hn x509.HostnameError
	switch {
	case errors.As(err, &inv) && inv.Reason == x509.Expired:
		return false, "expired"
	case errors.As(err, &unk):
		return false, "untrusted"
	case errors.As(err, &hn):
		return false, "hostname_mismatch"
	}
	return false, "invalid"
}

func certInfo(c *x509.Certificate, now time.Time) CertInfo {
	names := c.DNSNames
	if len(names) > 40 {
		names = names[:40]
	}
	kt := "?"
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		kt = fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PublicKey:
		kt = "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		kt = "Ed25519"
	}
	return CertInfo{Subject: clip(c.Subject.String(), 200), Issuer: clip(c.Issuer.String(), 200), NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(),
		DaysLeft: int(c.NotAfter.Sub(now).Hours() / 24), DNSNames: names, Serial: hex.EncodeToString(c.SerialNumber.Bytes()), SigAlg: c.SignatureAlgorithm.String(), KeyType: kt, CA: c.IsCA}
}

// ---- HTTP inspector ------------------------------------------------------------------------------------

type HTTPHop struct {
	URL      string            `json:"url"`
	Status   int               `json:"status"`
	Proto    string            `json:"proto"`
	Ms       int               `json:"ms"`
	Remote   string            `json:"remote,omitempty"`
	Location string            `json:"location,omitempty"`
	TLS      string            `json:"tls,omitempty"`
	Headers  map[string]string `json:"headers"`
}

type HTTPResult struct {
	Hops     []HTTPHop       `json:"hops"`
	Final    int             `json:"final_status"`
	Security map[string]bool `json:"security"` // which common protective headers the last answer carries
}

var securityHeaders = []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"}

// httpPortOK says which explicit ports a URL may use; tests replace it.
var httpPortOK = func(p string) bool { return p == "80" || p == "443" || p == "8080" || p == "8443" }

// maxRedirects is how many redirects are followed, each one re-checked as a new, separate request.
const maxRedirects = 5

// HTTP requests "/" (or a given path) and follows up to five redirects by hand, so that every hop is
// checked against the same public-address rule. Only http and https on the usual ports, GET only,
// the body is never read, cookies are never stored and their values are never shown. Never cached.
func (t *Tool) HTTP(ctx context.Context, tg Target, scheme, path string) Envelope {
	now := t.now().UTC()
	env := Envelope{Kind: "http", Target: tg.Value, Display: tg.Display, FetchedAt: now, ExpiresAt: now, Vantage: "server"}
	if scheme != "http" {
		scheme = "https"
	}
	if path == "" || path[0] != '/' || len(path) > 200 || strings.ContainsAny(path, "\r\n \x00") {
		path = "/"
	}
	if tg.Kind != KindDomain && tg.Kind != KindIP {
		env.Sources = []Source{{Name: "http", OK: false, Error: "invalid_target"}}
		return env
	}
	host := tg.Value
	if tg.Kind == KindIP && tg.Addr.Is6() {
		host = "[" + host + "]"
	}
	if _, err := t.publicAddrs(ctx, tg); err != nil {
		env.Sources = []Source{{Name: "http", OK: false, Error: codeOf(err)}}
		return env
	}
	return t.httpFrom(ctx, tg, scheme+"://"+host+path)
}

// httpFrom inspects the chain that starts at one URL.
func (t *Tool) httpFrom(ctx context.Context, tg Target, next string) Envelope {
	now := t.now().UTC()
	env := Envelope{Kind: "http", Target: tg.Value, Display: tg.Display, FetchedAt: now, ExpiresAt: now, Vantage: "server"}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	client := &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{Proxy: nil, DialContext: guardedDialer(5 * time.Second).DialContext, TLSHandshakeTimeout: 6 * time.Second,
			ResponseHeaderTimeout: 8 * time.Second, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	res := HTTPResult{Hops: []HTTPHop{}, Security: map[string]bool{}}
	var lastErr string
	for i := 0; i <= maxRedirects && next != ""; i++ {
		u, err := url.Parse(next)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
			lastErr = "invalid_target"
			break
		}
		if p := u.Port(); p != "" && !httpPortOK(p) {
			lastErr = "port_not_allowed"
			break
		}
		// A redirect may name an internal host: refuse before connecting (the dialer checks again).
		if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
			if publicCheck(ip.Unmap()) != nil {
				lastErr = "not_public"
				break
			}
		} else if pt, perr := Parse(u.Hostname()); perr != nil || pt.Kind != KindDomain {
			lastErr = "not_public"
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			lastErr = "invalid_target"
			break
		}
		req.Header.Set("User-Agent", "Owlery-Inspector/1")
		req.Header.Set("Accept", "*/*")
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			lastErr = httpErrCode(err)
			break
		}
		hop := HTTPHop{URL: clip(u.String(), 300), Status: resp.StatusCode, Proto: resp.Proto, Ms: int(time.Since(start).Milliseconds()), Headers: map[string]string{}}
		if resp.TLS != nil {
			hop.TLS = tlsVersion(resp.TLS.Version)
		}
		keys := make([]string, 0, len(resp.Header))
		for k := range resp.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if len(hop.Headers) >= 40 {
				break
			}
			v := strings.Join(resp.Header[k], ", ")
			if strings.EqualFold(k, "Set-Cookie") {
				v = fmt.Sprintf("(%d cookie, значения не показываются)", len(resp.Header[k]))
			}
			hop.Headers[k] = clip(v, 300)
		}
		loc := resp.Header.Get("Location")
		resp.Body.Close()
		res.Final = resp.StatusCode
		res.Hops = append(res.Hops, hop)
		for _, h := range securityHeaders {
			res.Security[h] = resp.Header.Get(h) != ""
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
			if ref, err := u.Parse(loc); err == nil {
				hop.Location = clip(ref.String(), 300)
				res.Hops[len(res.Hops)-1].Location = hop.Location
				next = ref.String()
				continue
			}
		}
		next = ""
		lastErr = ""
	}
	if len(res.Hops) == 0 {
		env.Sources = []Source{{Name: "http", OK: false, Error: coalesceStr(lastErr, "unavailable")}}
		return env
	}
	src := Source{Name: "http", OK: true}
	if lastErr != "" {
		src.Error = lastErr // the chain stopped early: the hops so far are shown, with the reason
	}
	env.Sources = []Source{src}
	env.Data = res
	return env
}

func coalesceStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func httpErrCode(err error) string {
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var inv x509.CertificateInvalidError
	switch {
	case errors.Is(err, ErrNotPublic):
		return "not_public"
	case errors.As(err, &ua), errors.As(err, &hn), errors.As(err, &inv):
		return "tls_failure"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "not public") || strings.Contains(s, "не публичный"):
		return "not_public"
	case strings.Contains(s, "certificate"), strings.Contains(s, "tls:"):
		return "tls_failure"
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline"):
		return "timeout"
	case strings.Contains(s, "refused"):
		return "refused"
	case strings.Contains(s, "no such host"):
		return "not_found"
	}
	return "unavailable"
}
