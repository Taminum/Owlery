// Package safehttp is the only way RemnaScope talks to an operator-supplied URL.
//
// Every connection (not just the first one) resolves the host, validates ALL
// returned addresses against a deny list, and dials the validated IP directly, so
// a DNS answer that changes between "check" and "use" (rebinding) cannot reach an
// internal address. Redirects are never followed, response size and time are
// bounded, ambient proxy settings are ignored, and there is no switch to skip TLS
// verification.
package safehttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Error codes shown to operators; they never contain addresses, tokens or response bodies.
const (
	CodeInvalidURL    = "invalid_url"
	CodeUnsafeTarget  = "unsafe_target"
	CodeDNS           = "dns_failure"
	CodeConnect       = "connect_failed"
	CodeTLS           = "tls_failure"
	CodeTimeout       = "timeout"
	CodeRedirect      = "redirect_blocked"
	CodeTooLarge      = "response_too_large"
	CodeRequestFailed = "request_failed"
)

type Error struct {
	Code string
	msg  string
	// Location is the redirect target when Code is redirect_blocked. It is for callers that decide for
	// themselves to follow one more hop; it is never shown to operators.
	Location string
}

func (e *Error) Error() string { return e.msg }

func newErr(code, format string, a ...any) *Error {
	return &Error{Code: code, msg: fmt.Sprintf(format, a...)}
}

// CodeOf extracts the operator-facing code from any error produced here.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeRequestFailed
}

type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type Policy struct {
	// AllowedPorts defaults to {443}.
	AllowedPorts []int
	// AllowedPrivateHosts are exact hostnames an admin approved to resolve to private
	// (RFC1918 / ULA / CGNAT) space. Loopback, link-local, metadata, multicast and
	// reserved ranges stay blocked even for these.
	AllowedPrivateHosts []string
	// ExtraCAPEM is an admin-managed CA bundle added to the system roots, used only
	// when a panel is flagged to use it. It comes from a file on the server, never
	// from the browser.
	ExtraCAPEM []byte
	// MaxBody caps the bytes read from a response (default 8 MiB).
	MaxBody int64
	// Timeout caps one whole request (default 20s).
	Timeout  time.Duration
	Resolver Resolver

	// dialFn replaces the final TCP dial. In-package tests only.
	dialFn func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (p *Policy) withDefaults() Policy {
	c := *p
	if len(c.AllowedPorts) == 0 {
		c.AllowedPorts = []int{443}
	}
	if c.MaxBody <= 0 {
		c.MaxBody = 8 << 20
	}
	if c.Timeout <= 0 {
		c.Timeout = 20 * time.Second
	}
	if c.Resolver == nil {
		c.Resolver = net.DefaultResolver
	}
	return c
}

func (p *Policy) portAllowed(port int) bool {
	for _, a := range p.AllowedPorts {
		if a == port {
			return true
		}
	}
	return false
}

func (p *Policy) privateHost(host string) bool {
	host = strings.ToLower(host)
	for _, h := range p.AllowedPrivateHosts {
		if strings.ToLower(h) == host {
			return true
		}
	}
	return false
}

var letterRe = regexp.MustCompile(`[a-z]`)
var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var pathRe = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)*/?$`)

// ParseBaseURL validates an operator-supplied panel URL and returns it normalised
// (lower-case host, no trailing slash). It performs no network access.
func ParseBaseURL(raw string, p *Policy) (*url.URL, error) { return parseURL(raw, p, false) }

// ValidateRequestURL applies the same rules to a full request URL: identical except
// that a query string is allowed (the adapter paginates with ?start=&size=).
func ValidateRequestURL(raw string, p *Policy) error {
	_, err := parseURL(raw, p, true)
	return err
}

func parseURL(raw string, p *Policy, allowQuery bool) (*url.URL, error) {
	pol := p.withDefaults()
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 512 || strings.ContainsAny(raw, " \t\r\n\\") {
		return nil, newErr(CodeInvalidURL, "URL is empty, too long or has forbidden characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, newErr(CodeInvalidURL, "URL cannot be parsed")
	}
	switch {
	case u.Scheme != "https":
		return nil, newErr(CodeInvalidURL, "only https:// URLs are accepted")
	case u.User != nil:
		return nil, newErr(CodeInvalidURL, "credentials in the URL are not allowed")
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return nil, newErr(CodeInvalidURL, "fragments are not allowed")
	case !allowQuery && (u.RawQuery != "" || strings.Contains(raw, "?")):
		return nil, newErr(CodeInvalidURL, "query strings are not allowed")
	case allowQuery && len(u.RawQuery) > 1024:
		return nil, newErr(CodeInvalidURL, "query string is too long")
	case u.Opaque != "" || u.Hostname() == "":
		return nil, newErr(CodeInvalidURL, "URL has no host")
	case strings.Contains(u.Path, "//") || strings.Contains(u.Path, ".."):
		return nil, newErr(CodeInvalidURL, "unexpected path")
	case !pathRe.MatchString(u.Path):
		return nil, newErr(CodeInvalidURL, "unexpected path")
	}

	host := strings.ToLower(u.Hostname())
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if reason := classify(ip, pol.privateHost(host)); reason != "" {
			return nil, newErr(CodeUnsafeTarget, "target address is not allowed")
		}
	} else {
		if len(host) > 253 || !strings.Contains(host, ".") {
			return nil, newErr(CodeInvalidURL, "host must be a fully qualified domain name")
		}
		labels := strings.Split(strings.TrimSuffix(host, "."), ".")
		for _, l := range labels {
			if !labelRe.MatchString(l) {
				return nil, newErr(CodeInvalidURL, "host contains forbidden characters")
			}
		}
		// A real TLD always contains a letter. Rejecting numeric/hex final labels keeps
		// legacy IPv4 spellings ("127.1", "0x7f.0.0.1") from being resolved by libc as addresses.
		if !letterRe.MatchString(labels[len(labels)-1]) {
			return nil, newErr(CodeInvalidURL, "host must end in a valid top-level domain")
		}
	}

	port := 443
	if ps := u.Port(); ps != "" {
		n, err := strconv.Atoi(ps)
		if err != nil || n < 1 || n > 65535 {
			return nil, newErr(CodeInvalidURL, "invalid port")
		}
		port = n
	}
	if !pol.portAllowed(port) {
		return nil, newErr(CodeUnsafeTarget, "port is not allowed")
	}

	u.Host = host
	if port != 443 {
		u.Host = net.JoinHostPort(host, strconv.Itoa(port))
	}
	if !allowQuery {
		u.Path = strings.TrimRight(u.Path, "/")
	}
	u.RawPath = ""
	return u, nil
}

var (
	// Never reachable, whatever the admin allow-list says.
	hardBlocked = mustPrefixes(
		"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32", "2001:db8::/32",
		"2002::/16", "fe80::/10", "fec0::/10", "ff00::/8",
	)
	// Reachable only for hostnames the admin explicitly approved.
	privateRanges = mustPrefixes("10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, v := range s {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}

// classify returns "" when the address may be dialled, or a short reason.
func classify(a netip.Addr, privateOK bool) string {
	a = a.Unmap()
	if !a.IsValid() {
		return "invalid"
	}
	if a.IsUnspecified() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() {
		return "blocked range"
	}
	for _, p := range hardBlocked {
		if p.Contains(a) {
			return "blocked range"
		}
	}
	for _, p := range privateRanges {
		if p.Contains(a) {
			if privateOK {
				return ""
			}
			return "private range"
		}
	}
	if !a.IsGlobalUnicast() {
		return "not global unicast"
	}
	return ""
}

// Client is an SSRF-hardened HTTPS GET client bound to one Policy.
type Client struct {
	pol  Policy
	http *http.Client
}

type Response struct {
	Status int
	Body   []byte
}

// New builds a client. useExtraCA adds Policy.ExtraCA to the trust store for this client only.
func New(p Policy, useExtraCA bool) *Client {
	pol := p.withDefaults()
	c := &Client{pol: pol}

	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if useExtraCA && len(pol.ExtraCAPEM) > 0 {
		roots = roots.Clone()
		roots.AppendCertsFromPEM(pol.ExtraCAPEM)
	}

	tr := &http.Transport{
		Proxy:                 nil, // never honour HTTP(S)_PROXY from the environment
		DialContext:           c.dial,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: 12 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		DisableCompression:    false,
	}
	c.http = &http.Client{
		Transport:     tr,
		Timeout:       pol.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c
}

// ValidateCAPEM reports whether an admin-managed bundle contains at least one certificate.
func ValidateCAPEM(pem []byte) error {
	if !x509.NewCertPool().AppendCertsFromPEM(pem) {
		return errors.New("safehttp: no valid certificates in CA bundle")
	}
	return nil
}

func (c *Client) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, newErr(CodeInvalidURL, "bad address")
	}
	port, _ := strconv.Atoi(portStr)
	if !c.pol.portAllowed(port) {
		return nil, newErr(CodeUnsafeTarget, "port is not allowed")
	}
	ips, err := c.resolveAndCheck(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		target := net.JoinHostPort(ip.String(), portStr)
		var conn net.Conn
		if c.pol.dialFn != nil {
			conn, err = c.pol.dialFn(ctx, network, target)
		} else {
			d := net.Dialer{Timeout: 5 * time.Second}
			conn, err = d.DialContext(ctx, "tcp", target)
		}
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if errors.Is(lastErr, context.DeadlineExceeded) {
		return nil, newErr(CodeTimeout, "connection timed out")
	}
	return nil, newErr(CodeConnect, "could not connect")
}

// resolveAndCheck resolves host and rejects it if ANY returned address is unsafe.
func (c *Client) resolveAndCheck(ctx context.Context, host string) ([]netip.Addr, error) {
	privOK := c.pol.privateHost(host)
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if classify(ip, privOK) != "" {
			return nil, newErr(CodeUnsafeTarget, "target address is not allowed")
		}
		return []netip.Addr{ip.Unmap()}, nil
	}
	ips, err := c.pol.Resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, newErr(CodeTimeout, "DNS lookup timed out")
		}
		return nil, newErr(CodeDNS, "host name could not be resolved")
	}
	for _, ip := range ips {
		if classify(ip, privOK) != "" {
			return nil, newErr(CodeUnsafeTarget, "target address is not allowed")
		}
	}
	return ips, nil
}

// Get performs one GET. header values are sent as-is; callers pass the bearer token here.
// The returned error never includes header values.
func (c *Client) Get(ctx context.Context, rawURL string, header http.Header) (*Response, error) {
	u, err := parseURL(rawURL, &c.pol, true)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, newErr(CodeInvalidURL, "bad request")
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Accept", "application/json")
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "RemnaScope")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, mapTransportErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		e := newErr(CodeRedirect, "the server answered with a redirect, which is never followed")
		e.Location = resp.Header.Get("Location")
		return nil, e
	}
	if resp.ContentLength > c.pol.MaxBody {
		return nil, newErr(CodeTooLarge, "response is larger than the allowed limit")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.pol.MaxBody+1))
	if err != nil {
		return nil, mapTransportErr(err)
	}
	if int64(len(body)) > c.pol.MaxBody {
		return nil, newErr(CodeTooLarge, "response is larger than the allowed limit")
	}
	return &Response{Status: resp.StatusCode, Body: body}, nil
}

func mapTransportErr(err error) error {
	var se *Error
	if errors.As(err, &se) {
		return se
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return newErr(CodeTimeout, "request timed out")
	}
	var certErr *tls.CertificateVerificationError
	var unk x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invErr x509.CertificateInvalidError
	var recErr tls.RecordHeaderError
	if errors.As(err, &certErr) || errors.As(err, &unk) || errors.As(err, &hostErr) || errors.As(err, &invErr) || errors.As(err, &recErr) ||
		strings.Contains(err.Error(), "tls:") || strings.Contains(err.Error(), "x509:") {
		return newErr(CodeTLS, "TLS verification failed")
	}
	return newErr(CodeRequestFailed, "request failed")
}

// PublicAddr reports whether an address is one the server may connect to on a user's behalf: a
// public, globally routable one. Anything private, local or reserved is refused.
func PublicAddr(a netip.Addr) bool { return classify(a, false) == "" }
