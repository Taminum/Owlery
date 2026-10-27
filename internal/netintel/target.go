// Package netintel is the "network intelligence" part of Owlery: looking up what a domain or an
// address is on the public internet (DNS, owner, subdomains) and, on request, whether it answers.
//
// Everything here describes the view from the server Owlery runs on, never from the user's home
// or from another country, and every result carries where it came from and when. Observations of
// real traffic live elsewhere; nothing here is mixed into them.
//
// Active checks (ping, ports) only ever go to public addresses. A name is resolved first and every
// address it resolves to must be public, so a domain that points at 127.0.0.1 or the cloud metadata
// address cannot be used to reach the server's own network.
package netintel

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"

	"github.com/Taminum/Owlery/internal/safehttp"
)

type Kind string

const (
	KindDomain Kind = "domain"
	KindIP     Kind = "ip"
	KindCIDR   Kind = "cidr"
	KindASN    Kind = "asn"
)

// Target is a validated, normalised thing to look at.
type Target struct {
	Kind    Kind
	Value   string // normalised: ASCII (punycode) lower-case domain, canonical IP, canonical CIDR, "AS123"
	Display string // what to show: the domain in Unicode when it was an IDN
	Addr    netip.Addr
	Prefix  netip.Prefix
	ASN     uint32
}

// Errors carry a short code the API passes on; the text is for people.
type Error struct{ Code, Msg string }

func (e *Error) Error() string { return e.Msg }

func bad(msg string) error { return &Error{"invalid_target", msg} }

// internalSuffixes are names that never exist on the public internet.
var internalSuffixes = []string{".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".intranet", ".arpa", ".test", ".invalid", ".example"}

// Parse accepts a domain, an IP, a CIDR, an ASN ("AS15169") or a URL (only its host is used).
func Parse(raw string) (Target, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Target{}, bad("введите домен, IP, CIDR или ASN")
	}
	if len(s) > 300 {
		return Target{}, bad("слишком длинная строка")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return Target{}, bad("недопустимые символы")
		}
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return Target{}, bad("не удалось разобрать ссылку")
		}
		s = u.Hostname()
	}
	if up := strings.ToUpper(s); strings.HasPrefix(up, "AS") {
		if n, err := strconv.ParseUint(up[2:], 10, 32); err == nil && n > 0 {
			return Target{Kind: KindASN, Value: "AS" + strconv.FormatUint(n, 10), Display: "AS" + strconv.FormatUint(n, 10), ASN: uint32(n)}, nil
		}
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return Target{}, bad("некорректный CIDR")
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
		return Target{Kind: KindCIDR, Value: p.String(), Display: p.String(), Prefix: p}, nil
	}
	h := strings.TrimSuffix(strings.Trim(s, "[]"), ".")
	if a, err := netip.ParseAddr(h); err == nil {
		if a.Zone() != "" {
			return Target{}, bad("адрес с зоной не поддерживается")
		}
		a = a.Unmap()
		return Target{Kind: KindIP, Value: a.String(), Display: a.String(), Addr: a}, nil
	}
	// host:port
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[:i], ":") {
		if _, err := strconv.Atoi(h[i+1:]); err == nil {
			h = h[:i]
		}
	}
	if strings.EqualFold(h, "localhost") {
		return Target{}, &Error{"not_public", "внутреннее имя: во внешнем интернете его нет"}
	}
	ascii, err := idna.Lookup.ToASCII(strings.ToLower(h))
	if err != nil || !validDomain(ascii) {
		return Target{}, bad("введите корректный IPv4, IPv6, домен, CIDR или ASN")
	}
	for _, suf := range internalSuffixes {
		if strings.HasSuffix(ascii, suf) || ascii == strings.TrimPrefix(suf, ".") {
			return Target{}, &Error{"not_public", "внутреннее имя: во внешнем интернете его нет"}
		}
	}
	disp, err := idna.Lookup.ToUnicode(ascii)
	if err != nil {
		disp = ascii
	}
	return Target{Kind: KindDomain, Value: ascii, Display: disp}, nil
}

func validDomain(d string) bool {
	if len(d) < 3 || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	labels := strings.Split(d, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	if strings.HasPrefix(tld, "xn--") {
		return true
	}
	for _, r := range tld {
		if r < 'a' || r > 'z' {
			return false // an all-digit last label would read as an IPv4 address
		}
	}
	return len(tld) >= 2
}

// ErrNotPublic is returned by active checks for a target that is not a public address.
var ErrNotPublic = &Error{"not_public", "адрес не публичный: активные проверки идут только на публичные адреса"}

// PublicOnly reports whether an address may be probed.
func PublicOnly(a netip.Addr) error {
	if !a.IsValid() || !safehttp.PublicAddr(a.Unmap()) {
		return ErrNotPublic
	}
	return nil
}

// publicCheck is PublicOnly; only tests replace it (to reach a server on loopback).
var publicCheck = PublicOnly

// IsError unwraps the API-facing error.
func IsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
