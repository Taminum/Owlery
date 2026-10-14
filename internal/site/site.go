// Package site folds a host name into the "site" it belongs to: the registrable domain
// (example.co.uk for cdn.images.example.co.uk), using the public suffix list. A host that
// has no registrable domain (a bare TLD, a private name) is its own site. An IP address is not
// a site at all and gives "".
package site

import (
	"net/netip"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Of returns the site of a host, lower-cased and without a trailing dot. It never returns an
// empty string for a non-empty host name, so a result can be stored and compared safely.
func Of(host string) string {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return ""
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return "" // an IP address is not a site
	}
	if s, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil && s != "" {
		return s
	}
	return h
}
