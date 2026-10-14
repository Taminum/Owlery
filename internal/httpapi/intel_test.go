package httpapi

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"testing"

	"github.com/Taminum/RemnaScope/internal/netintel"
)

type noDNS struct{}

func (noDNS) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if host == "inside.example.com" {
		return []netip.Addr{netip.MustParseAddr("10.1.1.1")}, nil
	}
	return nil, &net.DNSError{IsNotFound: true}
}
func (noDNS) LookupAddr(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{IsNotFound: true}
}
func (noDNS) LookupCNAME(context.Context, string) (string, error) {
	return "", &net.DNSError{IsNotFound: true}
}
func (noDNS) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, &net.DNSError{IsNotFound: true}
}
func (noDNS) LookupNS(context.Context, string) ([]*net.NS, error) {
	return nil, &net.DNSError{IsNotFound: true}
}
func (noDNS) LookupTXT(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{IsNotFound: true}
}

func intelPath(kind, target string) string {
	return "/api/v1/intel/" + kind + "?target=" + url.QueryEscape(target)
}

func TestIntelIsOwnerOnlyAndRefusesInsideTargets(t *testing.T) {
	w := analyzerWorld(t)
	w.h.srv.Intel = &netintel.Tool{Resolver: noDNS{}}
	for _, c := range []*client{w.viewer, w.op, w.adm} {
		for _, k := range []string{"lookup", "dns", "subdomains", "ping", "ports", "trace", "tls", "http"} {
			if st, _ := c.get(intelPath(k, "example.com")); st != 403 {
				t.Errorf("%s: %d", k, st)
			}
		}
	}
	if st, _ := w.h.anon().get(intelPath("lookup", "example.com")); st != 401 {
		t.Fatalf("anonymous: %d", st)
	}
	for in, code := range map[string]string{"": "invalid_target", "not a host": "invalid_target", "router.lan": "not_public", "localhost": "not_public"} {
		st, b := w.owner.get(intelPath("lookup", in))
		if st != 422 || errCode(b) != code {
			t.Errorf("%q: %d %s", in, st, b)
		}
	}
	for _, target := range []string{"127.0.0.1", "192.168.1.1", "169.254.169.254", "inside.example.com"} {
		for _, k := range []string{"ping", "ports", "trace", "tls", "http"} {
			st, b := w.owner.get(intelPath(k, target))
			var env struct {
				Data    any `json:"data"`
				Sources []struct {
					OK    bool   `json:"ok"`
					Error string `json:"error"`
				} `json:"sources"`
			}
			_ = json.Unmarshal(b, &env)
			if st != 200 || env.Data != nil || len(env.Sources) != 1 || env.Sources[0].OK || env.Sources[0].Error != "not_public" {
				t.Errorf("%s %s: %d %s", k, target, st, b)
			}
		}
	}
	if st, _ := w.owner.get(intelPath("dns", "8.8.8.8")); st != 422 {
		t.Errorf("dns of an IP: %d", st)
	}
}

func TestIntelCIDRArithmetic(t *testing.T) {
	w := analyzerWorld(t)
	w.h.srv.Intel = &netintel.Tool{Resolver: noDNS{}}
	for in, want := range map[string]cidrOut{
		"8.8.8.77/24":    {CIDR: "8.8.8.0/24", Version: 4, First: "8.8.8.0", Last: "8.8.8.255", Addresses: "256", Netmask: "255.255.255.0", Public: true},
		"10.0.0.0/8":     {CIDR: "10.0.0.0/8", Version: 4, First: "10.0.0.0", Last: "10.255.255.255", Addresses: "16777216", Netmask: "255.0.0.0"},
		"8.8.8.8/32":     {CIDR: "8.8.8.8/32", Version: 4, First: "8.8.8.8", Last: "8.8.8.8", Addresses: "1", Netmask: "255.255.255.255", Public: true},
		"2606:4700::/32": {CIDR: "2606:4700::/32", Version: 6, First: "2606:4700::", Last: "2606:4700:ffff:ffff:ffff:ffff:ffff:ffff", Addresses: "79228162514264337593543950336", Public: true},
	} {
		st, b := w.owner.get(intelPath("lookup", in))
		var env struct {
			Data cidrOut `json:"data"`
		}
		_ = json.Unmarshal(b, &env)
		if st != 200 || env.Data != want {
			t.Errorf("%s: %d %+v want %+v", in, st, env.Data, want)
		}
	}
}
