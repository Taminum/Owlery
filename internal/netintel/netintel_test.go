package netintel

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseNormalisesAndRejects(t *testing.T) {
	ok := map[string]struct {
		kind  Kind
		value string
	}{
		"Example.COM":                     {KindDomain, "example.com"},
		"example.com.":                    {KindDomain, "example.com"},
		"https://www.Example.com/a/b?q=1": {KindDomain, "www.example.com"},
		"example.com:8443":                {KindDomain, "example.com"},
		"пример.рф":                       {KindDomain, "xn--e1afmkfd.xn--p1ai"},
		"8.8.8.8":                         {KindIP, "8.8.8.8"},
		"2001:4860:4860:0:0:0:0:8888":     {KindIP, "2001:4860:4860::8888"},
		"[2001:db8::1]":                   {KindIP, "2001:db8::1"},
		"::ffff:1.2.3.4":                  {KindIP, "1.2.3.4"},
		"10.1.2.3/8":                      {KindCIDR, "10.0.0.0/8"},
		"2001:db8::/32":                   {KindCIDR, "2001:db8::/32"},
		"as15169":                         {KindASN, "AS15169"},
		"  AS 15169  ":                    {},
		"":                                {},
		"localhost":                       {},
		"router.lan":                      {},
		"printer.local":                   {},
		"a b.com":                         {},
		"-bad.com":                        {},
		"exa mple.com":                    {},
		"1.2.3.4.5":                       {},
		"999.1.1.1":                       {},
		"example.com/path":                {},
		"fe80::1%eth0":                    {},
		"http://":                         {},
		"example.com\x00evil":             {},
		strings.Repeat("a", 64) + ".com":  {},
		strings.Repeat("a.", 130) + "com": {},
	}
	for in, want := range ok {
		got, err := Parse(in)
		if want.kind == "" {
			if err == nil {
				t.Errorf("%q was accepted as %v %q", in, got.Kind, got.Value)
			}
			continue
		}
		if err != nil || got.Kind != want.kind || got.Value != want.value {
			t.Errorf("%q -> %v %q err %v, want %v %q", in, got.Kind, got.Value, err, want.kind, want.value)
		}
	}
	if tg, _ := Parse("пример.рф"); tg.Display != "пример.рф" {
		t.Errorf("display %q", tg.Display)
	}
}

func TestOnlyPublicAddressesMayBeProbed(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.5.5", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fc00::1", "224.0.0.1", "::ffff:127.0.0.1"} {
		if err := PublicOnly(netip.MustParseAddr(s)); err == nil {
			t.Errorf("%s may be probed", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if err := PublicOnly(netip.MustParseAddr(s)); err != nil {
			t.Errorf("%s refused: %v", s, err)
		}
	}
}

// fakeDNS answers from a table.
type fakeDNS struct {
	ips   map[string][]string
	calls int
}

func (f *fakeDNS) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	f.calls++
	var out []netip.Addr
	for _, s := range f.ips[host] {
		a := netip.MustParseAddr(s)
		if network == "ip4" && !a.Is4() || network == "ip6" && !a.Is6() {
			continue
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return out, nil
}
func (f *fakeDNS) LookupAddr(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{IsNotFound: true}
}
func (f *fakeDNS) LookupCNAME(context.Context, string) (string, error) {
	return "", &net.DNSError{IsNotFound: true}
}
func (f *fakeDNS) LookupMX(context.Context, string) ([]*net.MX, error) {
	return []*net.MX{{Host: "b.mail.example.com.", Pref: 20}, {Host: "a.mail.example.com.", Pref: 10}}, nil
}
func (f *fakeDNS) LookupNS(context.Context, string) ([]*net.NS, error) {
	return []*net.NS{{Host: "ns2.example.com."}, {Host: "ns1.example.com."}}, nil
}
func (f *fakeDNS) LookupTXT(context.Context, string) ([]string, error) {
	return []string{"v=spf1 -all"}, nil
}

func mustTarget(t *testing.T, s string) Target {
	t.Helper()
	tg, err := Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func TestActiveChecksRefuseNamesThatPointInside(t *testing.T) {
	dns := &fakeDNS{ips: map[string][]string{
		"evil.example.com":  {"127.0.0.1"},
		"mixed.example.com": {"8.8.8.8", "10.0.0.5"},
		"meta.example.com":  {"169.254.169.254"},
	}}
	tool := &Tool{Resolver: dns}
	for _, name := range []string{"evil.example.com", "mixed.example.com", "meta.example.com"} {
		for kind, env := range map[string]Envelope{
			"ping":  tool.Ping(context.Background(), mustTarget(t, name), 1),
			"ports": tool.Ports(context.Background(), mustTarget(t, name), []int{22, 80}),
		} {
			if len(env.Sources) != 1 || env.Sources[0].OK || env.Sources[0].Error != "not_public" || env.Data != nil {
				t.Errorf("%s %s: %+v", kind, name, env)
			}
		}
	}
	for _, ip := range []string{"127.0.0.1", "192.168.1.1", "169.254.169.254"} {
		if env := tool.Ports(context.Background(), mustTarget(t, ip), []int{22}); env.Data != nil || env.Sources[0].Error != "not_public" {
			t.Errorf("ports %s: %+v", ip, env)
		}
		if env := tool.Ping(context.Background(), mustTarget(t, ip), 1); env.Data != nil || env.Sources[0].Error != "not_public" {
			t.Errorf("ping %s: %+v", ip, env)
		}
	}
	if env := tool.Ping(context.Background(), mustTarget(t, "10.0.0.0/8"), 1); env.Data != nil {
		t.Error("a CIDR was pinged")
	}
}

func TestRecordsAreSortedAndCachedUntilRefreshed(t *testing.T) {
	dns := &fakeDNS{ips: map[string][]string{"example.com": {"93.184.216.34", "2606:2800::1"}}}
	clock := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	tool := &Tool{Resolver: dns, Now: func() time.Time { return clock }}
	tg := mustTarget(t, "example.com")
	env := tool.Records(context.Background(), tg, false)
	rec := env.Data.(DNSRecords)
	if rec.A[0] != "93.184.216.34" || rec.AAAA[0] != "2606:2800::1" || rec.MX[0].Host != "a.mail.example.com" || rec.NS[0] != "ns1.example.com" || rec.TXT[0] != "v=spf1 -all" {
		t.Fatalf("%+v", rec)
	}
	if env.Cached || env.Vantage != "server" || !env.ExpiresAt.After(env.FetchedAt) {
		t.Fatalf("%+v", env)
	}
	calls := dns.calls
	if e := tool.Records(context.Background(), tg, false); !e.Cached || dns.calls != calls {
		t.Fatal("not served from the cache")
	}
	if e := tool.Records(context.Background(), tg, true); e.Cached || dns.calls == calls {
		t.Fatal("refresh was ignored")
	}
	clock = clock.Add(11 * time.Minute)
	calls = dns.calls
	if e := tool.Records(context.Background(), tg, false); e.Cached || dns.calls == calls {
		t.Fatal("an expired result was served")
	}
}

func TestPrivateAddressesGetNoOutsideRequests(t *testing.T) {
	tool := &Tool{} // no client at all: any outside request would fail loudly
	env := tool.IP(context.Background(), mustTarget(t, "192.168.1.10"), false)
	info := env.Data.(IPInfo)
	if info.Public || info.RDAP != nil || len(env.Sources) != 1 || env.Sources[0].Name != "local" {
		t.Fatalf("%+v", env)
	}
}

func TestSubdomainNamesAreKeptOnlyIfTheyBelongToTheDomain(t *testing.T) {
	for in, want := range map[string]string{
		"www.example.com":       "www.example.com",
		"EXAMPLE.COM":           "example.com",
		"a.b.example.com":       "a.b.example.com",
		"*.example.com":         "",
		"notexample.com":        "",
		"example.com.evil.net":  "",
		"evil.com":              "",
		"x y.example.com":       "",
		"bad_name.example.com":  "",
		"":                      "",
		"a.example.com\nb.evil": "",
	} {
		got, ok := keepName(in, "example.com")
		if (want == "") == ok || got != want {
			t.Errorf("%q -> %q %v", in, got, ok)
		}
	}
}

func TestFailedLookupsAreNotCached(t *testing.T) {
	tool := &Tool{}
	n := 0
	tg := mustTarget(t, "example.com")
	run := func() Envelope {
		return tool.cachedRun("x", tg, time.Hour, false, func() (any, []Source) {
			n++
			return nil, []Source{{Name: "a", OK: false, Error: "timeout"}}
		})
	}
	run()
	run()
	if n != 2 {
		t.Fatalf("a total failure was cached (%d runs)", n)
	}
}

func TestErrorsNeverCarryProviderText(t *testing.T) {
	if c := errCode(&net.DNSError{Err: "secret resolver text 10.0.0.53", IsTimeout: true}); c != "timeout" {
		t.Fatal(c)
	}
	if c := errCode(context.DeadlineExceeded); c != "timeout" {
		t.Fatal(c)
	}
	if c := errCode(net.ErrClosed); c != "unavailable" || strings.Contains(c, "closed") {
		t.Fatal(c)
	}
}

func TestTraceStopsAtTheDestinationAndShowsSilentHops(t *testing.T) {
	tool := &Tool{Resolver: &fakeDNS{}}
	dst := netip.MustParseAddr("8.8.8.8")
	probe := func(_ context.Context, d netip.Addr, ttl, seq int) (netip.Addr, time.Duration, bool, bool) {
		switch ttl {
		case 1:
			return netip.MustParseAddr("192.168.1.1"), time.Millisecond, false, true
		case 2: // a router that never answers
			return netip.Addr{}, 0, false, false
		case 3:
			if seq%10 == 0 { // one probe of three is lost
				return netip.Addr{}, 0, false, false
			}
			return netip.MustParseAddr("62.1.2.3"), 7 * time.Millisecond, false, true
		default:
			return d, 20 * time.Millisecond, true, true
		}
	}
	env := tool.trace(context.Background(), mustTarget(t, "8.8.8.8"), probe)
	res, ok := env.Data.(TraceResult)
	if !ok || !res.Reached || len(res.Hops) != 4 || res.Address != dst.String() {
		t.Fatalf("%+v", env)
	}
	if res.Hops[1].Addr != "" || res.Hops[1].Lost != 3 || len(res.Hops[1].RTTms) != 0 {
		t.Fatalf("a silent hop: %+v", res.Hops[1])
	}
	if h := res.Hops[2]; h.Lost != 1 || len(h.RTTms) != 2 || h.Addr != "62.1.2.3" {
		t.Fatalf("a hop with a lost probe: %+v", h)
	}
	if !res.Hops[3].Reached || res.Hops[3].Addr != "8.8.8.8" {
		t.Fatalf("%+v", res.Hops[3])
	}
}

func TestTraceRefusesInsideTargetsAndIPv6(t *testing.T) {
	probe := func(context.Context, netip.Addr, int, int) (netip.Addr, time.Duration, bool, bool) {
		t.Error("a probe was sent")
		return netip.Addr{}, 0, false, false
	}
	tool := &Tool{Resolver: &fakeDNS{ips: map[string][]string{"in.example.com": {"10.0.0.1"}}}}
	for _, s := range []string{"127.0.0.1", "10.1.1.1", "in.example.com"} {
		if env := tool.trace(context.Background(), mustTarget(t, s), probe); env.Data != nil || env.Sources[0].Error != "not_public" {
			t.Errorf("%s: %+v", s, env)
		}
	}
	tool = &Tool{Resolver: &fakeDNS{}}
	if env := tool.trace(context.Background(), mustTarget(t, "2606:4700:4700::1111"), probe); env.Data != nil || env.Sources[0].Error != "unsupported" {
		t.Errorf("ipv6: %+v", env)
	}
}
