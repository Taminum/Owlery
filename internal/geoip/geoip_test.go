package geoip

import (
	"bytes"
	"compress/gzip"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCountryLookup(t *testing.T) {
	db := Default()
	if len(db.v4) < 100000 || len(db.v6) < 10000 {
		t.Fatalf("the embedded table looks truncated: %d v4, %d v6", len(db.v4), len(db.v6))
	}
	for ip, want := range map[string]string{
		"8.8.8.8":        "US",
		"77.88.8.8":      "RU", // Yandex DNS
		"::ffff:8.8.8.8": "US", // an IPv4-mapped address is looked up as IPv4
		"192.168.1.5":    "",
		"10.0.0.1":       "",
		"127.0.0.1":      "",
		"198.18.0.7":     "", // the router's fake-ip range is private-use
		"169.254.1.1":    "",
		"0.0.0.0":        "",
		"224.0.0.1":      "",
		"fe80::1":        "",
	} {
		if got := db.Country(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
	if got := db.Country(netip.Addr{}); got != "" {
		t.Fatalf("zero address: %q", got)
	}
	if got := db.Country(netip.MustParseAddr("2606:4700:4700::1111")); len(got) != 2 {
		t.Fatalf("a public IPv6 address must resolve to some country: %q", got)
	}
}

func TestNameIsRussian(t *testing.T) {
	if Name("DE") != "Германия" || !strings.Contains(Name("us"), "Штаты") {
		t.Fatalf("%q %q", Name("DE"), Name("us"))
	}
	if Name("??") != "??" {
		t.Fatal("an unknown code falls back to itself")
	}
}

func TestLoadIsFast(t *testing.T) {
	start := time.Now()
	if _, err := parse(data); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("parsing took %s", d)
	}
}

// The table logic is checked against a small table of known contents, so a change in the real
// data can never hide a bug in the lookup.
func TestLookupBoundariesOnAKnownTable(t *testing.T) {
	csv := strings.Join([]string{
		"0.0.0.0,0.255.255.255,ZZ",
		"1.0.0.0,1.0.0.255,AU",
		"1.0.2.0,1.0.3.255,CN",
		"200.0.0.0,200.0.0.255,BR",
		"2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,NL",
		"2a00::,2a00::ffff,DE",
		"not,a,row",
		"1.2.3.4,1.2.3.5",
	}, "\n") + "\n"
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(csv))
	_ = zw.Close()
	db, err := parse(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]string{
		"1.0.0.0": "AU", "1.0.0.255": "AU", "1.0.1.0": "", "1.0.2.0": "CN", "1.0.3.255": "CN", "1.0.4.0": "",
		"0.0.0.1": "", "200.0.0.128": "BR", "200.0.1.0": "", "250.1.1.1": "",
		"2001:db8::1": "NL", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff": "NL", "2001:db9::": "", "2a00::8": "DE", "2a00::1:0": "", "2a01::": "",
	} {
		if got := db.Country(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
}
