package asn

import (
	"bytes"
	"compress/gzip"
	"net/netip"
	"strings"
	"testing"
)

func TestKnownOwnersInTheEmbeddedTable(t *testing.T) {
	db := Default()
	if len(db.v4) < 100000 || len(db.v6) < 10000 || len(db.orgs) < 10000 {
		t.Fatalf("the embedded table looks truncated: %d v4, %d v6, %d orgs", len(db.v4), len(db.v6), len(db.orgs))
	}
	for ip, want := range map[string]uint32{"1.1.1.1": 13335, "8.8.8.8": 15169, "::ffff:8.8.8.8": 15169} {
		o, ok := db.Lookup(netip.MustParseAddr(ip))
		if !ok || o.ASN != want || o.Org == "" {
			t.Errorf("%s: %+v %v, want AS%d", ip, o, ok, want)
		}
	}
	if o, _ := db.Lookup(netip.MustParseAddr("1.1.1.1")); !strings.Contains(o.Org, "Cloudflare") {
		t.Fatalf("org names with commas must survive the quoting: %q", o.Org)
	}
	for _, ip := range []string{"192.168.1.5", "10.0.0.1", "127.0.0.1", "198.18.0.7", "169.254.1.1", "0.0.0.0", "224.0.0.1", "fe80::1"} {
		if _, ok := db.Lookup(netip.MustParseAddr(ip)); ok {
			t.Errorf("%s must have no owner", ip)
		}
	}
	if _, ok := db.Lookup(netip.Addr{}); ok {
		t.Fatal("zero address")
	}
}

// The lookup logic is checked on a small table whose contents are known.
func TestLookupBoundariesOnAKnownTable(t *testing.T) {
	csv := strings.Join([]string{
		`1.0.0.0,1.0.0.255,13335,"Cloudflare, Inc."`,
		`1.0.2.0,1.0.3.255,64500,Example Net`,
		`1.0.4.0,1.0.4.255,0,Nobody`,
		`200.0.0.0,200.0.0.255,64501,"Quoted ""Name"", Ltd"`,
		`2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,64502,V6 Net`,
		`bad,row`,
		`x,y,notanumber,Org`,
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
		"1.0.0.0": "13335 Cloudflare, Inc.", "1.0.0.255": "13335 Cloudflare, Inc.", "1.0.1.0": "", "1.0.2.0": "64500 Example Net", "1.0.3.255": "64500 Example Net",
		"1.0.4.7": "", "200.0.0.9": `64501 Quoted "Name", Ltd`, "250.0.0.1": "", "2001:db8::1": "64502 V6 Net", "2001:db9::": "",
	} {
		o, ok := db.Lookup(netip.MustParseAddr(ip))
		got := ""
		if ok {
			got = strings.TrimSpace(itoa(o.ASN) + " " + o.Org)
		}
		if got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
}

func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
