package xraylog

import (
	"bufio"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func mustParse(t *testing.T, line string) Event {
	t.Helper()
	ev, err := ParseLine(line)
	if err != nil {
		t.Fatalf("%q: %v", line, err)
	}
	return ev
}

func TestTheLineFromTheSpec(t *testing.T) {
	ev := mustParse(t, "2026/10/09 12:03:31.803861 from 95.183.45.51:47242 accepted tcp:www.google.com:443 [Steal -> DIRECT] email: 2")
	want := time.Date(2026, 10, 9, 12, 3, 31, 803861000, time.UTC)
	if !ev.Time.Equal(want) || ev.ClientIP != netip.MustParseAddr("95.183.45.51") || ev.ClientPort != 47242 ||
		ev.Protocol != "tcp" || ev.DestHost != "www.google.com" || ev.DestPort != 443 || ev.DestIP.IsValid() ||
		ev.InboundTag != "Steal" || ev.OutboundTag != "DIRECT" || ev.Arrow != "->" || ev.Email != "2" || ev.Internal {
		t.Fatalf("%+v", ev)
	}
}

func TestObservedVariants(t *testing.T) {
	cases := map[string]func(Event) bool{
		"2026/10/09 12:00:00.000001 from 1.2.3.4:5 accepted tcp:example.org:80 [Steal >> DIRECT] email: 4":      func(e Event) bool { return e.Arrow == ">>" && e.Email == "4" },
		"2026/10/09 12:00:00.000001 from 1.2.3.4:5 accepted tcp:example.org:443 [Steal -> warp-out] email: 3":   func(e Event) bool { return e.OutboundTag == "warp-out" },
		"2026/10/09 12:00:00.000001 from 1.2.3.4:5 accepted tcp:blocked.example:443 [Steal -> BLOCK] email: 3":  func(e Event) bool { return e.OutboundTag == "BLOCK" },
		"2026/10/09 12:00:00.000001 from tcp:1.2.3.4:5 accepted tcp:example.org:443 [Steal -> DIRECT] email: 2": func(e Event) bool { return e.ClientIP == netip.MustParseAddr("1.2.3.4") && e.ClientPort == 5 },
		"2026/10/09 12:00:00.000001 from 1.2.3.4:5 accepted udp:9.9.9.9:443 [Steal >> DIRECT] email: 2": func(e Event) bool {
			return e.Protocol == "udp" && e.DestIP == netip.MustParseAddr("9.9.9.9") && e.DestHost == ""
		},
		"2026/10/09 12:00:00.000001 from 1.2.3.4:5 accepted tcp:[2001:db8::1]:443 [Steal >> DIRECT] email: 2":                      func(e Event) bool { return e.DestIP == netip.MustParseAddr("2001:db8::1") && e.DestPort == 443 },
		"2026/10/09 12:00:00.000001 from [2001:db8::7]:4000 accepted tcp:example.org:443 [Steal >> DIRECT] email: 2":               func(e Event) bool { return e.ClientIP == netip.MustParseAddr("2001:db8::7") },
		"2026/10/09 12:00:00.000001 from DNS accepted udp:9.9.9.9:53 [xray.system.00000000-0000-4000-8000-000000000000 >> DIRECT]": func(e Event) bool { return e.Internal && !e.ClientIP.IsValid() && e.Email == "" },
	}
	for line, ok := range cases {
		if ev := mustParse(t, line); !ok(ev) {
			t.Errorf("%s -> %+v", line, ev)
		}
	}
}

func TestDestinationsAreNormalisedButIPsStayIPs(t *testing.T) {
	ev := mustParse(t, "2026/10/09 12:00:00.000001 from 1.2.3.4:5 accepted tcp:WWW.Example.ORG.:443 [Steal -> DIRECT] email: 2")
	if ev.DestHost != "www.example.org" {
		t.Fatalf("%q", ev.DestHost)
	}
	ev = mustParse(t, "2026/10/09 12:00:00.000001 from 1.2.3.4:5 accepted tcp:xn--80ak6aa92e.com:443 [Steal -> DIRECT] email: 2")
	if ev.DestHost != "xn--80ak6aa92e.com" {
		t.Fatal("punycode must be preserved")
	}
	ev = mustParse(t, "2026/10/09 12:00:00.000001 from 1.2.3.4:5 accepted tcp:[::ffff:9.9.9.9]:443 [Steal -> DIRECT] email: 2")
	if ev.DestIP != netip.MustParseAddr("9.9.9.9") || ev.DestHost != "" {
		t.Fatalf("v4-mapped: %+v", ev)
	}
}

func TestMalformedLinesAreRefusedWithoutEchoingThem(t *testing.T) {
	bad := []string{
		"", "garbage", "2026/10/09 12:00:00.000001",
		"2026/13/40 25:00:00.000001 from 1.2.3.4:5 accepted tcp:a.example:80 [Steal -> DIRECT] email: 2",
		"2026/10/09 12:00:00.000001 from 1.2.3.4 accepted tcp:a.example:80 [Steal -> DIRECT] email: 2",
		"2026/10/09 12:00:00.000001 from 1.2.3.4:5 rejected tcp:a.example:80 [Steal -> DIRECT] email: 2",
		"2026/10/09 12:00:00.000001 from 1.2.3.4:5 accepted icmp:a.example:80 [Steal -> DIRECT] email: 2",
		"2026/10/09 12:00:00.000001 from 1.2.3.4:5 accepted tcp:a.example [Steal -> DIRECT] email: 2",
		"2026/10/09 12:00:00.000001 from 1.2.3.4:5 accepted tcp:a.example:99999 [Steal -> DIRECT] email: 2",
		"2026/10/09 12:00:00.000001 from 1.2.3.4:5 accepted tcp:a.example:80 [Steal => DIRECT] email: 2",
		"2026/10/09 12:00:00.000001 from 1.2.3.4:5 accepted tcp:a.example:80 [Steal -> DIRECT",
		"2026/10/09 12:00:00.000001 from 1.2.3.4:5 accepted tcp:a.example:80 [Steal -> DIRECT] email:",
		"2026/10/09 12:00:00.000001 from 1.2.3.4:5 accepted tcp:a.example:80 [Steal -> DIRECT] email: 2 extra",
		"2026/10/09 12:00:00.000001 from 1.2.3.4:5 accepted tcp:[::1:80 [Steal -> DIRECT] email: 2",
		"2026/10/09 12:00:00.000001 from 1.2.3.4:5 accepted tcp::80 [Steal -> DIRECT] email: 2",
		strings.Repeat("x", 5000),
	}
	for _, l := range bad {
		ev, err := ParseLine(l)
		if err == nil {
			t.Errorf("should fail: %.80q -> %+v", l, ev)
			continue
		}
		if !IsParseError(err) {
			t.Errorf("not a ParseError: %v", err)
		}
		if strings.Contains(err.Error(), "example") || strings.Contains(err.Error(), "1.2.3.4") {
			t.Errorf("error text contains line content: %v", err)
		}
	}
}

func TestParserNeverPanicsOnArbitraryInput(t *testing.T) {
	seeds := []string{"2026/10/09 12:00:00.000001 from 1.2.3.4:5 accepted tcp:a.example:80 [Steal -> DIRECT] email: 2", "[", "]", " ", "from", "accepted tcp:", "\x00\xff\xfe"}
	for _, s := range seeds {
		for i := 0; i <= len(s); i++ {
			_, _ = ParseLine(s[:i])
			_, _ = ParseLine(s[i:])
			_, _ = ParseLine(s[:i] + "[" + s[i:])
		}
	}
}

func TestSanitisedRealSampleParsesCompletely(t *testing.T) {
	f, err := os.Open("testdata/sample_sanitized.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var n, internal, noEmail, v6dest, udp, arrows int
	seenArrow := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ev, err := ParseLine(sc.Text())
		if err != nil {
			t.Fatalf("line %d: %v", n+1, err)
		}
		n++
		if ev.Internal {
			internal++
			if ev.ClientIP.IsValid() || ev.Email != "" {
				t.Errorf("internal event carries a client or email: %+v", ev)
			}
		}
		if ev.Email == "" {
			noEmail++
		}
		if ev.DestIP.Is6() {
			v6dest++
		}
		if ev.Protocol == "udp" {
			udp++
		}
		seenArrow[ev.Arrow] = true
	}
	arrows = len(seenArrow)
	if n != 120 || internal == 0 || noEmail != internal || v6dest == 0 || udp == 0 || arrows != 2 {
		t.Fatalf("n=%d internal=%d noEmail=%d v6=%d udp=%d arrows=%d", n, internal, noEmail, v6dest, udp, arrows)
	}
}

func TestFixtureHoldsNoRealLookingData(t *testing.T) {
	b, _ := os.ReadFile("testdata/sample_sanitized.log")
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		ev, err := ParseLine(l)
		if err != nil {
			t.Fatal(err)
		}
		if ev.ClientIP.IsValid() && !netip.MustParsePrefix("198.51.100.0/24").Contains(ev.ClientIP) {
			t.Fatalf("client outside the documentation range: %v", ev.ClientIP)
		}
		if ev.DestHost != "" && !strings.HasSuffix(ev.DestHost, ".example.test") && !strings.HasPrefix(ev.DestHost, "host") {
			t.Fatalf("real-looking destination: %q", ev.DestHost)
		}
		if ev.DestIP.IsValid() && !netip.MustParsePrefix("192.0.2.0/24").Contains(ev.DestIP) && !netip.MustParsePrefix("2001:db8::/32").Contains(ev.DestIP) {
			t.Fatalf("destination IP outside documentation ranges: %v", ev.DestIP)
		}
	}
}
