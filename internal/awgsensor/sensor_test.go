package awgsensor

import (
	"encoding/binary"
	"math/rand"
	"net/netip"
	"testing"
	"time"
)

func ipv4(src, dst string, proto byte, l4 []byte) []byte {
	b := make([]byte, 20+len(l4))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8], b[9] = 64, proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	copy(b[20:], l4)
	return b
}

func tcp(sport, dport uint16, flags byte, payload []byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h, sport)
	binary.BigEndian.PutUint16(h[2:], dport)
	h[12] = 5 << 4
	h[13] = flags
	return append(h, payload...)
}

func udp(sport, dport uint16, payload []byte) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h, sport)
	binary.BigEndian.PutUint16(h[2:], dport)
	binary.BigEndian.PutUint16(h[4:], uint16(8+len(payload)))
	return append(h, payload...)
}

func clientHello(host string) []byte {
	var ext []byte
	if host != "" {
		name := []byte(host)
		sn := append([]byte{0}, binary.BigEndian.AppendUint16(nil, uint16(len(name)))...)
		sn = append(sn, name...)
		list := binary.BigEndian.AppendUint16(nil, uint16(len(sn)))
		list = append(list, sn...)
		ext = binary.BigEndian.AppendUint16(nil, 0)
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(list)))
		ext = append(ext, list...)
	}
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)                            // session id
	body = append(body, 0, 4, 0x13, 0x01, 0x13, 0x02) // cipher suites
	body = append(body, 1, 0)                         // compression
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{22, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func dnsResponse(name string, addrs ...string) []byte {
	var q []byte
	for _, l := range splitDots(name) {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	h := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, byte(len(addrs)), 0, 0, 0, 0}
	out := append(h, q...)
	for _, a := range addrs {
		ip := netip.MustParseAddr(a).As4()
		out = append(out, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
		out = append(out, ip[:]...)
	}
	return out
}

func splitDots(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == '.' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	return append(out, cur)
}

var t0 = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func TestSNIHostAndDNSAreReadFromRealShapes(t *testing.T) {
	if got := SNI(clientHello("Example.COM")); got != "example.com" {
		t.Fatalf("sni %q", got)
	}
	if got := SNI(clientHello("")); got != "" {
		t.Fatalf("a hello without a name gave %q", got)
	}
	if got := HTTPHost([]byte("GET / HTTP/1.1\r\nUser-Agent: x\r\nHost: Files.Example.org:8080\r\n\r\n")); got != "files.example.org" {
		t.Fatalf("host %q", got)
	}
	name, addrs := DNSAnswer(dnsResponse("cdn.example.net", "93.184.216.34", "93.184.216.35"))
	if name != "cdn.example.net" || len(addrs) != 2 || addrs[0] != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("%q %v", name, addrs)
	}
	for _, bad := range []string{"exa mple.com", "ex\x00.com", "-.", "a..b", ".lead"} {
		if got := SNI(clientHello(bad)); got != "" {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
	if n, _ := DNSAnswer([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}); n != "" {
		t.Fatal("a DNS query was read as an answer")
	}
}

func TestFlowsCountBytesPerDeviceAndDirectionAndNameThemBySNIHostOrDNS(t *testing.T) {
	a := New()
	c1, c2 := "10.8.1.2", "10.8.1.4"
	a.Add(FromClient, ipv4(c1, "1.2.3.4", 6, tcp(40000, 443, 0x02, nil)), t0)
	a.Add(FromClient, ipv4(c1, "1.2.3.4", 6, tcp(40000, 443, 0x18, clientHello("site.example"))), t0)
	a.Add(ToClient, ipv4("1.2.3.4", c1, 6, tcp(443, 40000, 0x10, make([]byte, 1000))), t0)
	a.Add(FromClient, ipv4(c2, "5.6.7.8", 6, tcp(41000, 80, 0x18, []byte("GET /x HTTP/1.1\r\nHost: plain.example\r\n\r\n"))), t0)
	// a DNS answer to the second device names a later flow that has no SNI of its own
	a.Add(ToClient, ipv4("1.1.1.1", c2, 17, udp(53, 5353, dnsResponse("viaDNS.example", "9.9.9.9"))), t0)
	a.Add(FromClient, ipv4(c2, "9.9.9.9", 6, tcp(42000, 8443, 0x18, []byte("opaque"))), t0.Add(time.Second))
	// another device reaching the same address gets no borrowed name
	a.Add(FromClient, ipv4(c1, "9.9.9.9", 6, tcp(43000, 8443, 0x18, []byte("opaque"))), t0.Add(time.Second))
	got := map[string]Flow{}
	for _, f := range a.Flush(t0.Add(time.Minute)) {
		got[f.Client.String()+">"+f.Remote.String()] = f
	}
	f := got[c1+">1.2.3.4"]
	if f.Name != "site.example" || f.How != HowSNI || f.Port != 443 || f.Down < 1000 || f.Up == 0 {
		t.Fatalf("%+v", f)
	}
	if f := got[c2+">5.6.7.8"]; f.Name != "plain.example" || f.How != HowHost {
		t.Fatalf("%+v", f)
	}
	if f := got[c2+">9.9.9.9"]; f.Name != "viadns.example" || f.How != HowDNS {
		t.Fatalf("%+v", f)
	}
	if f := got[c1+">9.9.9.9"]; f.Name != "" {
		t.Fatalf("a name from another device's DNS was used: %+v", f)
	}
}

func TestANameSurvivesTheWindowOfALongFlowAndIsForgottenWhenItIsIdle(t *testing.T) {
	a := New()
	a.Add(FromClient, ipv4("10.8.1.2", "1.2.3.4", 6, tcp(40000, 443, 0x18, clientHello("long.example"))), t0)
	if f := a.Flush(t0.Add(time.Minute)); len(f) != 1 || f[0].Name != "long.example" {
		t.Fatalf("%+v", f)
	}
	// the next window has only the stream's data packets, no handshake
	a.Add(ToClient, ipv4("1.2.3.4", "10.8.1.2", 6, tcp(443, 40000, 0x10, make([]byte, 1200))), t0.Add(90*time.Second))
	if f := a.Flush(t0.Add(2 * time.Minute)); len(f) != 1 || f[0].Name != "long.example" || f[0].Up != 0 || f[0].Down == 0 {
		t.Fatalf("a long flow lost its name: %+v", f)
	}
	// a flow's counters restart each window
	if f := a.Flush(t0.Add(3 * time.Minute)); len(f) != 0 {
		t.Fatalf("an idle window reported %+v", f)
	}
	// and an idle name is forgotten after a while
	a.Flush(t0.Add(40 * time.Minute))
	a.Add(ToClient, ipv4("1.2.3.4", "10.8.1.2", 6, tcp(443, 40000, 0x10, make([]byte, 100))), t0.Add(41*time.Minute))
	if f := a.Flush(t0.Add(42 * time.Minute)); len(f) != 1 || f[0].Name != "" {
		t.Fatalf("%+v", f)
	}
}

func TestMemoryStaysBoundedUnderAScan(t *testing.T) {
	a := New()
	for i := 0; i < MaxFlows+500; i++ {
		dst := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String()
		a.Add(FromClient, ipv4("10.8.1.2", dst, 6, tcp(40000, 443, 0x02, nil)), t0)
	}
	if len(a.flows) != MaxFlows || a.Dropped != 500 {
		t.Fatalf("%d flows, %d dropped", len(a.flows), a.Dropped)
	}
	// a flood of DNS answers cannot grow a device's address book without bound
	for i := 0; i < MaxDNSPerHost*2; i++ {
		ad := netip.AddrFrom4([4]byte{9, byte(i >> 16), byte(i >> 8), byte(i)}).String()
		a.Add(ToClient, ipv4("1.1.1.1", "10.8.1.2", 17, udp(53, 5353, dnsResponse("x.example", ad))), t0)
	}
	if n := len(a.dns[netip.MustParseAddr("10.8.1.2")]); n > MaxDNSPerHost {
		t.Fatalf("%d addresses remembered", n)
	}
}

func TestMalformedPacketsNeverPanic(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	a := New()
	for i := 0; i < 20000; i++ {
		b := make([]byte, r.Intn(200))
		r.Read(b)
		if len(b) > 0 && i%3 == 0 {
			b[0] = 0x45 // make some of them look like IPv4
		}
		a.Add(Dir(i%2), b, t0)
		SNI(b)
		HTTPHost(b)
		DNSAnswer(b)
	}
	// truncated real shapes
	for _, full := range [][]byte{clientHello("a.example"), dnsResponse("a.example", "1.2.3.4"), []byte("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")} {
		for n := 0; n <= len(full); n++ {
			SNI(full[:n])
			HTTPHost(full[:n])
			DNSAnswer(full[:n])
			a.Add(FromClient, ipv4("10.8.1.2", "1.2.3.4", 6, tcp(1, 443, 0x18, full[:n])), t0)
		}
	}
	// a compression loop in DNS must end
	loop := []byte{0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1}
	DNSAnswer(loop)
}

func FuzzParsers(f *testing.F) {
	f.Add(clientHello("a.example"))
	f.Add(dnsResponse("a.example", "1.2.3.4"))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		SNI(b)
		HTTPHost(b)
		DNSAnswer(b)
		ParseIP(b)
		New().Add(FromClient, b, t0)
	})
}

func TestOnlyNewConnectionsAreCountedAsStarted(t *testing.T) {
	a := New()
	c := "10.8.1.2"
	// TCP: a SYN starts a connection, its later packets do not
	a.Add(FromClient, ipv4(c, "1.2.3.4", 6, tcp(40000, 443, 0x02, nil)), t0)
	a.Add(FromClient, ipv4(c, "1.2.3.4", 6, tcp(40000, 443, 0x18, make([]byte, 10))), t0)
	// a connection already running when the sensor started has no SYN in view
	a.Add(ToClient, ipv4("5.6.7.8", c, 6, tcp(443, 41000, 0x10, make([]byte, 1000))), t0)
	// UDP: the first packet of a flow starts it, the next minute's packets do not
	a.Add(FromClient, ipv4(c, "9.9.9.9", 17, udp(5000, 3478, make([]byte, 20))), t0)
	got := map[string]bool{}
	for _, f := range a.Flush(t0.Add(time.Minute)) {
		got[f.Remote.String()] = f.Started
	}
	if !got["1.2.3.4"] || got["5.6.7.8"] || !got["9.9.9.9"] {
		t.Fatalf("%v", got)
	}
	a.Add(FromClient, ipv4(c, "1.2.3.4", 6, tcp(40000, 443, 0x18, make([]byte, 10))), t0.Add(70*time.Second))
	a.Add(FromClient, ipv4(c, "9.9.9.9", 17, udp(5000, 3478, make([]byte, 20))), t0.Add(70*time.Second))
	for _, f := range a.Flush(t0.Add(2 * time.Minute)) {
		if f.Started {
			t.Fatalf("a flow that was already running was counted as new again: %+v", f)
		}
	}
	// a UDP flow that was silent for a few minutes starts again
	a.Add(FromClient, ipv4(c, "9.9.9.9", 17, udp(5000, 3478, make([]byte, 20))), t0.Add(10*time.Minute))
	if f := a.Flush(t0.Add(11 * time.Minute)); len(f) != 1 || !f[0].Started {
		t.Fatalf("%+v", f)
	}
}
