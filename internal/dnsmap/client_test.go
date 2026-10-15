package dnsmap

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// spec describes what the fake server answers for one name and type.
type spec struct {
	rcode   dnsmessage.RCode
	aa      bool
	answers []dnsmessage.Resource
	silent  bool // never answer
	tc      bool // over UDP answer "truncated" with nothing, over TCP answer in full
	stray   bool // before the real answer, send one with the wrong ID
	wrongQ  bool // answer a different question
}

type fakeDNS struct {
	t       *testing.T
	specs   map[string]spec
	queries atomic.Int64
	addr    netip.AddrPort
}

func nm(s string) dnsmessage.Name { return dnsmessage.MustNewName(strings.TrimSuffix(s, ".") + ".") }

func hdr(name string, t dnsmessage.Type, ttl uint32) dnsmessage.ResourceHeader {
	return dnsmessage.ResourceHeader{Name: nm(name), Type: t, Class: dnsmessage.ClassINET, TTL: ttl}
}

func rrA(name, ip string, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{Header: hdr(name, dnsmessage.TypeA, ttl), Body: &dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()}}
}

func rrCNAME(name, to string, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{Header: hdr(name, dnsmessage.TypeCNAME, ttl), Body: &dnsmessage.CNAMEResource{CNAME: nm(to)}}
}

func rrUnknown(name string, t dnsmessage.Type, data []byte) dnsmessage.Resource {
	return dnsmessage.Resource{Header: hdr(name, t, 300), Body: &dnsmessage.UnknownResource{Type: t, Data: data}}
}

func (f *fakeDNS) reply(req []byte, truncated bool, tcp bool) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(req)
	if err != nil {
		return nil
	}
	q, _ := p.Question()
	key := strings.TrimSuffix(q.Name.String(), ".") + "|" + typeName(q.Type)
	s, ok := f.specs[key]
	if !ok {
		s = spec{rcode: dnsmessage.RCodeNameError}
	}
	qq := q
	if s.wrongQ {
		qq.Name = nm("other.example")
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: s.aa, RCode: s.rcode, Truncated: truncated && !tcp})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(qq)
	_ = b.StartAnswers()
	if !(truncated && !tcp) {
		for _, a := range s.answers {
			switch body := a.Body.(type) {
			case *dnsmessage.AResource:
				_ = b.AResource(a.Header, *body)
			case *dnsmessage.AAAAResource:
				_ = b.AAAAResource(a.Header, *body)
			case *dnsmessage.CNAMEResource:
				_ = b.CNAMEResource(a.Header, *body)
			case *dnsmessage.MXResource:
				_ = b.MXResource(a.Header, *body)
			case *dnsmessage.NSResource:
				_ = b.NSResource(a.Header, *body)
			case *dnsmessage.SOAResource:
				_ = b.SOAResource(a.Header, *body)
			case *dnsmessage.TXTResource:
				_ = b.TXTResource(a.Header, *body)
			case *dnsmessage.UnknownResource:
				_ = b.UnknownResource(a.Header, *body)
			}
		}
	}
	out, _ := b.Finish()
	return out
}

func newFake(t *testing.T, specs map[string]spec) (*fakeDNS, *Client) {
	t.Helper()
	f := &fakeDNS{t: t, specs: specs}
	// UDP and TCP must share one port, and a port that is free for one may be taken for the other: try again.
	var pc net.PacketConn
	var tl net.Listener
	var port int
	for try := 0; try < 200; try++ {
		var err error
		if tl, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			tl = nil
			continue
		}
		port = tl.Addr().(*net.TCPAddr).Port
		if pc, err = net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", itoa(port))); err == nil {
			break
		}
		tl.Close()
		pc, tl = nil, nil
	}
	if pc == nil || tl == nil {
		t.Skip("no port free for both UDP and TCP")
	}
	f.addr = netip.MustParseAddrPort(pc.LocalAddr().String())
	t.Cleanup(func() { pc.Close(); tl.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			f.queries.Add(1)
			req := append([]byte(nil), buf[:n]...)
			var p dnsmessage.Parser
			if _, err := p.Start(req); err != nil {
				continue
			}
			q, _ := p.Question()
			s := specs[strings.TrimSuffix(q.Name.String(), ".")+"|"+typeName(q.Type)]
			if s.silent {
				continue
			}
			if s.stray {
				bad := f.reply(req, false, false)
				bad[0] ^= 0xff
				_, _ = pc.WriteTo(bad, from)
			}
			_, _ = pc.WriteTo(f.reply(req, s.tc, false), from)
		}
	}()
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				req := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				f.queries.Add(1)
				resp := f.reply(req, true, true)
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out, uint16(len(resp)))
				copy(out[2:], resp)
				_, _ = c.Write(out)
			}()
		}
	}()
	return f, &Client{Timeout: 400 * time.Millisecond, Allow: func(a netip.Addr) bool { return a.IsLoopback() }}
}

func itoa(n int) string { return strconv.Itoa(n) }

func q(c *Client, f *fakeDNS, name, typ string) Answer {
	return c.Query(context.Background(), f.addr, name, typ, true)
}

func TestRecordTypesAreReadWithTTLAndCanonicalValues(t *testing.T) {
	txt := dnsmessage.Resource{Header: hdr("example.com", dnsmessage.TypeTXT, 60), Body: &dnsmessage.TXTResource{TXT: []string{"v=spf1 include:_spf.example.net ", "-all"}}}
	soa := dnsmessage.Resource{Header: hdr("example.com", dnsmessage.TypeSOA, 3600), Body: &dnsmessage.SOAResource{NS: nm("ns1.example.com"), MBox: nm("hostmaster.example.com"), Serial: 2026101501, Refresh: 7200, Retry: 900, Expire: 1209600, MinTTL: 300}}
	mx := dnsmessage.Resource{Header: hdr("example.com", dnsmessage.TypeMX, 300), Body: &dnsmessage.MXResource{Pref: 10, MX: nm("Mail.Example.com")}}
	ns := dnsmessage.Resource{Header: hdr("example.com", dnsmessage.TypeNS, 86400), Body: &dnsmessage.NSResource{NS: nm("NS1.example.com")}}
	aaaa := dnsmessage.Resource{Header: hdr("example.com", dnsmessage.TypeAAAA, 120), Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::1").As16()}}
	caa := rrUnknown("example.com", 257, append([]byte{0, 5}, []byte("issuehttps://letsencrypt.org")[0:0]...))
	caa.Body = &dnsmessage.UnknownResource{Type: 257, Data: append(append([]byte{0, 5}, []byte("issue")...), []byte("letsencrypt.org")...)}
	ds := rrUnknown("example.com", 43, []byte{0x30, 0x39, 13, 2, 0xAB, 0xCD, 0xEF})
	key := rrUnknown("example.com", 48, []byte{1, 1, 3, 13, 'k', 'e', 'y', '!'})
	f, c := newFake(t, map[string]spec{
		"example.com|A": {answers: []dnsmessage.Resource{rrA("example.com", "93.184.216.34", 300), rrA("example.com", "93.184.216.33", 300)}}, "example.com|AAAA": {answers: []dnsmessage.Resource{aaaa}},
		"example.com|TXT": {answers: []dnsmessage.Resource{txt}}, "example.com|SOA": {aa: true, answers: []dnsmessage.Resource{soa}}, "example.com|MX": {answers: []dnsmessage.Resource{mx}},
		"example.com|NS": {answers: []dnsmessage.Resource{ns}}, "example.com|CAA": {answers: []dnsmessage.Resource{caa}}, "example.com|DS": {answers: []dnsmessage.Resource{ds}}, "example.com|DNSKEY": {answers: []dnsmessage.Resource{key}},
	})
	want := map[string]string{
		TypeAAAA: "2001:db8::1", TypeTXT: "v=spf1 include:_spf.example.net -all", TypeSOA: "ns1.example.com hostmaster.example.com 2026101501 7200 900 1209600 300",
		TypeMX: "10 mail.example.com", TypeNS: "ns1.example.com", TypeCAA: `0 issue "letsencrypt.org"`, TypeDS: "12345 13 2 ABCDEF", TypeDNSKEY: "257 3 13 a2V5IQ==",
	}
	for typ, v := range want {
		a := q(c, f, "example.com", typ)
		if a.Outcome != OutcomeAnswer || len(a.RRs) != 1 || a.RRs[0].Value != v || a.RRs[0].Type != typ {
			t.Errorf("%s: %+v want %q", typ, a, v)
		}
	}
	a := q(c, f, "example.com", TypeA)
	if len(a.RRs) != 2 || a.RRs[0].Value != "93.184.216.33" || a.RRs[0].TTL != 300 {
		t.Fatalf("a values are sorted and carry their TTL: %+v", a)
	}
	if soaA := q(c, f, "example.com", TypeSOA); !soaA.AA || soaA.RRs[0].TTL != 3600 {
		t.Fatalf("%+v", soaA)
	}
}

func TestANullMXIsShownAsOne(t *testing.T) {
	null := dnsmessage.Resource{Header: hdr("example.com", dnsmessage.TypeMX, 60), Body: &dnsmessage.MXResource{Pref: 0, MX: dnsmessage.MustNewName(".")}}
	f, c := newFake(t, map[string]spec{"example.com|MX": {answers: []dnsmessage.Resource{null}}})
	a := q(c, f, "example.com", TypeMX)
	if a.Outcome != OutcomeAnswer || len(a.RRs) != 1 || a.RRs[0].Value != "0 ." {
		t.Fatalf("%+v", a)
	}
}

func TestOnlyWhatAnswersTheQuestionIsKept(t *testing.T) {
	f, c := newFake(t, map[string]spec{"www.example.com|A": {answers: []dnsmessage.Resource{
		rrCNAME("www.example.com", "cdn.example.net", 60), rrA("cdn.example.net", "198.51.100.7", 30),
		rrA("evil.example.org", "203.0.113.66", 30), // something a server threw in: it answers nothing that was asked
	}}})
	a := q(c, f, "www.example.com", TypeA)
	if a.Outcome != OutcomeAnswer || len(a.RRs) != 2 {
		t.Fatalf("%+v", a)
	}
	got := map[string]string{}
	for _, r := range a.RRs {
		got[r.Type] = r.Name + ">" + r.Value
	}
	if got["CNAME"] != "www.example.com>cdn.example.net" || got["A"] != "cdn.example.net>198.51.100.7" {
		t.Fatalf("the chain is the whole answer: %v", got)
	}
	for _, r := range a.RRs {
		if strings.Contains(r.Name, "evil") {
			t.Fatalf("an unrelated record leaked in: %+v", r)
		}
	}
}

func TestNegativeAnswersAndFailuresAreToldApart(t *testing.T) {
	f, c := newFake(t, map[string]spec{
		"nodata.example.com|AAAA": {},
		"gone.example.com|A":      {rcode: dnsmessage.RCodeNameError},
		"broken.example.com|A":    {rcode: dnsmessage.RCodeServerFailure},
		"refuses.example.com|A":   {rcode: dnsmessage.RCodeRefused},
		"weird.example.com|A":     {rcode: dnsmessage.RCodeNotImplemented},
		"silent.example.com|A":    {silent: true},
		"confused.example.com|A":  {wrongQ: true},
		"stray.example.com|A":     {stray: true, answers: []dnsmessage.Resource{rrA("stray.example.com", "198.51.100.9", 5)}},
	})
	for name, c2 := range map[string]struct{ typ, want string }{
		"nodata.example.com": {TypeAAAA, OutcomeNoData}, "gone.example.com": {TypeA, OutcomeNXDomain}, "broken.example.com": {TypeA, OutcomeServFail},
		"refuses.example.com": {TypeA, OutcomeRefused}, "weird.example.com": {TypeA, OutcomeError}, "silent.example.com": {TypeA, OutcomeTimeout},
		"confused.example.com": {TypeA, OutcomeError}, "stray.example.com": {TypeA, OutcomeAnswer},
	} {
		if a := q(c, f, name, c2.typ); a.Outcome != c2.want {
			t.Errorf("%s: %s want %s (%+v)", name, a.Outcome, c2.want, a)
		}
	}
	if a := q(c, f, "stray.example.com", TypeA); len(a.RRs) != 1 || a.RRs[0].Value != "198.51.100.9" {
		t.Errorf("a stray datagram with the wrong ID must be ignored: %+v", a)
	}
}

func TestATruncatedReplyIsRetriedOverTCP(t *testing.T) {
	var segs []dnsmessage.Resource
	for i := 0; i < 20; i++ {
		segs = append(segs, dnsmessage.Resource{Header: hdr("big.example.com", dnsmessage.TypeTXT, 60), Body: &dnsmessage.TXTResource{TXT: []string{strings.Repeat("x", 100) + itoa(i)}}})
	}
	f, c := newFake(t, map[string]spec{"big.example.com|TXT": {tc: true, answers: segs}})
	a := q(c, f, "big.example.com", TypeTXT)
	if a.Outcome != OutcomeAnswer || len(a.RRs) != 20 {
		t.Fatalf("%s %d", a.Outcome, len(a.RRs))
	}
	if f.queries.Load() != 2 {
		t.Fatalf("one UDP and one TCP query expected, got %d", f.queries.Load())
	}
}

func TestNothingIsSentToAnAddressThatIsNotAllowedOrForABadName(t *testing.T) {
	f, c := newFake(t, map[string]spec{"example.com|A": {answers: []dnsmessage.Resource{rrA("example.com", "93.184.216.34", 5)}}})
	strict := &Client{Timeout: c.Timeout} // the real rule: only public addresses
	if a := strict.Query(context.Background(), f.addr, "example.com", TypeA, true); a.Outcome != OutcomeError {
		t.Fatalf("a loopback server must be refused: %+v", a)
	}
	for _, bad := range []string{"", "a b.example.com", "-.", strings.Repeat("a", 64) + ".com", "x..com", "UPPER.example.com", "ex\x00.com", "http://example.com"} {
		if a := c.Query(context.Background(), f.addr, bad, TypeA, true); a.Outcome != OutcomeError {
			t.Errorf("%q: %+v", bad, a)
		}
	}
	if a := c.Query(context.Background(), f.addr, "example.com", "AXFR", true); a.Outcome != OutcomeError {
		t.Errorf("a zone transfer must not be askable: %+v", a)
	}
	if a := c.Query(context.Background(), f.addr, "example.com", "ANY", true); a.Outcome != OutcomeError {
		t.Errorf("ANY must not be askable: %+v", a)
	}
	if f.queries.Load() != 0 {
		t.Fatalf("something was sent: %d queries", f.queries.Load())
	}
}

func TestValidName(t *testing.T) {
	for s, want := range map[string]bool{"example.com": true, "example.com.": true, "_dmarc.example.com": true, "xn--e1afmkfd.xn--p1ai": true, "a-b.c": true, "": false, ".": false, "a.b c": false, "Ab.com": false} {
		if got := ValidName(s); got != want {
			t.Errorf("%q: %v", s, got)
		}
	}
}
