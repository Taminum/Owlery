// Package dnsmap discovers and tracks the publicly observable DNS records of a domain.
//
// It does not enumerate zones: ordinary DNS cannot list every name in a zone, so what it holds is the
// records it was able to observe, with where and when each was seen. client.go is the DNS client: a small one
// on golang.org/x/net/dns/dnsmessage, because the standard resolver exposes neither TTLs, nor SOA, CAA, DS
// or DNSKEY, nor the difference between "no such name", "no such record" and "the server failed".
package dnsmap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/Taminum/RemnaScope/internal/safehttp"
)

// Record types this package asks for. The values are the numbers on the wire.
const (
	TypeA      = "A"
	TypeAAAA   = "AAAA"
	TypeCNAME  = "CNAME"
	TypeMX     = "MX"
	TypeNS     = "NS"
	TypeSOA    = "SOA"
	TypeTXT    = "TXT"
	TypeCAA    = "CAA"
	TypeDS     = "DS"
	TypeDNSKEY = "DNSKEY"
)

var typeNum = map[string]dnsmessage.Type{
	TypeA: dnsmessage.TypeA, TypeAAAA: dnsmessage.TypeAAAA, TypeCNAME: dnsmessage.TypeCNAME, TypeMX: dnsmessage.TypeMX,
	TypeNS: dnsmessage.TypeNS, TypeSOA: dnsmessage.TypeSOA, TypeTXT: dnsmessage.TypeTXT, TypeCAA: 257, TypeDS: 43, TypeDNSKEY: 48,
}

func typeName(t dnsmessage.Type) string {
	for n, v := range typeNum {
		if v == t {
			return n
		}
	}
	return ""
}

// Outcomes of one query. A negative answer says nothing about the name forever, and a failure says nothing
// about the name at all.
const (
	OutcomeAnswer   = "answer"
	OutcomeNoData   = "nodata"   // the name exists, there is no record of that type
	OutcomeNXDomain = "nxdomain" // the name does not exist
	OutcomeServFail = "servfail"
	OutcomeRefused  = "refused"
	OutcomeTimeout  = "timeout"
	OutcomeError    = "error" // anything else: a bad reply, an address that is not allowed, a malformed name
)

const (
	maxAnswers  = 64
	maxChain    = 8
	udpSize     = 1232
	maxTCPBytes = 64 << 10
)

// RR is one resource record, with its value in a canonical text form so that equal records compare equal.
type RR struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// Answer is the result of one question to one server.
type Answer struct {
	Outcome string `json:"outcome"`
	RRs     []RR   `json:"rrs,omitempty"`
	Server  string `json:"server"`
	AA      bool   `json:"aa"` // the server says it is authoritative for the name
	Rcode   string `json:"rcode,omitempty"`
}

var errBlocked = errors.New("dnsmap: address not allowed")

// Client sends questions. Exchange and Allow are replaced in tests; nothing else should replace them.
type Client struct {
	Timeout  time.Duration
	Allow    func(netip.Addr) bool
	Exchange func(ctx context.Context, server netip.AddrPort, wire []byte) ([]byte, error)
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 4 * time.Second
}

func (c *Client) allowed(a netip.Addr) bool {
	if c.Allow != nil {
		return c.Allow(a)
	}
	return safehttp.PublicAddr(a)
}

func (c *Client) dialer() *net.Dialer {
	return &net.Dialer{Timeout: c.timeout(), Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil || !c.allowed(ap.Addr().Unmap()) {
			return errBlocked
		}
		return nil
	}}
}

// ValidName reports whether s can be a name in a query: a lower-case ASCII domain with labels of 1 to 63
// characters, at most 253 in all.
func ValidName(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		// A label may not start or end with a hyphen. A leading underscore is allowed: service names such
		// as _dmarc use it.
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			b := l[i]
			ok := b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_'
			if !ok {
				return false
			}
		}
	}
	return true
}

func build(id uint16, name string, qt dnsmessage.Type, rd bool) ([]byte, error) {
	n, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: rd})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: qt, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	// EDNS0 with a payload size that avoids most truncation.
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(udpSize, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, err
	}
	if err := b.OPTResource(opt, dnsmessage.OPTResource{}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// Query asks one server one question. rd is "recursion desired": true for a recursive resolver, false for an
// authoritative server. A malformed name is refused without sending anything.
func (c *Client) Query(ctx context.Context, server netip.AddrPort, name, qtype string, rd bool) Answer {
	ans := Answer{Server: server.String()}
	qt, ok := typeNum[qtype]
	if !ok || !ValidName(name) {
		ans.Outcome = OutcomeError
		return ans
	}
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	wire, err := build(id, name, qt, rd)
	if err != nil {
		ans.Outcome = OutcomeError
		return ans
	}
	ctx, cancel := context.WithTimeout(ctx, 2*c.timeout()+time.Second)
	defer cancel()
	ex := c.Exchange
	if ex == nil {
		ex = c.exchange
	}
	raw, err := ex(ctx, server, wire)
	if err != nil {
		ans.Outcome = outcomeOf(err)
		return ans
	}
	var p dnsmessage.Parser
	h, err := p.Start(raw)
	if err != nil || !h.Response || h.ID != id {
		ans.Outcome = OutcomeError
		return ans
	}
	q, err := p.Question()
	if err != nil || !strings.EqualFold(strings.TrimSuffix(q.Name.String(), "."), strings.TrimSuffix(name, ".")) || q.Type != qt {
		ans.Outcome = OutcomeError
		return ans
	}
	_ = p.SkipAllQuestions()
	ans.AA = h.Authoritative
	ans.Rcode = rcodeName(h.RCode)
	switch h.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		ans.Outcome = OutcomeNXDomain
		return ans
	case dnsmessage.RCodeServerFailure:
		ans.Outcome = OutcomeServFail
		return ans
	case dnsmessage.RCodeRefused:
		ans.Outcome = OutcomeRefused
		return ans
	default:
		ans.Outcome = OutcomeError
		return ans
	}
	all, err := readAnswers(&p)
	if err != nil {
		ans.Outcome = OutcomeError
		return ans
	}
	ans.RRs = followChain(strings.ToLower(strings.TrimSuffix(name, ".")), qtype, all)
	if len(ans.RRs) == 0 {
		ans.Outcome = OutcomeNoData
		return ans
	}
	ans.Outcome = OutcomeAnswer
	return ans
}

func rcodeName(r dnsmessage.RCode) string {
	switch r {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	}
	return "RCODE" + strconv.Itoa(int(r))
}

func outcomeOf(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, errBlocked):
		return OutcomeError
	case errors.Is(err, context.DeadlineExceeded):
		return OutcomeTimeout
	case errors.As(err, &ne) && ne.Timeout():
		return OutcomeTimeout
	}
	return OutcomeError
}

// exchange sends over UDP, and over TCP if the reply says it was cut short.
func (c *Client) exchange(ctx context.Context, server netip.AddrPort, wire []byte) ([]byte, error) {
	if !c.allowed(server.Addr().Unmap()) {
		return nil, errBlocked
	}
	d := c.dialer()
	conn, err := d.DialContext(ctx, "udp", server.String())
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(c.timeout()))
	if _, err := conn.Write(wire); err != nil {
		conn.Close()
		return nil, err
	}
	buf := make([]byte, 4096)
	var n int
	for {
		n, err = conn.Read(buf)
		if err != nil {
			conn.Close()
			return nil, err
		}
		// A reply that is not an answer to this question (a stray datagram) is ignored, not trusted.
		if n >= 2 && buf[0] == wire[0] && buf[1] == wire[1] {
			break
		}
	}
	conn.Close()
	reply := buf[:n]
	if n >= 4 && reply[2]&0x02 != 0 { // TC: truncated, ask again over TCP
		return c.exchangeTCP(ctx, server, wire)
	}
	return reply, nil
}

func (c *Client) exchangeTCP(ctx context.Context, server netip.AddrPort, wire []byte) ([]byte, error) {
	conn, err := c.dialer().DialContext(ctx, "tcp", server.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.timeout()))
	msg := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(msg, uint16(len(wire)))
	copy(msg[2:], wire)
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n == 0 || n > maxTCPBytes {
		return nil, errors.New("dnsmap: bad TCP reply length")
	}
	out := make([]byte, n)
	if _, err := io.ReadFull(conn, out); err != nil {
		return nil, err
	}
	return out, nil
}

type rawRR struct {
	name  string
	typ   dnsmessage.Type
	ttl   uint32
	value string
}

func readAnswers(p *dnsmessage.Parser) ([]rawRR, error) {
	var out []rawRR
	for len(out) < maxAnswers {
		h, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, err
		}
		name := strings.ToLower(strings.TrimSuffix(h.Name.String(), "."))
		v, ok, err := readValue(p, h)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, rawRR{name: name, typ: h.Type, ttl: h.TTL, value: v})
		}
	}
	return out, nil
}

func fqdn(n dnsmessage.Name) string { return strings.ToLower(strings.TrimSuffix(n.String(), ".")) }

// readValue reads the record the parser is at and turns it into the canonical text of its value. A type the
// package does not know is skipped, not an error.
func readValue(p *dnsmessage.Parser, h dnsmessage.ResourceHeader) (string, bool, error) {
	switch h.Type {
	case dnsmessage.TypeA:
		r, err := p.AResource()
		if err != nil {
			return "", false, err
		}
		return netip.AddrFrom4(r.A).String(), true, nil
	case dnsmessage.TypeAAAA:
		r, err := p.AAAAResource()
		if err != nil {
			return "", false, err
		}
		return netip.AddrFrom16(r.AAAA).Unmap().String(), true, nil
	case dnsmessage.TypeCNAME:
		r, err := p.CNAMEResource()
		if err != nil {
			return "", false, err
		}
		return fqdn(r.CNAME), true, nil
	case dnsmessage.TypeNS:
		r, err := p.NSResource()
		if err != nil {
			return "", false, err
		}
		return fqdn(r.NS), true, nil
	case dnsmessage.TypeMX:
		r, err := p.MXResource()
		if err != nil {
			return "", false, err
		}
		host := fqdn(r.MX)
		if host == "" { // the root name: a "null MX" says the domain takes no mail
			host = "."
		}
		return fmt.Sprintf("%d %s", r.Pref, host), true, nil
	case dnsmessage.TypeSOA:
		r, err := p.SOAResource()
		if err != nil {
			return "", false, err
		}
		return fmt.Sprintf("%s %s %d %d %d %d %d", fqdn(r.NS), fqdn(r.MBox), r.Serial, r.Refresh, r.Retry, r.Expire, r.MinTTL), true, nil
	case dnsmessage.TypeTXT:
		r, err := p.TXTResource()
		if err != nil {
			return "", false, err
		}
		return strings.Join(r.TXT, ""), true, nil
	case 257, 43, 48:
		r, err := p.UnknownResource()
		if err != nil {
			return "", false, err
		}
		return unknownValue(h.Type, r.Data)
	}
	return "", false, p.SkipAnswer()
}

func unknownValue(t dnsmessage.Type, d []byte) (string, bool, error) {
	switch t {
	case 257: // CAA: flags, tag length, tag, value
		if len(d) < 2 || int(d[1])+2 > len(d) {
			return "", false, errors.New("dnsmap: bad CAA")
		}
		tl := int(d[1])
		return fmt.Sprintf("%d %s %q", d[0], strings.ToLower(string(d[2:2+tl])), string(d[2+tl:])), true, nil
	case 43: // DS: key tag, algorithm, digest type, digest
		if len(d) < 5 {
			return "", false, errors.New("dnsmap: bad DS")
		}
		return fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(d), d[2], d[3], strings.ToUpper(hex.EncodeToString(d[4:]))), true, nil
	case 48: // DNSKEY: flags, protocol, algorithm, public key
		if len(d) < 5 {
			return "", false, errors.New("dnsmap: bad DNSKEY")
		}
		return fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(d), d[2], d[3], base64.StdEncoding.EncodeToString(d[4:])), true, nil
	}
	return "", false, nil
}

// followChain keeps only what answers the question: the CNAMEs leading from the asked name, and the
// records of the asked type at the end. Anything else a server put in the reply is dropped.
func followChain(name, qtype string, all []rawRR) []RR {
	want := typeNum[qtype]
	cur := name
	var out []RR
	seen := map[string]bool{}
	for hop := 0; hop <= maxChain; hop++ {
		next := ""
		for _, r := range all {
			if r.name != cur {
				continue
			}
			switch {
			case r.typ == want:
				out = append(out, RR{Name: r.name, Type: qtype, Value: r.value, TTL: r.ttl})
			case r.typ == dnsmessage.TypeCNAME && want != dnsmessage.TypeCNAME:
				out = append(out, RR{Name: r.name, Type: TypeCNAME, Value: r.value, TTL: r.ttl})
				next = r.value
			}
		}
		if next == "" || seen[next] {
			break
		}
		seen[cur] = true
		cur = next
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Value < out[j].Value
	})
	return out
}
