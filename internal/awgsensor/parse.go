// Package awgsensor reads the packets that cross one AmneziaWG interface and turns them into small
// per-flow summaries: which device (by its address in the tunnel), where to (address and port), how many
// bytes each way, and, when the packets say it in the open, a name for the destination.
//
// It keeps no packet and no payload. Everything it learns from a payload is a name: the SNI of a TLS
// handshake, the Host header of a plain HTTP request, or the answer to a DNS question. It cannot see
// pages, paths or anything inside encryption, and it says where each name came from.
//
// Packets come from an untrusted network, so every parser here checks every length before it reads and
// gives up quietly on anything it does not understand.
package awgsensor

import (
	"encoding/binary"
	"net/netip"
	"strings"
)

// Name sources.
const (
	HowSNI  = "sni"
	HowHost = "host"
	HowDNS  = "dns"
)

const maxName = 253

// cleanName keeps a host name to the characters real names use, lower-case, without a trailing dot.
func cleanName(b []byte) string {
	if len(b) == 0 || len(b) > maxName {
		return ""
	}
	out := make([]byte, 0, len(b))
	for _, c := range b {
		switch {
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
			out = append(out, c)
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
			out = append(out, c)
		default:
			return ""
		}
	}
	s := strings.TrimSuffix(string(out), ".")
	if s == "" {
		return ""
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "" // empty labels, over-long labels and labels starting or ending with a hyphen are not host names
		}
	}
	return s
}

// SNI reads the server name from the first bytes of a TCP stream, if they are a TLS ClientHello.
func SNI(p []byte) string {
	// record header (5) + handshake header (4) + version (2) + random (32)
	if len(p) < 5+4+2+32+1 || p[0] != 22 || p[5] != 1 {
		return ""
	}
	i := 5 + 4 + 2 + 32
	sid := int(p[i])
	i += 1 + sid
	if i+2 > len(p) {
		return ""
	}
	cs := int(binary.BigEndian.Uint16(p[i:]))
	i += 2 + cs
	if i+1 > len(p) {
		return ""
	}
	i += 1 + int(p[i])
	if i+2 > len(p) {
		return ""
	}
	extTotal := int(binary.BigEndian.Uint16(p[i:]))
	i += 2
	end := min(len(p), i+extTotal)
	for i+4 <= end {
		et := binary.BigEndian.Uint16(p[i:])
		el := int(binary.BigEndian.Uint16(p[i+2:]))
		i += 4
		if i+el > end {
			return ""
		}
		if et == 0 && el >= 5 { // server_name
			nl := int(binary.BigEndian.Uint16(p[i+3:]))
			if i+5+nl > i+el {
				return ""
			}
			return cleanName(p[i+5 : i+5+nl])
		}
		i += el
	}
	return ""
}

// HTTPHost reads the Host header from the start of a plain HTTP request.
func HTTPHost(p []byte) string {
	if len(p) < 16 {
		return ""
	}
	switch string(p[:4]) {
	case "GET ", "POST", "HEAD", "PUT ", "OPTI", "DELE", "PATC":
	default:
		return ""
	}
	lines := strings.Split(string(p), "\r\n")
	for i, l := range lines {
		if i == 0 {
			continue
		}
		if i > 30 || l == "" {
			break
		}
		if len(l) > 5 && strings.EqualFold(l[:5], "host:") {
			h := strings.TrimSpace(l[5:])
			if j := strings.IndexByte(h, ':'); j >= 0 {
				h = h[:j]
			}
			return cleanName([]byte(h))
		}
	}
	return ""
}

// DNSAnswer reads a DNS response and returns the name that was asked and the addresses it resolved to.
func DNSAnswer(p []byte) (string, []netip.Addr) {
	if len(p) < 12 || p[2]&0x80 == 0 { // not a response
		return "", nil
	}
	qd := int(binary.BigEndian.Uint16(p[4:]))
	an := int(binary.BigEndian.Uint16(p[6:]))
	if qd != 1 || an == 0 || an > 40 {
		return "", nil
	}
	i := 12
	qname, ni, ok := dnsName(p, i)
	if !ok || ni+4 > len(p) {
		return "", nil
	}
	name := cleanName([]byte(qname))
	if name == "" {
		return "", nil
	}
	i = ni + 4
	var addrs []netip.Addr
	for k := 0; k < an; k++ {
		_, ni, ok := dnsName(p, i)
		if !ok || ni+10 > len(p) {
			break
		}
		rtype := binary.BigEndian.Uint16(p[ni:])
		rdlen := int(binary.BigEndian.Uint16(p[ni+8:]))
		i = ni + 10
		if i+rdlen > len(p) {
			break
		}
		switch {
		case rtype == 1 && rdlen == 4:
			addrs = append(addrs, netip.AddrFrom4([4]byte(p[i:i+4])))
		case rtype == 28 && rdlen == 16:
			addrs = append(addrs, netip.AddrFrom16([16]byte(p[i:i+16])))
		}
		i += rdlen
	}
	return name, addrs
}

// dnsName reads a (possibly compressed) name at i and returns it with the offset just after it.
func dnsName(p []byte, i int) (string, int, bool) {
	var sb strings.Builder
	after := -1
	for hops := 0; hops < 40; hops++ {
		if i >= len(p) {
			return "", 0, false
		}
		n := int(p[i])
		switch {
		case n == 0:
			if after < 0 {
				after = i + 1
			}
			return sb.String(), after, true
		case n&0xC0 == 0xC0:
			if i+1 >= len(p) {
				return "", 0, false
			}
			if after < 0 {
				after = i + 2
			}
			i = (n&0x3F)<<8 | int(p[i+1])
		case n&0xC0 != 0:
			return "", 0, false
		default:
			if i+1+n > len(p) || sb.Len()+n+1 > maxName {
				return "", 0, false
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			sb.Write(p[i+1 : i+1+n])
			i += 1 + n
		}
	}
	return "", 0, false
}

// Packet is one IP packet reduced to what the summaries need.
type Packet struct {
	Src, Dst netip.Addr
	Proto    uint8
	SPort    uint16
	DPort    uint16
	Len      int // the packet's own length from its IP header
	Payload  []byte
	SYN      bool // a TCP SYN without ACK
}

// ParseIP reads an IPv4 or IPv6 packet. It returns false for anything it cannot place.
func ParseIP(b []byte) (Packet, bool) {
	if len(b) < 20 {
		return Packet{}, false
	}
	var pk Packet
	var l4 []byte
	switch b[0] >> 4 {
	case 4:
		ihl := int(b[0]&15) * 4
		if ihl < 20 || len(b) < ihl {
			return Packet{}, false
		}
		pk.Src = netip.AddrFrom4([4]byte(b[12:16]))
		pk.Dst = netip.AddrFrom4([4]byte(b[16:20]))
		pk.Proto = b[9]
		pk.Len = int(binary.BigEndian.Uint16(b[2:]))
		if frag := binary.BigEndian.Uint16(b[6:]) & 0x1FFF; frag != 0 { // not the first fragment: no ports to read
			return pk, true
		}
		l4 = b[ihl:]
	case 6:
		if len(b) < 40 {
			return Packet{}, false
		}
		pk.Src = netip.AddrFrom16([16]byte(b[8:24]))
		pk.Dst = netip.AddrFrom16([16]byte(b[24:40]))
		pk.Proto = b[6]
		pk.Len = 40 + int(binary.BigEndian.Uint16(b[4:]))
		l4 = b[40:]
	default:
		return Packet{}, false
	}
	switch pk.Proto {
	case 6: // TCP
		if len(l4) < 20 {
			return pk, true
		}
		pk.SPort = binary.BigEndian.Uint16(l4)
		pk.DPort = binary.BigEndian.Uint16(l4[2:])
		off := int(l4[12]>>4) * 4
		pk.SYN = l4[13]&0x02 != 0 && l4[13]&0x10 == 0
		if off >= 20 && off <= len(l4) {
			pk.Payload = l4[off:]
		}
	case 17: // UDP
		if len(l4) < 8 {
			return pk, true
		}
		pk.SPort = binary.BigEndian.Uint16(l4)
		pk.DPort = binary.BigEndian.Uint16(l4[2:])
		pk.Payload = l4[8:]
	}
	return pk, true
}
