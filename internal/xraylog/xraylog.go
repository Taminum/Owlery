// Package xraylog parses Xray access-log lines.
//
// The format was taken from a real Remnawave node (Xray 26.7.x), not from documentation:
//
//	2026/10/09 12:03:31.803861 from 95.183.45.51:47242 accepted tcp:www.google.com:443 [Steal -> DIRECT] email: 2
//
// Observed variants that this parser handles: the tag separator is "->" or ">>"; the outbound
// can be DIRECT, a named outbound, or BLOCK; "from" can be ip:port, tcp:ip:port, or the literal
// DNS for the node's own resolver, whose inbound is xray.system.<uuid> and which has no email;
// destinations are domains, IPv4 or bracketed IPv6. Timestamps carry no zone and are UTC on the nodes.
package xraylog

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const timeLayout = "2006/01/02 15:04:05.999999"

// ParserVersion is recorded with ingested events so a parser change is visible in the data.
const ParserVersion = 1

type Event struct {
	Time        time.Time
	ClientIP    netip.Addr // invalid for internal events
	ClientPort  int
	Internal    bool   // the node's own DNS/system traffic: from "DNS", inbound xray.system.*
	Protocol    string // tcp | udp
	DestHost    string // lower-case, no trailing dot; empty for IP destinations
	DestIP      netip.Addr
	DestPort    int
	InboundTag  string
	OutboundTag string
	Arrow       string // "->" or ">>" exactly as logged; its meaning is not assumed
	Email       string // the Remnawave user id as written by Xray; an identity HINT, never trusted alone
}

// ParseError never contains the line itself: lines hold browsing metadata.
type ParseError struct{ Reason string }

func (e *ParseError) Error() string { return "xraylog: " + e.Reason }

func bad(reason string) (Event, error) { return Event{}, &ParseError{Reason: reason} }

// ParseLine parses one access-log line (without the trailing newline).
func ParseLine(line string) (Event, error) {
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 || len(line) > 2048 {
		return bad("length")
	}
	// "2026/10/09 12:03:31.803861 from <client> accepted <proto>:<dest> [<in> <arrow> <out>] [email: <e>]"
	date, rest, ok := strings.Cut(line, " ")
	if !ok {
		return bad("no fields")
	}
	clock, rest, ok := strings.Cut(rest, " ")
	if !ok {
		return bad("no fields")
	}
	ts, err := time.ParseInLocation(timeLayout, date+" "+clock, time.UTC)
	if err != nil {
		return bad("timestamp")
	}
	rest, ok = strings.CutPrefix(rest, "from ")
	if !ok {
		return bad("missing from")
	}
	client, rest, ok := strings.Cut(rest, " ")
	if !ok {
		return bad("missing client")
	}
	rest, ok = strings.CutPrefix(rest, "accepted ")
	if !ok {
		return bad("not an accepted line")
	}
	target, rest, ok := strings.Cut(rest, " ")
	if !ok {
		return bad("missing tags")
	}
	if !strings.HasPrefix(rest, "[") {
		return bad("missing tags")
	}
	end := strings.Index(rest, "]")
	if end < 0 {
		return bad("unterminated tags")
	}
	tags, tail := rest[1:end], strings.TrimSpace(rest[end+1:])

	ev := Event{Time: ts}

	// client
	if client == "DNS" {
		ev.Internal = true
	} else {
		client = strings.TrimPrefix(client, "tcp:")
		ap, err := netip.ParseAddrPort(client)
		if err != nil {
			return bad("client address")
		}
		ev.ClientIP, ev.ClientPort = ap.Addr().Unmap(), int(ap.Port())
	}

	// protocol and destination
	proto, dest, ok := strings.Cut(target, ":")
	if !ok || (proto != "tcp" && proto != "udp") {
		return bad("protocol")
	}
	ev.Protocol = proto
	if err := parseDest(dest, &ev); err != nil {
		return Event{}, err
	}

	// tags: "<inbound> <arrow> <outbound>"
	f := strings.Fields(tags)
	if len(f) != 3 || (f[1] != "->" && f[1] != ">>") {
		return bad("tags")
	}
	ev.InboundTag, ev.Arrow, ev.OutboundTag = f[0], f[1], f[2]
	if strings.HasPrefix(ev.InboundTag, "xray.system.") {
		ev.Internal = true
	}

	// optional email
	if tail != "" {
		e, ok := strings.CutPrefix(tail, "email: ")
		if !ok || e == "" || strings.ContainsAny(e, " \t") || len(e) > 128 {
			return bad("trailer")
		}
		ev.Email = e
	}
	return ev, nil
}

func parseDest(d string, ev *Event) error {
	var host, port string
	if strings.HasPrefix(d, "[") { // bracketed IPv6
		i := strings.LastIndex(d, "]:")
		if i < 0 {
			return &ParseError{"destination"}
		}
		host, port = d[1:i], d[i+2:]
	} else {
		i := strings.LastIndex(d, ":")
		if i < 0 {
			return &ParseError{"destination"}
		}
		host, port = d[:i], d[i+1:]
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		return &ParseError{"destination port"}
	}
	ev.DestPort = p
	if ip, err := netip.ParseAddr(host); err == nil {
		ev.DestIP = ip.Unmap() // an IP stays an IP: it is never turned into a guessed domain
		return nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \t/\\[]") {
		return &ParseError{"destination host"}
	}
	ev.DestHost = host
	return nil
}

// IsParseError reports whether err came from ParseLine.
func IsParseError(err error) bool {
	var pe *ParseError
	return errors.As(err, &pe)
}
