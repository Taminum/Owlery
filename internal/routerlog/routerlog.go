// Package routerlog is the record a router agent sends: one connection seen on the router,
// as one JSON line. The agent sends a record when it first sees a connection and again while
// its byte counters change; the server keeps the latest values per connection.
package routerlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode"
)

const Version = 1

// Record is the wire form. Short keys keep a line well inside the per-line limit.
type Record struct {
	V     int       `json:"v"`
	ID    string    `json:"id"`
	Start time.Time `json:"t"`
	Seen  time.Time `json:"u"`
	Src   string    `json:"src"`
	Name  string    `json:"n,omitempty"`
	Host  string    `json:"h,omitempty"`
	DstIP string    `json:"di,omitempty"`
	Port  int       `json:"dp"`
	Proto string    `json:"p"`
	Up    int64     `json:"up"`
	Down  int64     `json:"dn"`
	Out   string    `json:"o,omitempty"`
}

// Event is a validated Record.
type Event struct {
	ID         string
	Start      time.Time
	Seen       time.Time
	Device     netip.Addr
	DeviceName string
	Host       string
	DestIP     netip.Addr
	Port       int
	Protocol   string
	Up, Down   int64
	Outbound   string
}

var ErrInvalid = errors.New("routerlog: invalid record")

// IsRecord reports whether a spooled line is a router record rather than an Xray log line.
func IsRecord(line string) bool { return strings.HasPrefix(line, "{") }

func clean(s string, max int) (string, bool) {
	if len(s) > max {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return s, true
}

// Parse validates one line. Nothing in it is trusted: the device must be a private address,
// the times must be plausible and the counters non-negative.
func Parse(line string, now time.Time) (Event, error) {
	var r Record
	dec := json.NewDecoder(bytes.NewReader([]byte(line)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil || r.V != Version {
		return Event{}, ErrInvalid
	}
	id, ok := clean(r.ID, 64)
	if !ok || id == "" {
		return Event{}, ErrInvalid
	}
	src, err := netip.ParseAddr(r.Src)
	if err != nil || !(src.IsPrivate() || src.IsLinkLocalUnicast()) || src.IsUnspecified() {
		return Event{}, ErrInvalid
	}
	if r.Proto != "tcp" && r.Proto != "udp" {
		return Event{}, ErrInvalid
	}
	if r.Port < 0 || r.Port > 65535 || r.Up < 0 || r.Down < 0 {
		return Event{}, ErrInvalid
	}
	if r.Start.IsZero() || r.Start.After(now.Add(10*time.Minute)) || r.Start.Before(now.Add(-48*time.Hour)) {
		return Event{}, ErrInvalid
	}
	if r.Seen.IsZero() || r.Seen.Before(r.Start) || r.Seen.After(now.Add(10*time.Minute)) {
		return Event{}, ErrInvalid
	}
	ev := Event{ID: id, Start: r.Start.UTC(), Seen: r.Seen.UTC(), Device: src, Port: r.Port, Protocol: r.Proto, Up: r.Up, Down: r.Down}
	if ev.DeviceName, ok = clean(r.Name, 64); !ok {
		return Event{}, ErrInvalid
	}
	if ev.Outbound, ok = clean(r.Out, 64); !ok {
		return Event{}, ErrInvalid
	}
	host, ok := clean(strings.ToLower(strings.TrimSuffix(r.Host, ".")), 253)
	if !ok {
		return Event{}, ErrInvalid
	}
	ev.Host = host
	if r.DstIP != "" {
		ip, err := netip.ParseAddr(r.DstIP)
		if err != nil {
			return Event{}, ErrInvalid
		}
		ev.DestIP = ip
	}
	if ev.Host == "" && !ev.DestIP.IsValid() {
		return Event{}, ErrInvalid
	}
	return ev, nil
}
