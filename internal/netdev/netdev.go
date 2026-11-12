// Package netdev reads what a network device (a MikroTik router) sends about itself. The device has no agent of ours: a script on it
// posts plain "key=value" lines once a minute, in a few small pieces because RouterOS limits how long a string may be. This
// package turns the lines into numbers, checking every field, whatever the device sends.
package netdev

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
)

const (
	MaxBody    = 64 << 10
	MaxIfaces  = 48
	MaxClients = 512
	MaxTop     = 10
	MaxNat     = 40
)

type Iface struct {
	Name  string  `json:"name"`
	RX    int64   `json:"rx"` // byte counters since the interface came up
	TX    int64   `json:"tx"`
	Up    bool    `json:"up"`
	RXBps float64 `json:"rx_bps"`
	TXBps float64 `json:"tx_bps"`
}

type Client struct {
	IP   string `json:"ip"`
	MAC  string `json:"mac"`
	Host string `json:"host,omitempty"`
}

// TopSource is a client address and how many tracked connections it holds.
type TopSource struct {
	IP string `json:"ip"`
	N  int64  `json:"n"`
}

// NatRule is a source or destination NAT rule with its hit counters.
type NatRule struct {
	Chain   string `json:"chain"`
	Action  string `json:"action"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
	DstPort string `json:"dst_port,omitempty"`
	ToAddr  string `json:"to_addr,omitempty"`
	ToPorts string `json:"to_ports,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// Report is one piece or the whole of what a device said. A piece without "cpu" carries no statistics (only clients, perhaps).
type Report struct {
	HasStats     bool
	Board        string
	Version      string
	UptimeSec    int64
	CPU          float64
	MemFree      int64
	MemTotal     int64
	Temp         *float64
	Ifaces       []Iface
	Clients      []Client
	ResetClients bool // the first piece of a client list: forget the old list
	HasConn      bool // the piece carries the connection count (and perhaps the top sources)
	Conn         int64
	ConnMax      int64
	Top          []TopSource
	ResetNat     bool // the first piece of the NAT rules: forget the old ones
	Nat          []NatRule
}

var uptimeRe = regexp.MustCompile(`^(?:(\d+)w)?(?:(\d+)d)?(\d+):(\d+):(\d+)$`)

// ParseUptime reads RouterOS's "1w2d03:04:05".
func ParseUptime(s string) (int64, bool) {
	m := uptimeRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, false
	}
	n := func(x string) int64 {
		v, _ := strconv.ParseInt(x, 10, 64)
		return v
	}
	return n(m[1])*7*86400 + n(m[2])*86400 + n(m[3])*3600 + n(m[4])*60 + n(m[5]), true
}

func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > n {
		s = s[:n]
	}
	return s
}

func num(s string, max int64) (int64, bool) {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return v, err == nil && v >= 0 && v <= max
}

// Parse reads the lines of one POST. Lines it does not understand are skipped; a body with nothing usable is an error.
func Parse(body string) (Report, error) {
	var r Report
	used := 0
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "board":
			r.Board, used = clean(v, 60), used+1
		case "version":
			r.Version, used = clean(v, 40), used+1
		case "uptime":
			if u, ok := ParseUptime(v); ok {
				r.UptimeSec, used = u, used+1
			}
		case "cpu":
			if c, ok := num(v, 100); ok {
				r.CPU, r.HasStats, used = float64(c), true, used+1
			}
		case "mem_free":
			if c, ok := num(v, 1<<50); ok {
				r.MemFree, used = c, used+1
			}
		case "mem_total":
			if c, ok := num(v, 1<<50); ok {
				r.MemTotal, used = c, used+1
			}
		case "temp":
			if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && f > -60 && f < 200 {
				r.Temp, used = &f, used+1
			}
		case "conn":
			if c, ok := num(v, 1<<40); ok {
				r.Conn, r.HasConn, used = c, true, used+1
			}
		case "conn_max":
			if c, ok := num(v, 1<<40); ok {
				r.ConnMax, used = c, used+1
			}
		case "top":
			f := strings.Split(v, ",")
			if len(f) < 2 || len(r.Top) >= MaxTop {
				continue
			}
			ip := net.ParseIP(strings.TrimSpace(f[0]))
			n, ok := num(f[1], 1<<40)
			if ip == nil || !ok {
				continue
			}
			r.Top, used = append(r.Top, TopSource{IP: ip.String(), N: n}), used+1
		case "reset_nat":
			r.ResetNat, used = true, used+1
		case "nat":
			// chain,action,packets,bytes,dst-port,to-addresses,to-ports,comment (the comment may hold commas)
			f := strings.SplitN(v, ",", 8)
			if len(f) < 4 || len(r.Nat) >= MaxNat {
				continue
			}
			pk, ok1 := num(f[2], 1<<62)
			by, ok2 := num(f[3], 1<<62)
			chain := clean(f[0], 20)
			if chain == "" || !ok1 || !ok2 {
				continue
			}
			n := NatRule{Chain: chain, Action: clean(f[1], 30), Packets: pk, Bytes: by}
			if len(f) > 4 {
				n.DstPort = clean(f[4], 40)
			}
			if len(f) > 5 {
				n.ToAddr = clean(f[5], 60)
			}
			if len(f) > 6 {
				n.ToPorts = clean(f[6], 40)
			}
			if len(f) > 7 {
				n.Comment = clean(f[7], 80)
			}
			r.Nat, used = append(r.Nat, n), used+1
		case "reset_clients":
			r.ResetClients, used = true, used+1
		case "if":
			f := strings.Split(v, ",")
			if len(f) < 4 || len(r.Ifaces) >= MaxIfaces {
				continue
			}
			name := clean(f[0], 40)
			rx, ok1 := num(f[1], 1<<62)
			tx, ok2 := num(f[2], 1<<62)
			if name == "" || !ok1 || !ok2 {
				continue
			}
			r.Ifaces, used = append(r.Ifaces, Iface{Name: name, RX: rx, TX: tx, Up: strings.TrimSpace(f[3]) == "true"}), used+1
		case "client":
			f := strings.Split(v, ",")
			if len(f) < 2 || len(r.Clients) >= MaxClients {
				continue
			}
			ip := net.ParseIP(strings.TrimSpace(f[0]))
			mac, err := net.ParseMAC(strings.TrimSpace(f[1]))
			if ip == nil || err != nil || len(mac) != 6 {
				continue
			}
			c := Client{IP: ip.String(), MAC: strings.ToUpper(mac.String())}
			if len(f) > 2 {
				c.Host = clean(f[2], 60)
			}
			r.Clients, used = append(r.Clients, c), used+1
		}
	}
	if used == 0 {
		return Report{}, errors.New("netdev: nothing usable in the body")
	}
	return r, nil
}
