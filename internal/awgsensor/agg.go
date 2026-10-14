package awgsensor

import (
	"net/netip"
	"sort"
	"time"
)

// Direction of a packet relative to the AmneziaWG interface.
type Dir int

const (
	FromClient Dir = iota // a device sent it into the tunnel
	ToClient              // the server sends it to a device
)

// Limits that keep the sensor's memory flat whatever the network does.
const (
	MaxFlows      = 20000 // distinct flows in one reporting window; further new ones are counted as dropped
	MaxNames      = 50000 // flows whose name is remembered between windows
	MaxDNSPerHost = 4096  // address-to-name pairs remembered per device
	nameIdle      = 30 * time.Minute
	dnsTTL        = 10 * time.Minute
	udpIdle       = 2 * time.Minute
)

type key struct {
	client netip.Addr
	proto  uint8
	remote netip.Addr
	port   uint16
}

type flow struct {
	up, down    uint64
	first, last time.Time
	started     bool // a connection began in this window (TCP SYN, or a UDP flow not seen in the last minutes)
}

type nameEntry struct {
	name, how string
	seen      time.Time
}

type dnsEntry struct {
	name string
	exp  time.Time
}

// Flow is what one window reports about one flow: the traffic since the last report.
type Flow struct {
	Client      netip.Addr
	Proto       uint8
	Remote      netip.Addr
	Port        uint16
	Up, Down    uint64 // bytes from the device / to the device
	First, Last time.Time
	Name, How   string // the destination's name and where it came from; empty when nothing said it
	Started     bool   // the flow began in this window: counts as one new connection
}

// Aggregator folds packets into flows. It is not safe for concurrent use.
type Aggregator struct {
	flows   map[key]*flow
	names   map[key]nameEntry
	seen    map[key]time.Time // when each non-TCP flow was last seen: a flow absent for a while starts again
	dns     map[netip.Addr]map[netip.Addr]dnsEntry
	Dropped uint64 // packets that belonged to a flow beyond MaxFlows since the last Flush
}

func New() *Aggregator {
	return &Aggregator{flows: map[key]*flow{}, names: map[key]nameEntry{}, seen: map[key]time.Time{}, dns: map[netip.Addr]map[netip.Addr]dnsEntry{}}
}

// Add takes one IP packet that crossed the interface.
func (a *Aggregator) Add(dir Dir, ip []byte, now time.Time) {
	pk, ok := ParseIP(ip)
	if !ok || pk.Len <= 0 {
		return
	}
	var k key
	if dir == FromClient {
		k = key{pk.Src.Unmap(), pk.Proto, pk.Dst.Unmap(), pk.DPort}
	} else {
		k = key{pk.Dst.Unmap(), pk.Proto, pk.Src.Unmap(), pk.SPort}
	}
	// Names first: a DNS answer teaches the device's address book, a handshake or a request names the flow.
	switch {
	case dir == ToClient && pk.Proto == 17 && pk.SPort == 53:
		if name, addrs := DNSAnswer(pk.Payload); name != "" {
			a.learn(k.client, name, addrs, now)
		}
		k.port = 53
	case dir == FromClient && pk.Proto == 6 && pk.DPort == 443 && len(pk.Payload) > 0:
		if n := SNI(pk.Payload); n != "" {
			a.setName(k, n, HowSNI, now)
		}
	case dir == FromClient && pk.Proto == 6 && pk.DPort == 80 && len(pk.Payload) > 0:
		if n := HTTPHost(pk.Payload); n != "" {
			a.setName(k, n, HowHost, now)
		}
	}
	f := a.flows[k]
	if f == nil {
		if len(a.flows) >= MaxFlows {
			a.Dropped++
			return
		}
		f = &flow{first: now}
		a.flows[k] = f
	}
	f.last = now
	if pk.Proto == 6 {
		f.started = f.started || (dir == FromClient && pk.SYN)
	} else if t, ok := a.seen[k]; !ok || now.Sub(t) > udpIdle {
		if len(a.seen) < MaxFlows*2 {
			f.started = true
		}
	}
	if pk.Proto != 6 && len(a.seen) < MaxFlows*2 {
		a.seen[k] = now
	}
	if dir == FromClient {
		f.up += uint64(pk.Len)
	} else {
		f.down += uint64(pk.Len)
	}
}

func (a *Aggregator) learn(client netip.Addr, name string, addrs []netip.Addr, now time.Time) {
	m := a.dns[client]
	if m == nil {
		m = map[netip.Addr]dnsEntry{}
		a.dns[client] = m
	}
	if len(m) >= MaxDNSPerHost { // an address book that large is noise: start again rather than grow
		clear(m)
	}
	for _, ad := range addrs {
		m[ad.Unmap()] = dnsEntry{name, now.Add(dnsTTL)}
	}
}

func (a *Aggregator) setName(k key, name, how string, now time.Time) {
	if len(a.names) >= MaxNames {
		if _, known := a.names[k]; !known {
			return
		}
	}
	a.names[k] = nameEntry{name, how, now}
}

// Flush returns what happened since the last call and starts a new window. Flows that carried nothing
// are not reported; names stay remembered for the flows that are still alive.
func (a *Aggregator) Flush(now time.Time) []Flow {
	out := make([]Flow, 0, len(a.flows))
	for k, f := range a.flows {
		if f.up+f.down == 0 {
			continue
		}
		fl := Flow{Client: k.client, Proto: k.proto, Remote: k.remote, Port: k.port, Up: f.up, Down: f.down, First: f.first, Last: f.last, Started: f.started}
		if n, ok := a.names[k]; ok {
			fl.Name, fl.How = n.name, n.how
			a.names[k] = nameEntry{n.name, n.how, now}
		} else if d, ok := a.dns[k.client][k.remote]; ok && now.Before(d.exp) {
			fl.Name, fl.How = d.name, HowDNS
		}
		out = append(out, fl)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Up+out[i].Down > out[j].Up+out[j].Down })
	clear(a.flows)
	a.Dropped = 0
	for k, n := range a.names {
		if now.Sub(n.seen) > nameIdle {
			delete(a.names, k)
		}
	}
	for k, t := range a.seen {
		if now.Sub(t) > udpIdle {
			delete(a.seen, k)
		}
	}
	for c, m := range a.dns {
		for ad, d := range m {
			if now.After(d.exp) {
				delete(m, ad)
			}
		}
		if len(m) == 0 {
			delete(a.dns, c)
		}
	}
	return out
}
