package netintel

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"
)

// Hop is one step of a route: the address that answered for a given TTL, or none.
type Hop struct {
	TTL     int       `json:"ttl"`
	Addr    string    `json:"addr,omitempty"`
	Owner   string    `json:"owner,omitempty"` // the network the router belongs to (local ASN database)
	ASN     uint32    `json:"asn,omitempty"`
	RTTms   []float64 `json:"rtt_ms"`  // one entry per answered probe
	Lost    int       `json:"lost"`    // probes that got no answer
	Reached bool      `json:"reached"` // the destination itself answered at this hop
	Note    string    `json:"note,omitempty"`
}

type TraceResult struct {
	Address string `json:"address"`
	Hops    []Hop  `json:"hops"`
	Reached bool   `json:"reached"`
}

// errTraceUnsupported is returned where the platform cannot trace without raw-socket privileges.
var errTraceUnsupported = errors.New("traceroute is not supported on this platform")

const (
	traceMaxHops   = 20
	traceProbes    = 3
	traceProbeWait = 1200 * time.Millisecond
)

// probeFn sends one echo request with the given TTL and says who answered.
type probeFn func(ctx context.Context, dst netip.Addr, ttl, seq int) (from netip.Addr, rtt time.Duration, reached bool, ok bool)

// Trace maps the route from this server to a public IPv4 address. A router that does not answer
// shows as a silent hop, which is normal: many drop the packets that traceroute depends on. The
// route is what this server sees, and can differ from what any other place sees. Never cached.
func (t *Tool) Trace(ctx context.Context, tg Target) Envelope {
	return t.trace(ctx, tg, probeTTL)
}

func (t *Tool) trace(ctx context.Context, tg Target, probe probeFn) Envelope {
	now := t.now().UTC()
	env := Envelope{Kind: "trace", Target: tg.Value, Display: tg.Display, FetchedAt: now, ExpiresAt: now, Vantage: "server"}
	addrs, err := t.publicAddrs(ctx, tg)
	if err != nil {
		env.Sources = []Source{{Name: "icmp-ttl", OK: false, Error: codeOf(err)}}
		return env
	}
	var dst netip.Addr
	for _, a := range addrs {
		if a.Is4() {
			dst = a
			break
		}
	}
	if !dst.IsValid() {
		env.Sources = []Source{{Name: "icmp-ttl", OK: false, Error: "unsupported"}} // IPv6 routes are not traced yet
		return env
	}
	res := TraceResult{Address: dst.String(), Hops: []Hop{}}
	for ttl := 1; ttl <= traceMaxHops && ctx.Err() == nil; ttl++ {
		hop := Hop{TTL: ttl, RTTms: []float64{}}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for i := 0; i < traceProbes; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				from, rtt, reached, ok := probe(ctx, dst, ttl, ttl*10+i)
				mu.Lock()
				defer mu.Unlock()
				if !ok {
					hop.Lost++
					return
				}
				hop.RTTms = append(hop.RTTms, float64(rtt.Microseconds())/1000)
				if hop.Addr == "" && from.IsValid() {
					hop.Addr = from.String()
				}
				hop.Reached = hop.Reached || reached
			}()
		}
		wg.Wait()
		if hop.Addr != "" && t.ASN != nil {
			if a, err := netip.ParseAddr(hop.Addr); err == nil {
				if o, ok := t.ASN.Lookup(a); ok {
					hop.Owner, hop.ASN = o.Org, o.ASN
				}
			}
		}
		res.Hops = append(res.Hops, hop)
		if hop.Reached {
			res.Reached = true
			break
		}
	}
	if len(res.Hops) == 0 || (len(res.Hops) > 0 && allSilent(res.Hops) && probeUnsupported(probe)) {
		env.Sources = []Source{{Name: "icmp-ttl", OK: false, Error: "unsupported"}}
		return env
	}
	env.Sources = []Source{{Name: "icmp-ttl", OK: true}}
	env.Data = res
	return env
}

func allSilent(h []Hop) bool {
	for _, x := range h {
		if len(x.RTTms) > 0 {
			return false
		}
	}
	return true
}

// probeUnsupported lets the platform file say that its probe cannot work at all (so a route of
// silent hops is reported as "unsupported", not as a network that eats every packet).
func probeUnsupported(probeFn) bool { return !traceSupported }
