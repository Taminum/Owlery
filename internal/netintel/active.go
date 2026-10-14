package netintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ---- subdomains (Certificate Transparency) ------------------------------------------------------

type Subdomains struct {
	Names     []string `json:"names"`
	Total     int      `json:"total"`
	Truncated bool     `json:"truncated"`
}

const maxSubdomains = 500

// Subdomains lists names seen in public certificates for a domain. It only knows names that got a
// certificate; a subdomain without one is invisible here, so the list is never "all subdomains".
func (t *Tool) Subdomains(ctx context.Context, tg Target, refresh bool) Envelope {
	return t.cachedRun("subdomains", tg, time.Hour, refresh, func() (any, []Source) {
		type res struct {
			name  string
			names []string
			err   error
		}
		fetchers := []struct {
			name string
			fn   func(context.Context, string) ([]string, error)
		}{{"crt.sh", t.crtsh}, {"certspotter", t.certspotter}}
		ch := make(chan res, len(fetchers))
		for _, f := range fetchers {
			go func() {
				c, cancel := context.WithTimeout(ctx, 25*time.Second)
				defer cancel()
				n, err := f.fn(c, tg.Value)
				ch <- res{f.name, n, err}
			}()
		}
		set := map[string]bool{tg.Value: true}
		srcs := []Source{}
		for range fetchers {
			r := <-ch
			srcs = append(srcs, Source{Name: r.name, OK: r.err == nil, Error: errCode(r.err)})
			for _, n := range r.names {
				set[n] = true
			}
		}
		sort.Slice(srcs, func(i, j int) bool { return srcs[i].Name < srcs[j].Name })
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sort.Strings(names)
		out := Subdomains{Total: len(names), Names: names}
		if len(names) > maxSubdomains {
			out.Names, out.Truncated = names[:maxSubdomains], true
		}
		return out, srcs
	})
}

// keepName accepts a name only if it belongs to the domain asked about and is a plain host name.
func keepName(n, domain string) (string, bool) {
	n = strings.ToLower(strings.TrimSpace(n))
	if n == "" || strings.HasPrefix(n, "*.") || len(n) > 253 {
		return "", false
	}
	if n != domain && !strings.HasSuffix(n, "."+domain) {
		return "", false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return "", false
		}
	}
	return n, true
}

func (t *Tool) crtsh(ctx context.Context, domain string) ([]string, error) {
	if t.Fetch == nil {
		return nil, fmt.Errorf("unavailable")
	}
	resp, err := t.Fetch.Get(ctx, "https://crt.sh/?output=json&q="+url.QueryEscape("%."+domain), nil)
	if err != nil {
		return nil, err
	}
	if resp.Status != 200 {
		return nil, fmt.Errorf("status %d", resp.Status)
	}
	var rows []struct {
		Names string `json:"name_value"`
	}
	if json.Unmarshal(resp.Body, &rows) != nil {
		return nil, fmt.Errorf("bad reply")
	}
	var out []string
	for _, r := range rows {
		for _, n := range strings.Split(r.Names, "\n") {
			if k, ok := keepName(n, domain); ok {
				out = append(out, k)
			}
		}
	}
	return out, nil
}

func (t *Tool) certspotter(ctx context.Context, domain string) ([]string, error) {
	if t.Fetch == nil {
		return nil, fmt.Errorf("unavailable")
	}
	resp, err := t.Fetch.Get(ctx, "https://api.certspotter.com/v1/issuances?include_subdomains=true&expand=dns_names&domain="+url.QueryEscape(domain), nil)
	if err != nil {
		return nil, err
	}
	if resp.Status != 200 {
		return nil, fmt.Errorf("status %d", resp.Status)
	}
	var rows []struct {
		Names []string `json:"dns_names"`
	}
	if json.Unmarshal(resp.Body, &rows) != nil {
		return nil, fmt.Errorf("bad reply")
	}
	var out []string
	for _, r := range rows {
		for _, n := range r.Names {
			if k, ok := keepName(n, domain); ok {
				out = append(out, k)
			}
		}
	}
	return out, nil
}

// ---- active checks ----------------------------------------------------------------------------------

// publicAddrs resolves a target to addresses and demands that every one of them is public.
func (t *Tool) publicAddrs(ctx context.Context, tg Target) ([]netip.Addr, error) {
	switch tg.Kind {
	case KindIP:
		return []netip.Addr{tg.Addr}, publicCheck(tg.Addr)
	case KindDomain:
		c, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		ips, err := t.resolver().LookupNetIP(c, "ip", tg.Value)
		if err != nil || len(ips) == 0 {
			return nil, &Error{"not_found", "домен не резолвится"}
		}
		out := make([]netip.Addr, 0, len(ips))
		for _, ip := range ips {
			ip = ip.Unmap()
			if err := publicCheck(ip); err != nil {
				return nil, &Error{"not_public", "домен указывает на непубличный адрес: проверка не выполняется"}
			}
			out = append(out, ip)
		}
		return out, nil
	}
	return nil, &Error{"invalid_target", "для этой проверки нужен домен или IP"}
}

type PingResult struct {
	Address   string    `json:"address"`
	Sent      int       `json:"sent"`
	Received  int       `json:"received"`
	LossPct   float64   `json:"loss_pct"`
	MinMs     *float64  `json:"min_ms"`
	AvgMs     *float64  `json:"avg_ms"`
	MaxMs     *float64  `json:"max_ms"`
	TimesMs   []float64 `json:"times_ms"`
	Reachable bool      `json:"reachable"`
}

// Ping sends ICMP echo requests (1 to 10) with an unprivileged datagram socket. A host that does not
// answer is not necessarily down: many drop ICMP. It is never cached.
func (t *Tool) Ping(ctx context.Context, tg Target, count int) Envelope {
	count = min(max(count, 1), 10)
	now := t.now().UTC()
	env := Envelope{Kind: "ping", Target: tg.Value, Display: tg.Display, FetchedAt: now, ExpiresAt: now, Vantage: "server"}
	addrs, err := t.publicAddrs(ctx, tg)
	if err != nil {
		env.Sources = []Source{{Name: "icmp", OK: false, Error: codeOf(err)}}
		return env
	}
	addr := addrs[0]
	for _, a := range addrs {
		if a.Is4() {
			addr = a
			break
		}
	}
	res, err := ping(ctx, addr, count)
	if err != nil {
		env.Sources = []Source{{Name: "icmp", OK: false, Error: "unavailable"}}
		return env
	}
	env.Sources = []Source{{Name: "icmp", OK: true}}
	env.Data = res
	return env
}

func codeOf(err error) string {
	if e, ok := IsError(err); ok {
		return e.Code
	}
	return errCode(err)
}

func ping(ctx context.Context, addr netip.Addr, count int) (PingResult, error) {
	network, proto, typ, replyType := "udp4", 1, icmp.Type(ipv4.ICMPTypeEcho), icmp.Type(ipv4.ICMPTypeEchoReply)
	listen := "0.0.0.0"
	if addr.Is6() {
		network, proto, typ, replyType, listen = "udp6", 58, ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply, "::"
	}
	conn, err := icmp.ListenPacket(network, listen)
	if err != nil {
		return PingResult{}, err
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: addr.AsSlice()}
	res := PingResult{Address: addr.String(), TimesMs: []float64{}}
	var sum float64
	id := os.Getpid() & 0xffff
	for seq := 1; seq <= count && ctx.Err() == nil; seq++ {
		msg := icmp.Message{Type: typ, Code: 0, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("remnascope")}}
		b, err := msg.Marshal(nil)
		if err != nil {
			return res, err
		}
		start := time.Now()
		if _, err := conn.WriteTo(b, dst); err != nil {
			return res, err
		}
		res.Sent++
		_ = conn.SetReadDeadline(start.Add(2 * time.Second))
		buf := make([]byte, 1500)
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				break
			}
			m, err := icmp.ParseMessage(proto, buf[:n])
			if err != nil || m.Type != replyType {
				continue
			}
			if e, ok := m.Body.(*icmp.Echo); ok && e.Seq == seq {
				ms := float64(time.Since(start).Microseconds()) / 1000
				res.TimesMs = append(res.TimesMs, ms)
				sum += ms
				res.Received++
				break
			}
		}
		if seq < count {
			select {
			case <-ctx.Done():
			case <-time.After(300 * time.Millisecond):
			}
		}
	}
	if res.Sent > 0 {
		res.LossPct = float64(res.Sent-res.Received) * 100 / float64(res.Sent)
	}
	res.Reachable = res.Received > 0
	if res.Received > 0 {
		mn, mx := res.TimesMs[0], res.TimesMs[0]
		for _, v := range res.TimesMs {
			mn, mx = min(mn, v), max(mx, v)
		}
		avg := sum / float64(res.Received)
		res.MinMs, res.AvgMs, res.MaxMs = &mn, &avg, &mx
	}
	return res, nil
}

type PortResult struct {
	Port  int    `json:"port"`
	Open  bool   `json:"open"`
	Error string `json:"error,omitempty"` // timeout | refused | unreachable
	Ms    int    `json:"ms,omitempty"`
}

type PortsResult struct {
	Address string       `json:"address"`
	Results []PortResult `json:"results"`
}

// DefaultPorts is what is checked when none are named.
var DefaultPorts = []int{80, 443}

// Ports tries a TCP connection to up to 20 ports. Every connection is made to the already checked
// address, and the dialer checks the destination again, so a name cannot change its answer between
// the check and the connection. Never cached.
func (t *Tool) Ports(ctx context.Context, tg Target, ports []int) Envelope {
	now := t.now().UTC()
	env := Envelope{Kind: "ports", Target: tg.Value, Display: tg.Display, FetchedAt: now, ExpiresAt: now, Vantage: "server"}
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	if len(ports) > 20 {
		ports = ports[:20]
	}
	addrs, err := t.publicAddrs(ctx, tg)
	if err != nil {
		env.Sources = []Source{{Name: "tcp", OK: false, Error: codeOf(err)}}
		return env
	}
	addr := addrs[0]
	d := guardedDialer(2500 * time.Millisecond)
	res := PortsResult{Address: addr.String(), Results: make([]PortResult, len(ports))}
	var wg sync.WaitGroup
	for i, p := range ports {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), fmt.Sprint(p)))
			r := PortResult{Port: p, Ms: int(time.Since(start).Milliseconds())}
			if err == nil {
				r.Open = true
				_ = c.Close()
			} else {
				r.Error, r.Ms = classifyDial(err), 0
			}
			res.Results[i] = r
		}()
	}
	wg.Wait()
	env.Sources = []Source{{Name: "tcp", OK: true}}
	env.Data = res
	return env
}

func classifyDial(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "refused"):
		return "refused"
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline"):
		return "timeout"
	}
	return "unreachable"
}
