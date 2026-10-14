package netintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Taminum/RemnaScope/internal/asn"
	"github.com/Taminum/RemnaScope/internal/geoip"
	"github.com/Taminum/RemnaScope/internal/safehttp"
)

// Source says where a piece of a result came from, and whether it could be had.
type Source struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"` // a short code, never a provider message
}

// Envelope wraps every result with when and from where it was obtained.
type Envelope struct {
	Kind      string    `json:"kind"`
	Target    string    `json:"target"`
	Display   string    `json:"display"`
	FetchedAt time.Time `json:"fetched_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Cached    bool      `json:"cached"`
	Vantage   string    `json:"vantage"` // always "server": the view from the machine RemnaScope runs on
	Sources   []Source  `json:"sources"`
	Data      any       `json:"data"`
}

// Resolver is the part of net.Resolver that is used; tests replace it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Tool runs the checks. Fetch is the SSRF-hardened client used for every outside request.
type Tool struct {
	Fetch    *safehttp.Client
	Resolver Resolver
	ASN      *asn.DB
	Geo      *geoip.DB
	Now      func() time.Time

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	env Envelope
	at  time.Time
}

func (t *Tool) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *Tool) resolver() Resolver {
	if t.Resolver != nil {
		return t.Resolver
	}
	return net.DefaultResolver
}

const maxCache = 300

// cachedRun returns a fresh cached result, or runs fn, caches and returns it. refresh skips the cache.
func (t *Tool) cachedRun(kind string, tg Target, ttl time.Duration, refresh bool, fn func() (any, []Source)) Envelope {
	key := kind + "|" + tg.Value
	t.mu.Lock()
	if c, ok := t.cache[key]; ok && !refresh && t.now().Before(c.env.ExpiresAt) {
		t.mu.Unlock()
		c.env.Cached = true
		return c.env
	}
	t.mu.Unlock()
	data, srcs := fn()
	now := t.now().UTC()
	env := Envelope{Kind: kind, Target: tg.Value, Display: tg.Display, FetchedAt: now, ExpiresAt: now.Add(ttl), Vantage: "server", Sources: srcs, Data: data}
	// Only keep results that got something: a total failure should be retried at once.
	if anyOK(srcs) {
		t.mu.Lock()
		if t.cache == nil || len(t.cache) > maxCache {
			t.cache = map[string]cached{}
		}
		t.cache[key] = cached{env: env, at: now}
		t.mu.Unlock()
	}
	return env
}

func anyOK(s []Source) bool {
	for _, x := range s {
		if x.OK {
			return true
		}
	}
	return len(s) == 0
}

// errCode keeps a provider or network error down to a short word that is safe to show.
func errCode(err error) string {
	if err == nil {
		return ""
	}
	var se *safehttp.Error
	if errors.As(err, &se) {
		return se.Code
	}
	var dnsErr *net.DNSError
	switch {
	case asDNS(err, &dnsErr) && dnsErr.IsNotFound:
		return "not_found"
	case asDNS(err, &dnsErr) && dnsErr.IsTimeout:
		return "timeout"
	case strings.Contains(err.Error(), "deadline"), strings.Contains(err.Error(), "timeout"):
		return "timeout"
	}
	return "unavailable"
}

func asDNS(err error, target **net.DNSError) bool {
	for err != nil {
		if d, ok := err.(*net.DNSError); ok {
			*target = d
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// ---- DNS ----------------------------------------------------------------------------------------

type MX struct {
	Host     string `json:"host"`
	Priority uint16 `json:"priority"`
}

type DNSRecords struct {
	A     []string `json:"a"`
	AAAA  []string `json:"aaaa"`
	CNAME string   `json:"cname,omitempty"`
	MX    []MX     `json:"mx"`
	NS    []string `json:"ns"`
	TXT   []string `json:"txt"`
}

// Records fetches the usual record types of a domain with the system resolver. A type that does not
// exist is simply empty; only a failure of the resolver itself counts as an error.
func (t *Tool) Records(ctx context.Context, tg Target, refresh bool) Envelope {
	return t.cachedRun("dns", tg, 10*time.Minute, refresh, func() (any, []Source) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		r := t.resolver()
		out := DNSRecords{A: []string{}, AAAA: []string{}, MX: []MX{}, NS: []string{}, TXT: []string{}}
		var failed int
		note := func(err error) {
			var d *net.DNSError
			if err != nil && !(asDNS(err, &d) && d.IsNotFound) {
				failed++
			}
		}
		if ips, err := r.LookupNetIP(ctx, "ip4", tg.Value); err == nil {
			for _, ip := range ips {
				out.A = append(out.A, ip.String())
			}
		} else {
			note(err)
		}
		if ips, err := r.LookupNetIP(ctx, "ip6", tg.Value); err == nil {
			for _, ip := range ips {
				out.AAAA = append(out.AAAA, ip.String())
			}
		} else {
			note(err)
		}
		if c, err := r.LookupCNAME(ctx, tg.Value); err == nil {
			if c = strings.TrimSuffix(c, "."); c != tg.Value {
				out.CNAME = c
			}
		} else {
			note(err)
		}
		if mx, err := r.LookupMX(ctx, tg.Value); err == nil {
			for _, m := range mx {
				out.MX = append(out.MX, MX{Host: strings.TrimSuffix(m.Host, "."), Priority: m.Pref})
			}
			sort.Slice(out.MX, func(i, j int) bool { return out.MX[i].Priority < out.MX[j].Priority })
		} else {
			note(err)
		}
		if ns, err := r.LookupNS(ctx, tg.Value); err == nil {
			for _, n := range ns {
				out.NS = append(out.NS, strings.TrimSuffix(n.Host, "."))
			}
			sort.Strings(out.NS)
		} else {
			note(err)
		}
		if txt, err := r.LookupTXT(ctx, tg.Value); err == nil {
			out.TXT = txt
		} else {
			note(err)
		}
		sort.Strings(out.A)
		sort.Strings(out.AAAA)
		src := Source{Name: "system-dns", OK: failed < 3}
		if !src.OK {
			src.Error = "unavailable"
		}
		return out, []Source{src}
	})
}

// ---- IP ----------------------------------------------------------------------------------------

type RDAPInfo struct {
	Name       string `json:"name,omitempty"`
	Handle     string `json:"handle,omitempty"`
	Range      string `json:"range,omitempty"`
	CIDR       string `json:"cidr,omitempty"`
	Org        string `json:"org,omitempty"`
	Country    string `json:"country,omitempty"`
	Registered string `json:"registered,omitempty"`
	Changed    string `json:"changed,omitempty"`
}

type IPInfo struct {
	IP      string    `json:"ip"`
	Version int       `json:"version"`
	Public  bool      `json:"public"`
	PTR     string    `json:"ptr,omitempty"`
	ASN     uint32    `json:"asn,omitempty"`
	Owner   string    `json:"owner,omitempty"` // the owner of the address range, not the service behind it
	Country string    `json:"country,omitempty"`
	RDAP    *RDAPInfo `json:"rdap,omitempty"`
}

// IP describes one address: the local ASN and country databases first (always available), then
// reverse DNS and RDAP. A private address gets no outside request at all.
func (t *Tool) IP(ctx context.Context, tg Target, refresh bool) Envelope {
	return t.cachedRun("ip", tg, 30*time.Minute, refresh, func() (any, []Source) {
		ip := tg.Addr
		info := IPInfo{IP: ip.String(), Version: 4}
		if ip.Is6() {
			info.Version = 6
		}
		info.Public = PublicOnly(ip) == nil
		if !info.Public {
			return info, []Source{{Name: "local", OK: true}}
		}
		srcs := []Source{}
		if t.ASN != nil {
			if o, ok := t.ASN.Lookup(ip); ok {
				info.ASN, info.Owner = o.ASN, o.Org
			}
			srcs = append(srcs, Source{Name: "dbip-asn", OK: info.ASN != 0})
		}
		if t.Geo != nil {
			info.Country = t.Geo.Country(ip)
			srcs = append(srcs, Source{Name: "dbip-country", OK: info.Country != ""})
		}
		var wg sync.WaitGroup
		var rdap *RDAPInfo
		var rdapErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, 6*time.Second)
			defer cancel()
			if names, err := t.resolver().LookupAddr(c, ip.String()); err == nil && len(names) > 0 {
				info.PTR = strings.TrimSuffix(names[0], ".")
			}
		}()
		go func() {
			defer wg.Done()
			rdap, rdapErr = t.rdap(ctx, ip)
		}()
		wg.Wait()
		info.RDAP = rdap
		srcs = append(srcs, Source{Name: "rdap", OK: rdapErr == nil, Error: errCode(rdapErr)})
		return info, srcs
	})
}

func (t *Tool) rdap(ctx context.Context, ip netip.Addr) (*RDAPInfo, error) {
	if t.Fetch == nil {
		return nil, fmt.Errorf("unavailable")
	}
	resp, err := t.rdapGet(ctx, "https://rdap.org/ip/"+ip.String())
	if err != nil {
		return nil, err
	}
	if resp.Status != 200 {
		return nil, fmt.Errorf("status %d", resp.Status)
	}
	var d struct {
		Name, Handle, Country string
		Start                 string `json:"startAddress"`
		End                   string `json:"endAddress"`
		CIDRs                 []struct {
			V4  string `json:"v4prefix"`
			V6  string `json:"v6prefix"`
			Len int    `json:"length"`
		} `json:"cidr0_cidrs"`
		Entities []struct {
			Roles  []string `json:"roles"`
			Handle string   `json:"handle"`
			VCard  []any    `json:"vcardArray"`
		} `json:"entities"`
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
	}
	if json.Unmarshal(resp.Body, &d) != nil {
		return nil, fmt.Errorf("bad reply")
	}
	out := &RDAPInfo{Name: clip(d.Name, 100), Handle: clip(d.Handle, 100), Country: clip(d.Country, 8)}
	if d.Start != "" && d.End != "" {
		out.Range = clip(d.Start+" – "+d.End, 120)
	}
	if len(d.CIDRs) > 0 {
		c := d.CIDRs[0]
		p := c.V4
		if p == "" {
			p = c.V6
		}
		if p != "" {
			out.CIDR = fmt.Sprintf("%s/%d", clip(p, 60), c.Len)
		}
	}
	for _, role := range []string{"registrant", "administrative", "technical", "abuse"} {
		for _, e := range d.Entities {
			for _, r := range e.Roles {
				if r == role && out.Org == "" {
					out.Org = clip(vcardName(e.VCard), 120)
				}
			}
		}
	}
	for _, e := range d.Events {
		switch e.Action {
		case "registration":
			out.Registered = clip(e.Date, 40)
		case "last changed":
			out.Changed = clip(e.Date, 40)
		}
	}
	return out, nil
}

func vcardName(v []any) string {
	if len(v) < 2 {
		return ""
	}
	props, _ := v[1].([]any)
	for _, p := range props {
		row, _ := p.([]any)
		if len(row) >= 4 && row[0] == "fn" {
			s, _ := row[3].(string)
			return s
		}
	}
	return ""
}

func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---- domain overview ------------------------------------------------------------------------------

type DomainOverview struct {
	DNS DNSRecords `json:"dns"`
	IPs []IPInfo   `json:"ips"`
}

// Domain resolves a domain and describes every address it points to.
func (t *Tool) Domain(ctx context.Context, tg Target, refresh bool) Envelope {
	return t.cachedRun("domain", tg, 10*time.Minute, refresh, func() (any, []Source) {
		dnsEnv := t.Records(ctx, tg, refresh)
		rec, _ := dnsEnv.Data.(DNSRecords)
		ov := DomainOverview{DNS: rec, IPs: []IPInfo{}}
		srcs := append([]Source{}, dnsEnv.Sources...)
		seen := map[string]bool{}
		addrs := append(append([]string{}, rec.A...), rec.AAAA...)
		if len(addrs) > 12 {
			addrs = addrs[:12]
		}
		for _, s := range addrs {
			a, err := netip.ParseAddr(s)
			if err != nil || seen[s] {
				continue
			}
			seen[s] = true
			env := t.IP(ctx, Target{Kind: KindIP, Value: a.String(), Display: a.String(), Addr: a}, refresh)
			if d, ok := env.Data.(IPInfo); ok {
				ov.IPs = append(ov.IPs, d)
			}
			for _, x := range env.Sources {
				if x.Name == "rdap" {
					srcs = appendSource(srcs, x)
				}
			}
		}
		return ov, srcs
	})
}

// appendSource keeps one entry per source name; one working address is enough for "ok".
func appendSource(s []Source, x Source) []Source {
	for i := range s {
		if s[i].Name == x.Name {
			if x.OK {
				s[i] = x
			}
			return s
		}
	}
	return append(s, x)
}
