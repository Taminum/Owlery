package dnsmap

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Provenance of a name in a map: how it came to be looked at.
const (
	ProvApex       = "apex"
	ProvWWW        = "www"
	ProvManual     = "manual_name"
	ProvExisting   = "existing_intel" // a name Network Intel found in public certificates
	ProvCNAMETaget = "cname_target"
)

// Limits that keep one run from becoming a crawl.
const (
	DefaultMaxNames   = 60
	DefaultConcurrent = 6
	maxAuthServers    = 4
)

var (
	apexTypes = []string{TypeA, TypeAAAA, TypeMX, TypeNS, TypeSOA, TypeTXT, TypeCAA, TypeDS, TypeDNSKEY}
	hostTypes = []string{TypeA, TypeAAAA}
	authTypes = []string{TypeSOA, TypeNS, TypeA, TypeMX, TypeTXT}
)

// Config is one run of a study.
type Config struct {
	Domain     string   // the apex, normalised: lower-case ASCII
	ExtraNames []string // names the operator added; only names inside the domain are looked at
	CTNames    []string // names found by Network Intel (provenance existing_intel)
	Resolvers  []netip.AddrPort
	MaxNames   int
	Client     *Client
	AuthPort   uint16 // 53 unless a test says otherwise
	Retry      time.Duration
}

type NameInfo struct {
	Name       string `json:"name"`
	Provenance string `json:"provenance"`
}

// ResolverView is what one server said about one record set.
type ResolverView struct {
	Server  string   `json:"server"`
	Outcome string   `json:"outcome"`
	Values  []string `json:"values,omitempty"`
}

// Rec is an observed record set with who said what.
type Rec struct {
	Obs
	Views []ResolverView `json:"views"`
}

type AuthAnswer struct {
	Outcome string   `json:"outcome"`
	Values  []string `json:"values,omitempty"`
	AA      bool     `json:"aa"`
}

// AuthServer is one authoritative server and its answers about the apex.
type AuthServer struct {
	NS      string                `json:"ns"`
	Addr    string                `json:"addr,omitempty"`
	Skipped string                `json:"skipped,omitempty"` // why it was not asked: unresolved, not_public
	Answers map[string]AuthAnswer `json:"answers,omitempty"`
}

// Coverage says plainly what a run looked at and what it did not.
type Coverage struct {
	Discovery          string   `json:"discovery"` // always "known_names": the names that were given or found, never the whole zone
	NamesTotal         int      `json:"names_total"`
	NamesChecked       int      `json:"names_checked"`
	NamesDropped       int      `json:"names_dropped"`
	Types              []string `json:"types"`
	Resolvers          []string `json:"resolvers"`
	Questions          int      `json:"questions"`
	Failures           int      `json:"failures"`    // questions neither resolver could settle
	Unconfirmed        int      `json:"unconfirmed"` // questions the two resolvers answered differently, or only one answered
	DNSSEC             string   `json:"dnssec"`      // not_checked: DS and DNSKEY are shown as records, nothing is validated
	AuthoritativeAsked int      `json:"authoritative_asked"`
}

type RunResult struct {
	Names    []NameInfo
	Recs     []Rec
	Auth     []AuthServer
	Mismatch []string // record sets on which authoritative servers disagree with each other or with the resolvers
	Coverage Coverage
	Status   string // ok | partial | failed
}

type question struct{ name, typ string }

func within(domain, name string) bool { return name == domain || strings.HasSuffix(name, "."+domain) }

func (c *Config) maxNames() int {
	if c.MaxNames > 0 {
		return c.MaxNames
	}
	return DefaultMaxNames
}

func uniqSorted(v []string) []string {
	m := map[string]bool{}
	for _, x := range v {
		m[x] = true
	}
	out := make([]string, 0, len(m))
	for x := range m {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

func sameSet(a, b []string) bool {
	a, b = uniqSorted(a), uniqSorted(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// planNames lists the names to look at, in order, with how each came to be there.
func (c *Config) planNames() (names []NameInfo, dropped int) {
	seen := map[string]bool{}
	add := func(n, prov string) {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if seen[n] || !ValidName(n) || !within(c.Domain, n) {
			if n != "" && !seen[n] {
				dropped++
			}
			return
		}
		if len(names) >= c.maxNames() {
			dropped++
			return
		}
		seen[n] = true
		names = append(names, NameInfo{Name: n, Provenance: prov})
	}
	add(c.Domain, ProvApex)
	add("www."+c.Domain, ProvWWW)
	for _, n := range c.ExtraNames {
		add(n, ProvManual)
	}
	for _, n := range c.CTNames {
		add(n, ProvExisting)
	}
	return names, dropped
}

// ask puts one question to every resolver at once.
func (c *Config) ask(ctx context.Context, name, typ string) []Answer {
	out := make([]Answer, len(c.Resolvers))
	var wg sync.WaitGroup
	for i, r := range c.Resolvers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = c.Client.Query(ctx, r, name, typ, true)
		}()
	}
	wg.Wait()
	return out
}

func valuesAt(a Answer, owner, typ string) []string {
	var v []string
	for _, r := range a.RRs {
		if r.Name == owner && r.Type == typ {
			v = append(v, r.Value)
		}
	}
	return uniqSorted(v)
}

func ttlAt(a Answer, owner, typ string) uint32 {
	var ttl uint32
	for _, r := range a.RRs {
		if r.Name == owner && r.Type == typ && (ttl == 0 || r.TTL < ttl) {
			ttl = r.TTL
		}
	}
	return ttl
}

// owners lists the (owner, type) pairs a reply contains, the asked pair first.
func owners(a Answer, name, typ string) []Key {
	keys := []Key{{name, typ}}
	seen := map[Key]bool{{name, typ}: true}
	for _, r := range a.RRs {
		k := Key{r.Name, r.Type}
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	return keys
}

// agree says whether the resolvers' answers are the same fact: the same outcome and, for answers, the same records.
func agree(as []Answer) bool {
	for _, a := range as[1:] {
		if a.Outcome != as[0].Outcome {
			return false
		}
		if a.Outcome == OutcomeAnswer {
			ka, kb := owners(as[0], "", ""), owners(a, "", "")
			if len(ka) != len(kb) {
				return false
			}
			for _, k := range ka {
				if !sameSet(valuesAt(as[0], k.Name, k.Type), valuesAt(a, k.Name, k.Type)) {
					return false
				}
			}
		}
	}
	return true
}

// settle picks the answer that speaks for a question: the first resolver that gave a complete answer.
func settle(as []Answer) (Answer, bool) {
	for _, a := range as {
		if Settled(a.Outcome) {
			return a, true
		}
	}
	return as[0], false
}

// combine turns the answers to one question into record sets: the one asked about, and any CNAME chain the
// answer carried.
func combine(name, typ string, as []Answer) (recs []Rec, confirmed, failed bool) {
	main, ok := settle(as)
	if !ok {
		recs = append(recs, Rec{Obs: Obs{Name: name, Type: typ, Result: main.Outcome}, Views: views(as, name, typ)})
		return recs, false, true
	}
	confirmed = len(as) > 1 && agree(as)
	for _, k := range owners(main, name, typ) {
		vals := valuesAt(main, k.Name, k.Type)
		res := OutcomeAnswer
		if len(vals) == 0 {
			res = OutcomeNoData
		}
		if k.Name == name && k.Type == typ && main.Outcome != OutcomeAnswer {
			res = main.Outcome
		}
		recs = append(recs, Rec{Obs: Obs{Name: k.Name, Type: k.Type, Result: res, Values: vals, TTL: ttlAt(main, k.Name, k.Type), Confirmed: confirmed}, Views: views(as, k.Name, k.Type)})
	}
	return recs, confirmed, false
}

func views(as []Answer, name, typ string) []ResolverView {
	out := make([]ResolverView, 0, len(as))
	for _, a := range as {
		out = append(out, ResolverView{Server: a.Server, Outcome: a.Outcome, Values: valuesAt(a, name, typ)})
	}
	return out
}

// Run looks at every planned name with the types that make sense for it, asks two resolvers each question,
// puts a disagreement to them once more, and, for the apex, asks the authoritative servers too. It never
// returns an error: whatever could not be settled is in the result as such.
func Run(ctx context.Context, cfg Config) RunResult {
	if cfg.Client == nil {
		cfg.Client = &Client{}
	}
	retry := cfg.Retry
	if retry <= 0 {
		retry = 2 * time.Second
	}
	names, dropped := cfg.planNames()
	res := RunResult{Names: names, Coverage: Coverage{Discovery: "known_names", NamesTotal: len(names) + dropped, NamesDropped: dropped, DNSSEC: "not_checked"}}
	for _, r := range cfg.Resolvers {
		res.Coverage.Resolvers = append(res.Coverage.Resolvers, r.String())
	}
	typeSet := map[string]bool{}

	var qs []question
	for _, n := range names {
		ts := hostTypes
		if n.Name == cfg.Domain {
			ts = apexTypes
		}
		for _, t := range ts {
			qs = append(qs, question{n.Name, t})
			typeSet[t] = true
		}
	}
	qs = append(qs, question{"_dmarc." + cfg.Domain, TypeTXT})
	res.Coverage.Questions = len(qs)

	conc := DefaultConcurrent
	sem := make(chan struct{}, conc)
	var mu sync.Mutex
	var wg sync.WaitGroup
	byKey := map[Key]Rec{}
	checked := map[string]bool{}
	for _, q := range qs {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			as := cfg.ask(ctx, q.name, q.typ)
			if _, ok := settle(as); ok && len(as) > 1 && !agree(as) {
				// Two resolvers saying different things is often propagation: look once more before trusting it.
				select {
				case <-time.After(retry):
					as = cfg.ask(ctx, q.name, q.typ)
				case <-ctx.Done():
				}
			}
			recs, confirmed, failed := combine(q.name, q.typ, as)
			mu.Lock()
			defer mu.Unlock()
			if q.name != "_dmarc."+cfg.Domain { // a policy lookup, not one of the map's names
				checked[q.name] = true
			}
			switch {
			case failed:
				res.Coverage.Failures++
			case !confirmed:
				res.Coverage.Unconfirmed++
			}
			for _, r := range recs {
				k := Key{r.Name, r.Type}
				// A record set seen as part of a chain keeps the stronger of two sightings.
				if old, seen := byKey[k]; seen && old.Confirmed && !r.Confirmed {
					continue
				}
				byKey[k] = r
			}
		}()
	}
	wg.Wait()
	res.Coverage.NamesChecked = len(checked)
	for t := range typeSet {
		res.Coverage.Types = append(res.Coverage.Types, t)
	}
	sort.Strings(res.Coverage.Types)
	for k, r := range byKey {
		res.Recs = append(res.Recs, r)
		if k.Type == TypeCNAME && Settled(r.Result) {
			for _, v := range r.Values {
				if within(cfg.Domain, v) && !hasName(res.Names, v) {
					res.Names = append(res.Names, NameInfo{Name: v, Provenance: ProvCNAMETaget})
				}
			}
		}
	}
	sort.Slice(res.Recs, func(i, j int) bool {
		if res.Recs[i].Name != res.Recs[j].Name {
			return res.Recs[i].Name < res.Recs[j].Name
		}
		return res.Recs[i].Type < res.Recs[j].Type
	})

	res.Auth, res.Mismatch = cfg.authoritative(ctx, byKey)
	for _, a := range res.Auth {
		if a.Addr != "" {
			res.Coverage.AuthoritativeAsked++
		}
	}
	res.Status = status(res, cfg.Domain, byKey)
	return res
}

func hasName(ns []NameInfo, n string) bool {
	for _, x := range ns {
		if x.Name == n {
			return true
		}
	}
	return false
}

// status is "failed" when not even the apex's basic records could be settled, "partial" when some question
// could not be settled, and "ok" otherwise.
func status(r RunResult, domain string, by map[Key]Rec) string {
	basic := 0
	for _, t := range []string{TypeSOA, TypeNS, TypeA} {
		if rec, ok := by[Key{domain, t}]; ok && Settled(rec.Result) {
			basic++
		}
	}
	switch {
	case basic == 0:
		return "failed"
	case r.Coverage.Failures > 0:
		return "partial"
	}
	return "ok"
}

// authoritative asks the delegated servers of the apex directly, without recursion, and notes where they
// disagree with each other or with what the resolvers returned. It only goes to public addresses.
func (c *Config) authoritative(ctx context.Context, by map[Key]Rec) ([]AuthServer, []string) {
	ns, ok := by[Key{c.Domain, TypeNS}]
	if !ok || !Settled(ns.Result) || len(ns.Values) == 0 {
		return nil, nil
	}
	port := c.AuthPort
	if port == 0 {
		port = 53
	}
	hosts := ns.Values
	if len(hosts) > maxAuthServers {
		hosts = hosts[:maxAuthServers]
	}
	var servers []AuthServer
	for _, h := range hosts {
		s := AuthServer{NS: h}
		var addr netip.Addr
		for _, t := range []string{TypeA, TypeAAAA} {
			a := c.Client.Query(ctx, c.Resolvers[0], h, t, true)
			for _, v := range valuesAt(a, h, t) {
				if ip, err := netip.ParseAddr(v); err == nil && !addr.IsValid() {
					addr = ip
				}
			}
			if addr.IsValid() {
				break
			}
		}
		switch {
		case !addr.IsValid():
			s.Skipped = "unresolved"
		case !c.Client.allowed(addr):
			s.Skipped = "not_public"
		default:
			s.Addr = addr.String()
			s.Answers = map[string]AuthAnswer{}
			for _, t := range authTypes {
				a := c.Client.Query(ctx, netip.AddrPortFrom(addr, port), c.Domain, t, false)
				s.Answers[t] = AuthAnswer{Outcome: a.Outcome, Values: valuesAt(a, c.Domain, t), AA: a.AA}
			}
		}
		servers = append(servers, s)
	}

	var mismatch []string
	for _, t := range authTypes {
		var first *AuthAnswer
		differ := false
		for _, s := range servers {
			a, ok := s.Answers[t]
			if !ok || !Settled(a.Outcome) {
				continue
			}
			if first == nil {
				first = &a
				continue
			}
			if t == TypeSOA {
				continue // serials lag a little between servers; the SOA is compared separately below
			}
			if !sameSet(first.Values, a.Values) {
				differ = true
			}
		}
		if t == TypeSOA {
			serials := map[string]bool{}
			for _, s := range servers {
				if a, ok := s.Answers[t]; ok && a.Outcome == OutcomeAnswer && len(a.Values) > 0 {
					serials[a.Values[0]] = true
				}
			}
			differ = len(serials) > 1
		}
		if first != nil {
			if rec, ok := by[Key{c.Domain, t}]; ok && rec.Confirmed && t != TypeSOA && Settled(rec.Result) && !sameSet(rec.Values, first.Values) {
				differ = true
			}
		}
		if differ {
			mismatch = append(mismatch, t)
		}
	}
	return servers, mismatch
}
