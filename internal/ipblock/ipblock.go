// Package ipblock shuts out addresses that guess passwords. It counts failed remote sign-ins per address and, past a limit,
// has a firewall rule made for that address for a while. It decides; the firewall is behind an interface so that the
// decisions can be tested without touching one.
//
// What it never does, whatever it is told: block an address on a private or local network, one that signed in
// successfully in the last day, or one on the whitelist. A machine starts in watch mode, where it records what it would
// have blocked and changes nothing.
package ipblock

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

// Firewall is what the engine needs from the machine's firewall. Rules are the engine's own: it never lists or touches
// any other.
type Firewall interface {
	Block(ctx context.Context, ip netip.Addr) error
	Unblock(ctx context.Context, ip netip.Addr) error
	// Blocked lists the addresses the engine's rules are made for.
	Blocked(ctx context.Context) ([]netip.Addr, error)
}

// Config is what the person set up. The zero value is not usable: start from DefaultConfig.
type Config struct {
	Mode      string // secproto.BlockOff, BlockWatch or BlockOn
	Threshold int    // failures within Window that get an address blocked
	Window    time.Duration
	TTL       time.Duration // how long a block lasts; 0 is for good
	Whitelist []netip.Prefix
}

func DefaultConfig() Config {
	return Config{Mode: secproto.BlockWatch, Threshold: 5, Window: 10 * time.Minute, TTL: 24 * time.Hour}
}

func (c Config) normalised(allowBlock bool) Config {
	if c.Mode != secproto.BlockOff && c.Mode != secproto.BlockOn {
		c.Mode = secproto.BlockWatch
	}
	if c.Mode == secproto.BlockOn && !allowBlock {
		c.Mode = secproto.BlockWatch // the machine has not been set up to allow blocking
	}
	if c.Threshold < 2 {
		c.Threshold = 2
	}
	if c.Threshold > 1000 {
		c.Threshold = 1000
	}
	if c.Window < time.Minute {
		c.Window = time.Minute
	}
	if c.Window > 24*time.Hour {
		c.Window = 24 * time.Hour
	}
	if c.TTL < 0 {
		c.TTL = 0
	}
	if c.TTL > 365*24*time.Hour {
		c.TTL = 365 * 24 * time.Hour
	}
	return c
}

// Entry is one address the engine blocked or would have blocked.
type Entry struct {
	IP     netip.Addr
	Since  time.Time
	Until  time.Time // zero: no end
	Failed int
}

const (
	// safeFor is how long a successful sign-in protects its address.
	safeFor = 24 * time.Hour
	// wouldFor is how long a "would have blocked" is remembered when the block has no end.
	wouldFor    = 24 * time.Hour
	maxTracked  = 5000
	maxRemember = 2000
)

type Engine struct {
	mu         sync.Mutex
	cfg        Config
	allowBlock bool
	fw         Firewall
	path       string
	now        func() time.Time

	tries  map[netip.Addr][]time.Time
	active map[netip.Addr]Entry
	would  map[netip.Addr]Entry
	safe   map[netip.Addr]time.Time
	total  int64
	err    string
	synced bool
}

// New makes an engine. path is where it keeps its state across restarts ("" keeps nothing). allowBlock is the machine's
// permission to block at all.
func New(fw Firewall, path string, cfg Config, allowBlock bool) *Engine {
	e := &Engine{fw: fw, path: path, allowBlock: allowBlock, now: time.Now,
		tries: map[netip.Addr][]time.Time{}, active: map[netip.Addr]Entry{}, would: map[netip.Addr]Entry{}, safe: map[netip.Addr]time.Time{}}
	e.cfg = cfg.normalised(allowBlock)
	e.load()
	return e
}

// Config is what the engine works by now.
func (e *Engine) Config() Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

// SetConfig changes the settings. Leaving block mode lifts what was blocked: someone who turns it off wants it off.
func (e *Engine) SetConfig(ctx context.Context, c Config) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = c.normalised(e.allowBlock)
	if e.cfg.Mode != secproto.BlockOn {
		for ip := range e.active {
			e.release(ctx, ip)
		}
	}
	e.save()
}

// exempt says whether an address must not be blocked, and why does not matter.
func (e *Engine) exempt(ip netip.Addr, at time.Time) bool {
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, p := range e.cfg.Whitelist {
		if p.Contains(ip) {
			return true
		}
	}
	if until, ok := e.safe[ip]; ok && at.Before(until) {
		return true
	}
	return false
}

func parseIP(s string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

// OK tells the engine that this address signed in, so it is somebody's and is left alone for a day.
func (e *Engine) OK(ipStr string, at time.Time) {
	ip, ok := parseIP(ipStr)
	if !ok {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.safe) < maxTracked {
		e.safe[ip] = at.Add(safeFor)
	}
	delete(e.tries, ip)
}

// Fail counts one failed sign-in from this address, at the time the machine logged it.
func (e *Engine) Fail(ctx context.Context, ipStr string, at time.Time) {
	ip, ok := parseIP(ipStr)
	if !ok {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cfg.Mode == secproto.BlockOff || e.exempt(ip, at) {
		return
	}
	if _, on := e.active[ip]; on {
		return
	}
	if _, seen := e.would[ip]; seen {
		return
	}
	ts := e.tries[ip]
	cut := at.Add(-e.cfg.Window)
	keep := ts[:0]
	for _, t := range ts {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	keep = append(keep, at)
	if len(keep) < e.cfg.Threshold {
		if len(e.tries) >= maxTracked {
			if _, known := e.tries[ip]; !known {
				return // too many addresses at once; better to miss one than to grow without end
			}
		}
		e.tries[ip] = keep
		return
	}
	delete(e.tries, ip)
	now := e.now()
	en := Entry{IP: ip, Since: now, Failed: len(keep)}
	if e.cfg.TTL > 0 {
		en.Until = now.Add(e.cfg.TTL)
	}
	if e.cfg.Mode == secproto.BlockOn {
		if err := e.fw.Block(ctx, ip); err != nil {
			e.err = "the firewall did not take a rule"
			return
		}
		e.err = ""
		e.active[ip] = en
		e.total++
	} else {
		w := en
		w.Until = now.Add(wouldFor)
		if e.cfg.TTL > 0 {
			w.Until = now.Add(e.cfg.TTL)
		}
		if len(e.would) < maxRemember {
			e.would[ip] = w
		}
	}
	e.save()
}

func (e *Engine) release(ctx context.Context, ip netip.Addr) {
	if err := e.fw.Unblock(ctx, ip); err != nil {
		e.err = "the firewall did not remove a rule"
	}
	delete(e.active, ip)
}

// Unblock lifts a block (or forgets a would-have) by hand, and leaves the address alone for a day so it is not
// blocked again at once.
func (e *Engine) Unblock(ctx context.Context, ipStr string) bool {
	ip, ok := parseIP(ipStr)
	if !ok {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, a := e.active[ip]
	_, w := e.would[ip]
	if !a && !w {
		return false
	}
	if a {
		e.release(ctx, ip)
	}
	delete(e.would, ip)
	e.safe[ip] = e.now().Add(safeFor)
	e.save()
	return true
}

// Tick lifts the blocks whose time is up and forgets what is stale. The firewall is matched with what the engine thinks
// the first time it runs: a rule left behind by a crash is removed, a rule that went missing is made again.
func (e *Engine) Tick(ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	changed := false
	if !e.synced {
		e.synced = true
		e.reconcile(ctx)
	}
	for ip, en := range e.active {
		if !en.Until.IsZero() && !en.Until.After(now) {
			e.release(ctx, ip)
			changed = true
		}
	}
	for ip, en := range e.would {
		if !en.Until.After(now) {
			delete(e.would, ip)
			changed = true
		}
	}
	for ip, until := range e.safe {
		if !until.After(now) {
			delete(e.safe, ip)
			changed = true
		}
	}
	cut := now.Add(-e.cfg.Window)
	for ip, ts := range e.tries {
		if len(ts) == 0 || !ts[len(ts)-1].After(cut) {
			delete(e.tries, ip)
		}
	}
	if changed {
		e.save()
	}
}

func (e *Engine) reconcile(ctx context.Context) {
	have, err := e.fw.Blocked(ctx)
	if err != nil {
		e.err = "the firewall rules could not be read"
		return
	}
	in := map[netip.Addr]bool{}
	for _, ip := range have {
		in[ip] = true
		if _, ok := e.active[ip]; !ok {
			_ = e.fw.Unblock(ctx, ip)
		}
	}
	for ip := range e.active {
		if !in[ip] {
			if err := e.fw.Block(ctx, ip); err != nil {
				e.err = "the firewall did not take a rule"
			}
		}
	}
}

// Snapshot is the state in the shape the agent reports.
func (e *Engine) Snapshot() *secproto.WinBlock {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := &secproto.WinBlock{Mode: e.cfg.Mode, Threshold: e.cfg.Threshold, WindowMin: int(e.cfg.Window / time.Minute), TTLHours: int(e.cfg.TTL / time.Hour),
		Active: entries(e.active), Would: entries(e.would), Total: e.total, Error: e.err}
	return out
}

func entries(m map[netip.Addr]Entry) []secproto.WinBlockEntry {
	list := make([]Entry, 0, len(m))
	for _, en := range m {
		list = append(list, en)
	}
	sort.Slice(list, func(a, b int) bool {
		if !list[a].Since.Equal(list[b].Since) {
			return list[a].Since.After(list[b].Since)
		}
		return list[a].IP.Less(list[b].IP)
	})
	if len(list) > secproto.MaxWinBlocks {
		list = list[:secproto.MaxWinBlocks]
	}
	out := make([]secproto.WinBlockEntry, 0, len(list))
	for _, en := range list {
		x := secproto.WinBlockEntry{IP: en.IP.String(), Since: en.Since, Failed: en.Failed}
		if !en.Until.IsZero() {
			u := en.Until
			x.Until = &u
		}
		out = append(out, x)
	}
	return out
}

type savedConfig struct {
	Mode      string   `json:"mode"`
	Threshold int      `json:"threshold"`
	WindowMin int      `json:"window_min"`
	TTLHours  int      `json:"ttl_hours"`
	Whitelist []string `json:"whitelist"`
}

type saved struct {
	Config *savedConfig         `json:"config,omitempty"`
	Active []savedEntry         `json:"active"`
	Would  []savedEntry         `json:"would"`
	Safe   map[string]time.Time `json:"safe"`
	Total  int64                `json:"total"`
}

type savedEntry struct {
	IP     string    `json:"ip"`
	Since  time.Time `json:"since"`
	Until  time.Time `json:"until"`
	Failed int       `json:"failed"`
}

func (e *Engine) save() {
	if e.path == "" {
		return
	}
	s := saved{Safe: map[string]time.Time{}, Total: e.total}
	sc := savedConfig{Mode: e.cfg.Mode, Threshold: e.cfg.Threshold, WindowMin: int(e.cfg.Window / time.Minute), TTLHours: int(e.cfg.TTL / time.Hour)}
	for _, p := range e.cfg.Whitelist {
		sc.Whitelist = append(sc.Whitelist, p.String())
	}
	s.Config = &sc
	for _, en := range e.active {
		s.Active = append(s.Active, savedEntry{en.IP.String(), en.Since, en.Until, en.Failed})
	}
	for _, en := range e.would {
		s.Would = append(s.Would, savedEntry{en.IP.String(), en.Since, en.Until, en.Failed})
	}
	for ip, t := range e.safe {
		s.Safe[ip.String()] = t
	}
	b, err := json.Marshal(s)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(e.path), 0o700); err != nil {
		return
	}
	tmp := e.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, e.path)
}

func (e *Engine) load() {
	if e.path == "" {
		return
	}
	b, err := os.ReadFile(e.path)
	if err != nil {
		return
	}
	var s saved
	if json.Unmarshal(b, &s) != nil {
		return
	}
	if c := s.Config; c != nil {
		// What the person set up last wins over the defaults, so a restart does not undo it.
		cfg := Config{Mode: c.Mode, Threshold: c.Threshold, Window: time.Duration(c.WindowMin) * time.Minute, TTL: time.Duration(c.TTLHours) * time.Hour}
		for _, w := range c.Whitelist {
			if p, err := netip.ParsePrefix(w); err == nil {
				cfg.Whitelist = append(cfg.Whitelist, p)
			}
		}
		e.cfg = cfg.normalised(e.allowBlock)
	}
	for _, x := range s.Active {
		if ip, ok := parseIP(x.IP); ok && e.cfg.Mode == secproto.BlockOn {
			e.active[ip] = Entry{IP: ip, Since: x.Since, Until: x.Until, Failed: x.Failed}
		}
	}
	for _, x := range s.Would {
		if ip, ok := parseIP(x.IP); ok {
			e.would[ip] = Entry{IP: ip, Since: x.Since, Until: x.Until, Failed: x.Failed}
		}
	}
	for k, t := range s.Safe {
		if ip, ok := parseIP(k); ok {
			e.safe[ip] = t
		}
	}
	e.total = s.Total
}
