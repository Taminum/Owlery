// Package seccollect reads the security state of the host it runs on: Fail2ban, listening sockets and
// the firewall. It only reads. Every command is run without a shell, with a fixed argument list, a
// timeout and a cap on its output, and what cannot be read is reported as such (not installed, no
// permission, stopped) rather than as an empty result.
package seccollect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

// Result is what a command produced. Err is set when it could not be started at all.
type Result struct {
	Stdout, Stderr string
	ExitCode       int
	Err            error
}

// Runner runs one command. Tests replace it.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) Result
}

const (
	cmdTimeout = 10 * time.Second
	maxOutput  = 4 << 20
)

type ExecRunner struct{}

type capped struct {
	b bytes.Buffer
}

func (c *capped) Write(p []byte) (int, error) {
	if room := maxOutput - c.b.Len(); room > 0 {
		c.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil // the rest is dropped, and the command is not blocked by a full pipe
}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) Result {
	ctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}
	var out, errb capped
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	res := Result{Stdout: out.b.String(), Stderr: errb.b.String()}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	default:
		res.Err = err
	}
	return res
}

func (r Result) notFound() bool { return r.Err != nil && errors.Is(r.Err, exec.ErrNotFound) }

var permRe = regexp.MustCompile(`(?i)permission denied|operation not permitted|must be root|you need to be root|not permitted|are you root`)

func (r Result) denied() bool { return permRe.MatchString(r.Stderr) || permRe.MatchString(r.Stdout) }

// Snapshot is one category's collected state, ready to send.
type Snapshot struct {
	Category string
	Status   string
	Data     any // nil when Status is not ok
}

// --- Fail2ban ------------------------------------------------------------------------------------

var jailNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// ParseJailList reads the output of "fail2ban-client status".
func ParseJailList(out string) ([]string, bool) {
	for _, line := range strings.Split(out, "\n") {
		if _, v, ok := strings.Cut(line, "Jail list:"); ok {
			var names []string
			for _, n := range strings.Split(v, ",") {
				if n = strings.TrimSpace(n); n != "" {
					names = append(names, n)
				}
			}
			return names, true
		}
	}
	return nil, false
}

func labelValue(line, label string) (string, bool) {
	i := strings.Index(line, label)
	if i < 0 {
		return "", false
	}
	return strings.TrimSpace(line[i+len(label):]), true
}

// ParseJailStatus reads the output of "fail2ban-client status <jail>".
func ParseJailStatus(name, out string) (secproto.Jail, bool) {
	j := secproto.Jail{Name: name, BannedIPs: []string{}}
	seen := 0
	num := func(line, label string, into *int) {
		if v, ok := labelValue(line, label); ok {
			if n, err := strconv.Atoi(v); err == nil {
				*into = n
				seen++
			}
		}
	}
	for _, line := range strings.Split(out, "\n") {
		num(line, "Currently failed:", &j.CurrentlyFailed)
		num(line, "Total failed:", &j.TotalFailed)
		num(line, "Currently banned:", &j.CurrentlyBanned)
		num(line, "Total banned:", &j.TotalBanned)
		if v, ok := labelValue(line, "Banned IP list:"); ok {
			for _, ip := range strings.Fields(v) {
				j.BannedIPs = append(j.BannedIPs, ip)
			}
		}
	}
	return j, seen >= 4
}

func Fail2ban(ctx context.Context, r Runner, bin string) Snapshot {
	snap := Snapshot{Category: secproto.CatFail2ban}
	res := r.Run(ctx, bin, "status")
	switch {
	case res.notFound():
		snap.Status = secproto.StatusNotInstalled
		return snap
	case res.denied():
		snap.Status = secproto.StatusPermissionDenied
		return snap
	case res.Err != nil:
		snap.Status = secproto.StatusError
		return snap
	case res.ExitCode != 0:
		low := strings.ToLower(res.Stdout + res.Stderr)
		if strings.Contains(low, "failed to access socket") || strings.Contains(low, "is fail2ban running") || strings.Contains(low, "no such file") {
			snap.Status = secproto.StatusStopped
		} else {
			snap.Status = secproto.StatusError
		}
		return snap
	}
	names, ok := ParseJailList(res.Stdout)
	if !ok {
		snap.Status = secproto.StatusError
		return snap
	}
	if len(names) > secproto.MaxJails {
		names = names[:secproto.MaxJails]
	}
	data := secproto.Fail2ban{Jails: []secproto.Jail{}}
	for _, n := range names {
		if !jailNameRe.MatchString(n) {
			continue
		}
		jr := r.Run(ctx, bin, "status", n)
		if jr.Err != nil || jr.ExitCode != 0 {
			// A jail that cannot be read makes the whole picture incomplete; saying so beats a partial list.
			snap.Status = secproto.StatusError
			if jr.denied() {
				snap.Status = secproto.StatusPermissionDenied
			}
			return snap
		}
		j, ok := ParseJailStatus(n, jr.Stdout)
		if !ok {
			snap.Status = secproto.StatusError
			return snap
		}
		if len(j.BannedIPs) > secproto.MaxBannedIPs {
			snap.Status = secproto.StatusError
			return snap
		}
		data.Jails = append(data.Jails, j)
	}
	snap.Status, snap.Data = secproto.StatusOK, data
	return snap
}

// --- sockets -------------------------------------------------------------------------------------

var procRe = regexp.MustCompile(`\(\("([^"]*)",pid=(\d+)`)

// ParseSS reads the output of "ss -H -tulnp" (or -tuln, without process names).
func ParseSS(out string) secproto.Sockets {
	s := secproto.Sockets{Listeners: []secproto.Listener{}}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || (f[0] != "tcp" && f[0] != "udp") {
			continue
		}
		addr, port, ok := splitHostPort(f[4])
		if !ok {
			continue
		}
		l := secproto.Listener{Proto: f[0], Addr: addr, Port: port, State: f[1]}
		if m := procRe.FindStringSubmatch(line); m != nil {
			l.Process = m[1]
			l.PID, _ = strconv.Atoi(m[2])
			s.ProcessInfo = true
		}
		s.Listeners = append(s.Listeners, l)
	}
	return s
}

func splitHostPort(s string) (string, int, bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0, false
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil || port < 0 || port > 65535 {
		return "", 0, false
	}
	host := strings.Trim(s[:i], "[]")
	if j := strings.Index(host, "%"); j >= 0 { // 127.0.0.53%lo: the interface is not part of the address
		host = host[:j]
	}
	if host == "*" {
		host = "0.0.0.0"
	}
	return host, port, host != ""
}

func Sockets(ctx context.Context, r Runner, bin string) Snapshot {
	return NewSocketWatch(0).Collect(ctx, r, bin, time.Now())
}

// EphemeralFrom and EphemeralTo are Linux's default dynamic port range. A proxy such as Xray opens a UDP socket
// in that range for every client flow; each is a "listener" for seconds, and none is a service. The host's own
// range (net.ipv4.ip_local_port_range) is used when it can be read: Amnezia's hosts commonly set 10000-65535.
const (
	EphemeralFrom = 32768
	EphemeralTo   = 60999
)

// localPortRange reads the host's dynamic port range, or returns the Linux default.
func localPortRange() (int, int) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return EphemeralFrom, EphemeralTo
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return EphemeralFrom, EphemeralTo
	}
	lo, e1 := strconv.Atoi(f[0])
	hi, e2 := strconv.Atoi(f[1])
	if e1 != nil || e2 != nil || lo < 1024 || hi > 65535 || lo > hi {
		return EphemeralFrom, EphemeralTo
	}
	return lo, hi
}

// SocketWatch reads listening sockets but reports a UDP socket in the dynamic range only once it has been
// there for MinAge: a service that is really listening there (a VPN on a high UDP port) shows up after that
// delay, and flow sockets that come and go never do. Everything else is reported at once.
type SocketWatch struct {
	MinAge   time.Duration
	From, To int // the dynamic port range; UDP sockets in it are held back
	seen     map[string]time.Time
}

func NewSocketWatch(minAge time.Duration) *SocketWatch {
	lo, hi := localPortRange()
	return &SocketWatch{MinAge: minAge, From: lo, To: hi, seen: map[string]time.Time{}}
}

func (w *SocketWatch) Collect(ctx context.Context, r Runner, bin string, now time.Time) Snapshot {
	snap := Snapshot{Category: secproto.CatSockets}
	res := r.Run(ctx, bin, "-H", "-tulnp")
	switch {
	case res.notFound():
		snap.Status = secproto.StatusUnsupported
		return snap
	case res.Err != nil || res.ExitCode != 0:
		snap.Status = secproto.StatusError
		return snap
	}
	data := ParseSS(res.Stdout)
	if w.MinAge > 0 {
		now2 := map[string]time.Time{}
		kept := data.Listeners[:0]
		for _, l := range data.Listeners {
			if l.Proto != "udp" || l.Port < w.From || l.Port > w.To {
				kept = append(kept, l)
				continue
			}
			k := fmt.Sprintf("%s|%d", l.Addr, l.Port)
			first, ok := w.seen[k]
			if !ok {
				first = now
			}
			now2[k] = first
			if now.Sub(first) >= w.MinAge {
				kept = append(kept, l)
			}
		}
		w.seen, data.Listeners = now2, kept
	}
	if len(data.Listeners) > secproto.MaxListeners {
		data.Listeners = data.Listeners[:secproto.MaxListeners]
	}
	sort.SliceStable(data.Listeners, func(a, b int) bool { return data.Listeners[a].Port < data.Listeners[b].Port })
	snap.Status, snap.Data = secproto.StatusOK, data
	return snap
}

// --- firewall ------------------------------------------------------------------------------------

var (
	nftCounterRe = regexp.MustCompile(`counter packets \d+ bytes \d+`)
	nftHandleRe  = regexp.MustCompile(`\s+# handle \d+$`)
	// The body of a named counter object ("counter processed { packets N bytes M }") is a running count.
	nftCounterBodyRe = regexp.MustCompile(`^packets \d+ bytes \d+$`)
	iptCountRe       = regexp.MustCompile(` \[\d+:\d+\]`)
)

// Fail2ban keeps the addresses it has banned inside the firewall: the elements of its nftables set, or one
// per-address rule in its iptables chains. They change with every ban and unban, which is the journal's
// Fail2ban events and not a change of the firewall's rules, so they are left out of the canonical form.
var f2bIptablesRe = regexp.MustCompile(`^-A f2b-\S+ -s \S+ `)

func isFail2banTable(name string) bool { return strings.HasPrefix(name, "f2b") }

// perAddressRe finds the address a one-address rule is about: "ip saddr 1.2.3.4" (nftables) or "-s 1.2.3.4"
// (iptables). Fail2ban's UFW and "reject" actions put one such rule per banned address into ordinary chains.
var perAddressRe = regexp.MustCompile(`(?:\bip6? saddr|(?:^|\s)-s)\s+([0-9A-Fa-f:.]+)(?:/32|/128)?(?:\s|$)`)

// isBanRule reports whether a line is a drop or reject of exactly one address that Fail2ban has banned right
// now. Such a rule is the ban itself, so it is the journal's Fail2ban event and not a change of the firewall.
// A rule for an address Fail2ban does not hold is kept: that is someone's own rule.
func isBanRule(line string, banned map[string]bool) bool {
	if len(banned) == 0 {
		return false
	}
	m := perAddressRe.FindStringSubmatch(line)
	if m == nil || !banned[m[1]] {
		return false
	}
	l := strings.ToLower(line)
	return strings.Contains(l, "reject") || strings.Contains(l, "drop")
}

// CanonicalNft removes what changes without the rules changing: packet counters, handles, comments, and
// the banned addresses Fail2ban keeps in its own table.
func CanonicalNft(s string) string { return canonicalNft(s, nil) }

func canonicalNft(s string, banned map[string]bool) string {
	var out []string
	table := ""
	skipping := false // inside a multi-line "elements = { ... }" of a Fail2ban set
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if skipping {
			skipping = !strings.Contains(t, "}")
			continue
		}
		if t == "" || strings.HasPrefix(t, "#") || nftCounterBodyRe.MatchString(t) {
			continue
		}
		if f := strings.Fields(t); len(f) >= 3 && f[0] == "table" {
			table = f[2]
		}
		if isFail2banTable(table) && strings.HasPrefix(t, "elements") {
			skipping = !strings.Contains(t, "}")
			continue
		}
		if isBanRule(t, banned) {
			continue
		}
		line = nftHandleRe.ReplaceAllString(line, "")
		line = nftCounterRe.ReplaceAllString(line, "counter")
		out = append(out, strings.TrimRight(line, " \t"))
	}
	return strings.Join(out, "\n")
}

// CanonicalIptables removes the generation timestamps, the per-chain counters and Fail2ban's per-address rules.
func CanonicalIptables(s string) string { return canonicalIptables(s, nil) }

func canonicalIptables(s string, banned map[string]bool) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || f2bIptablesRe.MatchString(t) || isBanRule(t, banned) {
			continue
		}
		out = append(out, strings.TrimRight(iptCountRe.ReplaceAllString(line, ""), " \t"))
	}
	return strings.Join(out, "\n")
}

func fit(rules string) (string, bool) {
	if len(rules) <= secproto.MaxRulesBytes {
		return rules, false
	}
	cut := strings.LastIndex(rules[:secproto.MaxRulesBytes], "\n")
	if cut < 0 {
		cut = secproto.MaxRulesBytes
	}
	return rules[:cut], true
}

// Firewall reads nftables first and iptables second. UFW is a front end over these and is not read on
// its own yet; on a host where UFW manages the rules, they are visible here as nftables or iptables.
func Firewall(ctx context.Context, r Runner, nft, iptables string) Snapshot {
	return FirewallWithBans(ctx, r, nft, iptables, nil)
}

// FirewallWithBans is Firewall for a host where Fail2ban acts through the ordinary firewall (UFW, "reject"
// actions): the per-address rules for the addresses in banned are left out of the canonical text, so a ban
// is not also reported as a change of the rules.
func FirewallWithBans(ctx context.Context, r Runner, nft, iptables string, banned map[string]bool) Snapshot {
	snap := Snapshot{Category: secproto.CatFirewall}
	denied, anyTool, nftEmpty := false, false, false

	res := r.Run(ctx, nft, "list", "ruleset")
	switch {
	case res.notFound():
	case res.denied():
		denied, anyTool = true, true
	case res.Err == nil && res.ExitCode == 0:
		if rules := canonicalNft(res.Stdout, banned); rules != "" {
			rules, trunc := fit(rules)
			snap.Status, snap.Data = secproto.StatusOK, secproto.Firewall{Backend: "nft", Rules: rules, Truncated: trunc}
			return snap
		}
		nftEmpty = true
	default:
		anyTool = true
	}

	res = r.Run(ctx, iptables)
	switch {
	case res.notFound():
	case res.denied():
		denied, anyTool = true, true
	case res.Err == nil && res.ExitCode == 0:
		if rules := canonicalIptables(res.Stdout, banned); rules != "" || !nftEmpty {
			rules, trunc := fit(rules)
			snap.Status, snap.Data = secproto.StatusOK, secproto.Firewall{Backend: "iptables", Rules: rules, Truncated: trunc}
			return snap
		}
	default:
		anyTool = true
	}
	switch {
	case nftEmpty && !denied:
		// nftables answered and holds no rules: that is a real, empty firewall.
		snap.Status, snap.Data = secproto.StatusOK, secproto.Firewall{Backend: "nft", Rules: ""}
	case denied:
		snap.Status = secproto.StatusPermissionDenied
	case anyTool:
		snap.Status = secproto.StatusError
	default:
		snap.Status = secproto.StatusNotInstalled
	}
	return snap
}

// ErrNotInstalled is what a Runner returns when the command does not exist.
var ErrNotInstalled = exec.ErrNotFound

// NotFound and Denied let other packages classify a Result the way the collectors do.
func NotFound(r Result) bool { return r.notFound() }
func Denied(r Result) bool   { return r.denied() }
