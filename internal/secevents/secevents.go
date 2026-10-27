// Package secevents turns two consecutive snapshots of one category into journal events. It is a pure
// function of its inputs: the first snapshot of a category is a baseline and produces nothing.
package secevents

import (
	"fmt"
	"sort"

	"github.com/Taminum/Owlery/internal/secproto"
)

const (
	SevInfo     = "info"
	SevWarning  = "warning"
	SevCritical = "critical"

	SourceStateDiff = "state_diff"
)

// Event is one normalised journal entry. Key distinguishes events of one type within one snapshot pair.
type Event struct {
	Category string
	Type     string
	Severity string
	Key      string
	Payload  map[string]any
}

// Snap is what a diff needs of a stored snapshot.
type Snap struct {
	Status string
	Hash   string
	F2B    *secproto.Fail2ban
	Sock   *secproto.Sockets
	FW     *secproto.Firewall
}

func Diff(category string, prev, cur Snap) []Event {
	switch category {
	case secproto.CatFail2ban:
		return diffFail2ban(prev, cur)
	case secproto.CatSockets:
		return diffSockets(prev, cur)
	case secproto.CatFirewall:
		return diffFirewall(prev, cur)
	}
	return nil
}

func stateEvent(cat string, prev, cur Snap) []Event {
	if prev.Status == cur.Status {
		return nil
	}
	sev := SevInfo
	if cur.Status != secproto.StatusOK {
		sev = SevWarning
	}
	return []Event{{Category: cat, Type: cat + ".state_changed", Severity: sev, Key: prev.Status + ">" + cur.Status,
		Payload: map[string]any{"from": prev.Status, "to": cur.Status, "source": SourceStateDiff}}}
}

func diffFail2ban(prev, cur Snap) []Event {
	out := stateEvent(secproto.CatFail2ban, prev, cur)
	// Bans are compared only while both snapshots are complete: otherwise a failed read would look
	// like every ban being lifted.
	if prev.Status != secproto.StatusOK || cur.Status != secproto.StatusOK || prev.F2B == nil || cur.F2B == nil {
		return out
	}
	pj, cj := map[string]map[string]bool{}, map[string]map[string]bool{}
	index := func(f *secproto.Fail2ban, into map[string]map[string]bool) {
		for _, j := range f.Jails {
			s := map[string]bool{}
			for _, ip := range j.BannedIPs {
				s[ip] = true
			}
			into[j.Name] = s
		}
	}
	index(prev.F2B, pj)
	index(cur.F2B, cj)
	jail := func(name, change string) Event {
		return Event{Category: secproto.CatFail2ban, Type: "fail2ban.jail_changed", Severity: SevInfo, Key: change + "|" + name,
			Payload: map[string]any{"jail": name, "change": change, "source": SourceStateDiff}}
	}
	for _, name := range sortedKeys(cj) {
		if _, ok := pj[name]; !ok {
			out = append(out, jail(name, "added"))
		}
	}
	for _, name := range sortedKeys(pj) {
		if _, ok := cj[name]; !ok {
			out = append(out, jail(name, "removed"))
		}
	}
	// Fail2ban counts every ban it has made. When the count grew by more than the new addresses that are now
	// visibly banned, some bans came and went between two reads: they are not named (that needs the log), but
	// they are counted, so a burst of attacks that the 30 second reads missed is not silently lost.
	total := func(f *secproto.Fail2ban) map[string]int {
		m := map[string]int{}
		for _, j := range f.Jails {
			m[j.Name] = j.TotalBanned
		}
		return m
	}
	pt, ct := total(prev.F2B), total(cur.F2B)
	for _, name := range sortedKeys(cj) {
		before, known := pj[name]
		if !known {
			continue
		}
		visible := 0
		for ip := range cj[name] {
			if !before[ip] {
				visible++
			}
		}
		// A negative growth is Fail2ban having been restarted with a fresh counter: nothing to say.
		if missed := ct[name] - pt[name] - visible; missed > 0 {
			out = append(out, Event{Category: secproto.CatFail2ban, Type: "fail2ban.bans_unobserved", Severity: SevInfo, Key: fmt.Sprintf("%s|%d", name, ct[name]),
				Payload: map[string]any{"jail": name, "count": missed, "source": SourceStateDiff}})
		}
	}
	ban := func(typ, name, ip string) Event {
		return Event{Category: secproto.CatFail2ban, Type: typ, Severity: SevInfo, Key: name + "|" + ip,
			Payload: map[string]any{"jail": name, "ip": ip, "source": SourceStateDiff}}
	}
	for _, name := range sortedKeys(cj) {
		before, ok := pj[name]
		if !ok {
			continue // a new jail: its bans are its baseline
		}
		for _, ip := range sortedKeys(cj[name]) {
			if !before[ip] {
				out = append(out, ban("fail2ban.ban", name, ip))
			}
		}
		for _, ip := range sortedKeys(before) {
			if !cj[name][ip] {
				out = append(out, ban("fail2ban.unban", name, ip))
			}
		}
	}
	return out
}

func sockKey(l secproto.Listener) string { return fmt.Sprintf("%s|%s|%d", l.Proto, l.Addr, l.Port) }
func portKey(l secproto.Listener) string { return fmt.Sprintf("%s|%d", l.Proto, l.Port) }

func diffSockets(prev, cur Snap) []Event {
	out := stateEvent(secproto.CatSockets, prev, cur)
	if prev.Status != secproto.StatusOK || cur.Status != secproto.StatusOK || prev.Sock == nil || cur.Sock == nil {
		return out
	}
	p, c := map[string]secproto.Listener{}, map[string]secproto.Listener{}
	for _, l := range prev.Sock.Listeners {
		p[sockKey(l)] = l
	}
	for _, l := range cur.Sock.Listeners {
		c[sockKey(l)] = l
	}
	var added, removed []string
	for k := range c {
		if _, ok := p[k]; !ok {
			added = append(added, k)
		}
	}
	for k := range p {
		if _, ok := c[k]; !ok {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	// One protocol/port that left one address and appeared on another is a changed bind, not two events.
	remByPort, addByPort := map[string][]string{}, map[string][]string{}
	for _, k := range removed {
		remByPort[portKey(p[k])] = append(remByPort[portKey(p[k])], k)
	}
	for _, k := range added {
		addByPort[portKey(c[k])] = append(addByPort[portKey(c[k])], k)
	}
	handled := map[string]bool{}
	for _, port := range sortedKeys(remByPort) {
		rs, as := remByPort[port], addByPort[port]
		if len(rs) == 1 && len(as) == 1 {
			handled[rs[0]], handled[as[0]] = true, true
			out = append(out, Event{Category: secproto.CatSockets, Type: "port.local_bind_changed", Severity: SevInfo, Key: rs[0] + ">" + as[0],
				Payload: map[string]any{"proto": c[as[0]].Proto, "port": c[as[0]].Port, "from": p[rs[0]].Addr, "to": c[as[0]].Addr, "source": SourceStateDiff}})
		}
	}
	emit := func(typ, k string, l secproto.Listener) Event {
		return Event{Category: secproto.CatSockets, Type: typ, Severity: SevInfo, Key: k,
			Payload: map[string]any{"proto": l.Proto, "addr": l.Addr, "port": l.Port, "process": l.Process, "source": SourceStateDiff}}
	}
	for _, k := range added {
		if !handled[k] {
			out = append(out, emit("port.local_added", k, c[k]))
		}
	}
	for _, k := range removed {
		if !handled[k] {
			out = append(out, emit("port.local_removed", k, p[k]))
		}
	}
	return out
}

func diffFirewall(prev, cur Snap) []Event {
	out := stateEvent(secproto.CatFirewall, prev, cur)
	if prev.Status != secproto.StatusOK || cur.Status != secproto.StatusOK || prev.FW == nil || cur.FW == nil {
		return out
	}
	if prev.Hash != cur.Hash || prev.FW.Backend != cur.FW.Backend {
		out = append(out, Event{Category: secproto.CatFirewall, Type: "firewall.rules_changed", Severity: SevWarning, Key: prev.Hash + ">" + cur.Hash,
			Payload: map[string]any{"backend": cur.FW.Backend, "previous_backend": prev.FW.Backend, "source": SourceStateDiff}})
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
