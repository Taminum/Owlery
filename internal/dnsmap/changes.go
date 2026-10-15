package dnsmap

import (
	"sort"
	"strings"
)

// Kinds of change recorded in a map's history.
const (
	ChangeAdded        = "dns.record_added"
	ChangeRemoved      = "dns.record_removed"
	ChangeValue        = "dns.value_changed"
	ChangeMX           = "dns.mx_changed"
	ChangeNS           = "dns.ns_changed"
	ChangeSPF          = "dns.spf_changed"
	ChangeDMARC        = "dns.dmarc_changed"
	ChangeCheckFailed  = "dns.check_failed"
	ChangeCheckRecover = "dns.check_recovered"
)

// Key identifies one record set: a name and a type.
type Key struct{ Name, Type string }

// State is what is known of a record set. Values are sorted. Result is the outcome of the last confirmed look.
type State struct {
	Values []string
	Result string
}

// Obs is one record set as observed in a run. Confirmed means the question was put to two resolvers and
// they gave the same answer; without that, a difference is not yet a change.
type Obs struct {
	Name      string
	Type      string
	Result    string
	Values    []string
	TTL       uint32
	Confirmed bool
}

// Change is one explained difference between what was known and what was just seen.
type Change struct {
	Name   string
	Type   string
	Kind   string
	Before []string
	After  []string
}

func isNegative(r string) bool { return r == OutcomeNoData || r == OutcomeNXDomain }

// Settled reports whether an outcome is a complete answer about the record set (it exists, or it
// certainly does not) as opposed to a failure that tells nothing.
func Settled(r string) bool { return r == OutcomeAnswer || isNegative(r) }

func setOf(v []string) map[string]bool {
	m := make(map[string]bool, len(v))
	for _, x := range v {
		m[x] = true
	}
	return m
}

func minus(a, b []string) []string {
	bm := setOf(b)
	var out []string
	for _, x := range a {
		if !bm[x] {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

func isSPF(v string) bool { return strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "v=spf1") }
func isDMARC(v string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "v=dmarc1")
}

func filter(v []string, keep func(string) bool) []string {
	var out []string
	for _, x := range v {
		if keep(x) {
			out = append(out, x)
		}
	}
	return out
}

// Diff explains what changed between the stored state and a run's observations.
//
// It reports a change only for a record set that was looked at, completely and confirmed: a timeout, a
// server failure, a refusal, a single resolver's word or a disagreement between resolvers is never the end
// of a record and never the start of one. The first run of a map (baseline) explains nothing. A record set
// that was not asked about this time is left exactly as it was.
func Diff(prev map[Key]State, cur []Obs, baseline bool) []Change {
	if baseline {
		return nil
	}
	var out []Change
	for _, o := range cur {
		if !o.Confirmed || !Settled(o.Result) {
			continue
		}
		k := Key{o.Name, o.Type}
		p, known := prev[k]
		before := p.Values
		if !known || !Settled(p.Result) {
			before = nil
		}
		after := o.Values
		if isNegative(o.Result) {
			after = nil
		}
		if !known && len(after) == 0 {
			continue // first sight of a name that has no such record: nothing was lost or gained
		}
		added, removed := minus(after, before), minus(before, after)
		if len(added) == 0 && len(removed) == 0 {
			continue
		}
		out = append(out, explain(o.Name, o.Type, before, after, added, removed)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

func explain(name, typ string, before, after, added, removed []string) []Change {
	mk := func(kind string, b, a []string) Change {
		return Change{Name: name, Type: typ, Kind: kind, Before: b, After: a}
	}
	switch typ {
	case TypeNS:
		return []Change{mk(ChangeNS, before, after)}
	case TypeMX:
		return []Change{mk(ChangeMX, before, after)}
	case TypeTXT:
		var out []Change
		if strings.HasPrefix(name, "_dmarc.") {
			if b, a := filter(before, isDMARC), filter(after, isDMARC); len(minus(a, b))+len(minus(b, a)) > 0 {
				out = append(out, mk(ChangeDMARC, b, a))
			}
		}
		if b, a := filter(before, isSPF), filter(after, isSPF); len(minus(a, b))+len(minus(b, a)) > 0 {
			out = append(out, mk(ChangeSPF, b, a))
		}
		rest := func(v []string) []string {
			return filter(v, func(s string) bool { return !isSPF(s) && !isDMARC(s) })
		}
		rb, ra := rest(before), rest(after)
		if ad, rm := minus(ra, rb), minus(rb, ra); len(ad) > 0 {
			out = append(out, mk(ChangeAdded, nil, ad))
		} else if len(rm) > 0 {
			out = append(out, mk(ChangeRemoved, rm, nil))
		}
		if rm := minus(rb, ra); len(rm) > 0 && len(minus(ra, rb)) > 0 {
			out = append(out, mk(ChangeRemoved, rm, nil))
		}
		return out
	case TypeCNAME, TypeSOA:
		if len(before) > 0 && len(after) > 0 {
			return []Change{mk(ChangeValue, before, after)}
		}
	}
	var out []Change
	if len(added) > 0 {
		out = append(out, mk(ChangeAdded, nil, added))
	}
	if len(removed) > 0 {
		out = append(out, mk(ChangeRemoved, removed, nil))
	}
	return out
}

// Important reports whether a change deserves an alert. Additions of ordinary address records and the
// movement of a SOA serial are part of normal life; the mail, delegation and policy records are not.
func Important(kind string) bool {
	switch kind {
	case ChangeNS, ChangeMX, ChangeSPF, ChangeDMARC, ChangeRemoved, ChangeValue:
		return true
	}
	return false
}
