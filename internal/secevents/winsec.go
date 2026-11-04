package secevents

import (
	"strconv"
	"strings"

	"github.com/Taminum/Owlery/internal/secproto"
)

// staleDays is how old Defender's definitions may get before it is worth saying so.
const staleDays = 7

// burstFailed is how many failed sign-ins between two reads make an event a warning rather than a note.
const burstFailed = 10

// diffWinsec turns two readings of the Windows event log and of Defender into events. The counters count from the
// moment the agent started: a counter that went down means the agent restarted, and then everything counted since is new.
func diffWinsec(prev, cur Snap) []Event {
	out := stateEvent(secproto.CatWinsec, prev, cur)
	if prev.Status != secproto.StatusOK || cur.Status != secproto.StatusOK || prev.Win == nil || cur.Win == nil {
		return out
	}
	p, c := prev.Win, cur.Win
	out = append(out, diffBlock(p.Block, c.Block)...)
	restarted := c.RemoteFailed < p.RemoteFailed || c.RemoteOK < p.RemoteOK

	if delta := c.RemoteFailed - p.RemoteFailed; restarted || delta > 0 {
		if restarted {
			delta = c.RemoteFailed
		}
		before := map[string]int{}
		if !restarted {
			for _, s := range p.Sources {
				before[s.IP] = s.Failed
			}
		}
		named := 0
		for _, s := range c.Sources {
			d := s.Failed - before[s.IP]
			if d <= 0 || len(out) >= 8 {
				continue
			}
			named += d
			out = append(out, failedEvent(s.IP, d))
		}
		if rest := int(delta) - named; rest > 0 {
			out = append(out, failedEvent("", rest))
		}
	}

	seen := map[int64]bool{}
	for _, l := range p.RecentOK {
		seen[l.ID] = true
	}
	for _, l := range c.RecentOK {
		if seen[l.ID] {
			continue
		}
		out = append(out, Event{Category: secproto.CatWinsec, Type: "winsec.rdp_ok", Severity: SevInfo, Key: "ok|" + strconv.FormatInt(l.ID, 10),
			Payload: map[string]any{"user": l.User, "ip": l.IP, "source": SourceStateDiff}})
	}

	seenT := map[int64]bool{}
	for _, th := range p.Threats {
		seenT[th.ID] = true
	}
	for _, th := range c.Threats {
		if seenT[th.ID] {
			continue
		}
		sev := SevWarning
		if s := strings.ToLower(th.Severity); s == "severe" || s == "high" {
			sev = SevCritical
		}
		out = append(out, Event{Category: secproto.CatWinsec, Type: "winsec.defender_threat", Severity: sev, Key: "threat|" + strconv.FormatInt(th.ID, 10),
			Payload: map[string]any{"name": th.Name, "severity": th.Severity, "path": th.Path, "source": SourceStateDiff}})
	}

	if p.Defender.Present && c.Defender.Present {
		switch {
		case p.Defender.Realtime && !c.Defender.Realtime:
			out = append(out, Event{Category: secproto.CatWinsec, Type: "winsec.defender_off", Severity: SevCritical, Key: "off",
				Payload: map[string]any{"source": SourceStateDiff}})
		case !p.Defender.Realtime && c.Defender.Realtime:
			out = append(out, Event{Category: secproto.CatWinsec, Type: "winsec.defender_on", Severity: SevInfo, Key: "on",
				Payload: map[string]any{"source": SourceStateDiff}})
		}
		if p.Defender.SignatureDays <= staleDays && c.Defender.SignatureDays > staleDays {
			out = append(out, Event{Category: secproto.CatWinsec, Type: "winsec.defender_old", Severity: SevWarning, Key: "old",
				Payload: map[string]any{"days": c.Defender.SignatureDays, "source": SourceStateDiff}})
		}
	}
	return out
}

func failedEvent(ip string, n int) Event {
	sev := SevInfo
	if n >= burstFailed {
		sev = SevWarning
	}
	return Event{Category: secproto.CatWinsec, Type: "winsec.rdp_failed", Severity: sev, Key: "failed|" + ip,
		Payload: map[string]any{"ip": ip, "count": n, "source": SourceStateDiff}}
}

// diffBlock turns what the address blocker did between two readings into events. Nothing is said about what was already
// there when the blocker first showed up in a report (an agent that was just updated).
func diffBlock(p, c *secproto.WinBlock) []Event {
	if p == nil || c == nil {
		return nil
	}
	key := func(e secproto.WinBlockEntry) string { return e.IP + "|" + strconv.FormatInt(e.Since.Unix(), 10) }
	had := func(list []secproto.WinBlockEntry) map[string]secproto.WinBlockEntry {
		m := map[string]secproto.WinBlockEntry{}
		for _, e := range list {
			m[key(e)] = e
		}
		return m
	}
	pa, pw, ca := had(p.Active), had(p.Would), had(c.Active)
	var out []Event
	payload := func(e secproto.WinBlockEntry) map[string]any {
		m := map[string]any{"ip": e.IP, "failed": e.Failed, "source": SourceStateDiff}
		if e.Until != nil {
			m["until"] = e.Until.UTC().Format("2006-01-02T15:04:05Z")
		}
		return m
	}
	for _, e := range c.Active {
		if _, ok := pa[key(e)]; !ok && len(out) < 20 {
			out = append(out, Event{Category: secproto.CatWinsec, Type: "winsec.ip_blocked", Severity: SevWarning, Key: "blk|" + key(e), Payload: payload(e)})
		}
	}
	for _, e := range p.Active {
		if _, ok := ca[key(e)]; !ok && len(out) < 20 {
			out = append(out, Event{Category: secproto.CatWinsec, Type: "winsec.ip_unblocked", Severity: SevInfo, Key: "unb|" + key(e), Payload: payload(e)})
		}
	}
	for _, e := range c.Would {
		if _, ok := pw[key(e)]; !ok && len(out) < 20 {
			out = append(out, Event{Category: secproto.CatWinsec, Type: "winsec.ip_would_block", Severity: SevInfo, Key: "wb|" + key(e), Payload: payload(e)})
		}
	}
	return out
}
