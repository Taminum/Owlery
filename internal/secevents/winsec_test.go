package secevents

import (
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

func win(failed, ok int64, src []secproto.WinSource, logons []secproto.WinLogon, threats []secproto.WinThreat, d secproto.WinDefender) Snap {
	return Snap{Status: secproto.StatusOK, Win: &secproto.Winsec{RemoteFailed: failed, RemoteOK: ok, Sources: src, RecentOK: logons, Threats: threats, Defender: d}}
}

func byType(evs []Event) map[string][]Event {
	m := map[string][]Event{}
	for _, e := range evs {
		m[e.Type] = append(m[e.Type], e)
	}
	return m
}

func TestWinsecNamesTheNewFailuresAndWhoGotIn(t *testing.T) {
	d := secproto.WinDefender{Present: true, Enabled: true, Realtime: true, SignatureDays: 1}
	prev := win(10, 1, []secproto.WinSource{{IP: "198.51.100.7", Failed: 6}, {IP: "203.0.113.9", Failed: 4}}, []secproto.WinLogon{{ID: 5, User: "old", IP: "192.0.2.1"}}, nil, d)
	cur := win(31, 2,
		[]secproto.WinSource{{IP: "198.51.100.7", Failed: 26}, {IP: "203.0.113.9", Failed: 5}},
		[]secproto.WinLogon{{ID: 9, User: "Administrator", IP: "198.51.100.20", At: time.Now()}, {ID: 5, User: "old", IP: "192.0.2.1"}},
		[]secproto.WinThreat{{ID: 70, Name: "Trojan:Win32/Test", Severity: "Severe", Path: `C:\x.exe`}}, d)
	ev := byType(Diff(secproto.CatWinsec, prev, cur))

	failed := ev["winsec.rdp_failed"]
	if len(failed) != 2 {
		t.Fatalf("failed: %+v", failed)
	}
	if failed[0].Payload["ip"] != "198.51.100.7" || failed[0].Payload["count"] != 20 || failed[0].Severity != SevWarning {
		t.Errorf("a burst from one address is a warning, with the address and the count: %+v", failed[0])
	}
	if failed[1].Payload["count"] != 1 || failed[1].Severity != SevInfo {
		t.Errorf("a single miss is a note: %+v", failed[1])
	}
	if got := ev["winsec.rdp_ok"]; len(got) != 1 || got[0].Payload["user"] != "Administrator" {
		t.Errorf("only the new sign-in is reported: %+v", got)
	}
	if got := ev["winsec.defender_threat"]; len(got) != 1 || got[0].Severity != SevCritical || got[0].Payload["name"] != "Trojan:Win32/Test" {
		t.Errorf("a severe find is critical: %+v", got)
	}
}

func TestWinsecAgentRestartCountsEverythingAgainAndDefenderSwitchedOffIsCritical(t *testing.T) {
	on := secproto.WinDefender{Present: true, Enabled: true, Realtime: true, SignatureDays: 3}
	off := on
	off.Realtime = false
	off.SignatureDays = 9
	prev := win(500, 20, []secproto.WinSource{{IP: "198.51.100.7", Failed: 500}}, nil, nil, on)
	cur := win(4, 0, []secproto.WinSource{{IP: "198.51.100.8", Failed: 4}}, nil, nil, off) // the counters went down: a new run
	ev := byType(Diff(secproto.CatWinsec, prev, cur))
	if got := ev["winsec.rdp_failed"]; len(got) != 1 || got[0].Payload["count"] != 4 {
		t.Errorf("after a restart what is counted is new: %+v", got)
	}
	if len(ev["winsec.defender_off"]) != 1 || ev["winsec.defender_off"][0].Severity != SevCritical {
		t.Errorf("live protection switched off: %+v", ev)
	}
	if len(ev["winsec.defender_old"]) != 1 {
		t.Errorf("definitions older than a week: %+v", ev)
	}

	// No change, no events.
	if got := Diff(secproto.CatWinsec, cur, cur); len(got) != 0 {
		t.Errorf("nothing changed: %+v", got)
	}
}

func TestBlockerEventsSayWhatWasBlockedLiftedAndWouldHaveBeen(t *testing.T) {
	d := secproto.WinDefender{Present: true, Enabled: true, Realtime: true, SignatureDays: 1}
	t0 := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	until := t0.Add(24 * time.Hour)
	old := secproto.WinBlockEntry{IP: "203.0.113.1", Since: t0.Add(-48 * time.Hour), Failed: 5}
	prev := win(0, 0, nil, nil, nil, d)
	prev.Win.Block = &secproto.WinBlock{Mode: secproto.BlockOn, Active: []secproto.WinBlockEntry{old}}
	cur := win(0, 0, nil, nil, nil, d)
	cur.Win.Block = &secproto.WinBlock{Mode: secproto.BlockOn,
		Active: []secproto.WinBlockEntry{{IP: "198.51.100.7", Since: t0, Until: &until, Failed: 5}},
		Would:  []secproto.WinBlockEntry{{IP: "198.51.100.8", Since: t0, Failed: 6}}}
	ev := byType(Diff(secproto.CatWinsec, prev, cur))
	if b := ev["winsec.ip_blocked"]; len(b) != 1 || b[0].Payload["ip"] != "198.51.100.7" || b[0].Severity != SevWarning || b[0].Payload["until"] == nil {
		t.Errorf("blocked: %+v", ev["winsec.ip_blocked"])
	}
	if u := ev["winsec.ip_unblocked"]; len(u) != 1 || u[0].Payload["ip"] != "203.0.113.1" {
		t.Errorf("unblocked: %+v", u)
	}
	if w := ev["winsec.ip_would_block"]; len(w) != 1 || w[0].Payload["ip"] != "198.51.100.8" || w[0].Severity != SevInfo {
		t.Errorf("would: %+v", w)
	}

	// The first report that has a blocker in it says nothing about what was already there.
	first := win(0, 0, nil, nil, nil, d)
	if got := Diff(secproto.CatWinsec, first, cur); len(byType(got)["winsec.ip_blocked"]) != 0 {
		t.Errorf("an agent that was just updated must not announce old blocks: %+v", got)
	}
	// And the same report twice says nothing new.
	if got := byType(Diff(secproto.CatWinsec, cur, cur)); len(got["winsec.ip_blocked"])+len(got["winsec.ip_would_block"])+len(got["winsec.ip_unblocked"]) != 0 {
		t.Errorf("a repeat: %+v", got)
	}
}
