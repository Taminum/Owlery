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
