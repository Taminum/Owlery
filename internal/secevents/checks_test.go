package secevents

import (
	"testing"
	"time"
)

func TestPortDiffBaselineTimeoutAndErrors(t *testing.T) {
	if got := PortDiff(PortPrev{}, PortReachable, false, "h", 22, "1.1.1.1"); len(got) != 0 {
		t.Fatalf("the first observation is a baseline: %+v", got)
	}
	got := PortDiff(PortPrev{Known: true, Result: PortRefused}, PortReachable, false, "h", 9000, "1.1.1.1")
	if len(got) != 1 || got[0].Type != "port.public_reachable" || got[0].Severity != SevCritical {
		t.Fatalf("an unexpected port that opened is critical: %+v", got)
	}
	got = PortDiff(PortPrev{Known: true, Result: PortRefused}, PortReachable, true, "h", 443, "1.1.1.1")
	if len(got) != 1 || got[0].Severity != SevInfo {
		t.Fatalf("%+v", got)
	}
	// A timeout after "reachable" is a loss, but never a proof of closure.
	got = PortDiff(PortPrev{Known: true, Result: PortReachable}, PortTimeout, true, "h", 443, "1.1.1.1")
	if len(got) != 1 || got[0].Type != "port.public_lost" || got[0].Payload["conclusive"] != false || got[0].Severity != SevWarning {
		t.Fatalf("%+v", got)
	}
	got = PortDiff(PortPrev{Known: true, Result: PortReachable}, PortRefused, false, "h", 80, "1.1.1.1")
	if len(got) != 1 || got[0].Payload["conclusive"] != true {
		t.Fatalf("%+v", got)
	}
	for _, c := range []struct{ prev, cur string }{{PortReachable, PortError}, {PortError, PortReachable}, {PortReachable, PortReachable}, {PortTimeout, PortRefused}} {
		if got := PortDiff(PortPrev{Known: true, Result: c.prev}, c.cur, false, "h", 1, ""); len(got) != 0 {
			t.Errorf("%s -> %s: %+v", c.prev, c.cur, got)
		}
	}
}

func typesOf(es []Event) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Type)
	}
	return out
}

func TestBands(t *testing.T) {
	for days, want := range map[int]int{90: 0, 31: 0, 30: 30, 15: 30, 14: 14, 8: 14, 7: 7, 4: 7, 3: 3, 0: 3} {
		if got := BandOf(days); got != want {
			t.Errorf("%d days: band %d want %d", days, got, want)
		}
	}
}

func TestTLSThresholdsAnnounceOnceAndRenewalResets(t *testing.T) {
	day := 24 * time.Hour
	base := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	prev := TLSPrev{Known: true, State: TLSOK, Fingerprint: "A", NotAfter: base.Add(40 * day)}

	ev, band := TLSDiff(prev, TLSCur{State: TLSOK, Fingerprint: "A", DaysLeft: 29, NotAfter: base.Add(29 * day), HasCert: true}, "h", 443)
	if got := typesOf(ev); len(got) != 1 || got[0] != "tls.expiry_threshold" || band != 30 {
		t.Fatalf("%v band %d", got, band)
	}
	// The same day count the next morning: nothing new.
	prev.Band = band
	if ev, b := TLSDiff(prev, TLSCur{State: TLSOK, Fingerprint: "A", DaysLeft: 28, NotAfter: base.Add(28 * day), HasCert: true}, "h", 443); len(ev) != 0 || b != 30 {
		t.Fatalf("a repeat: %v band %d", typesOf(ev), b)
	}
	// Crossing the next threshold announces it once.
	if ev, b := TLSDiff(prev, TLSCur{State: TLSOK, Fingerprint: "A", DaysLeft: 14, NotAfter: base.Add(14 * day), HasCert: true}, "h", 443); len(ev) != 1 || b != 14 {
		t.Fatalf("%v band %d", typesOf(ev), b)
	}
	// A renewal: a different, longer-lived certificate. It clears the band and is not a threat.
	prev.Band = 3
	ev, b := TLSDiff(prev, TLSCur{State: TLSOK, Fingerprint: "B", DaysLeft: 89, NotAfter: base.Add(89 * day), HasCert: true}, "h", 443)
	if got := typesOf(ev); len(got) != 1 || got[0] != "tls.renewed" || b != 0 {
		t.Fatalf("%v band %d", got, b)
	}
	// A different certificate that does not outlast the old one is not called a renewal.
	if ev, _ := TLSDiff(prev, TLSCur{State: TLSOK, Fingerprint: "C", DaysLeft: 2, NotAfter: base.Add(2 * day), HasCert: true}, "h", 443); len(ev) == 0 || ev[0].Type == "tls.renewed" {
		t.Fatalf("%v", typesOf(ev))
	}
}

func TestTLSProblemsAreReportedOnFirstSightAndOnlyOnChange(t *testing.T) {
	cur := TLSCur{State: TLSExpired, Fingerprint: "A", DaysLeft: -2, HasCert: true}
	ev, _ := TLSDiff(TLSPrev{}, cur, "h", 443)
	if got := typesOf(ev); len(got) != 1 || got[0] != "tls.expired" || ev[0].Severity != SevCritical {
		t.Fatalf("%v", got)
	}
	if ev, _ := TLSDiff(TLSPrev{Known: true, State: TLSExpired, Fingerprint: "A"}, cur, "h", 443); len(ev) != 0 {
		t.Fatalf("an expired certificate must not be re-announced daily: %v", typesOf(ev))
	}
	bad := TLSCur{State: TLSHostname, Fingerprint: "A", DaysLeft: 60, HasCert: true}
	if ev, _ := TLSDiff(TLSPrev{Known: true, State: TLSOK, Fingerprint: "A"}, bad, "h", 443); len(ev) != 1 || ev[0].Type != "tls.validation_error" {
		t.Fatalf("%v", typesOf(ev))
	}
	good := TLSCur{State: TLSOK, Fingerprint: "A", DaysLeft: 60, HasCert: true}
	if ev, _ := TLSDiff(TLSPrev{Known: true, State: TLSHostname, Fingerprint: "A"}, good, "h", 443); len(ev) != 1 || ev[0].Type != "tls.validation_recovered" {
		t.Fatalf("%v", typesOf(ev))
	}
	// A handshake error without any certificate reports the error and never invents an expiry.
	if ev, _ := TLSDiff(TLSPrev{}, TLSCur{State: TLSHandshake}, "h", 8443); len(ev) != 1 || ev[0].Type != "tls.validation_error" {
		t.Fatalf("%v", typesOf(ev))
	}
}
