package secevents

import (
	"fmt"
	"time"
)

// Port results of the external TCP check. A timeout or an unreachable answer is never "closed": only a
// refused connection says that, and only for the address that was asked.
const (
	PortReachable = "reachable"
	PortRefused   = "refused"
	PortTimeout   = "timeout"
	PortFiltered  = "filtered_or_unknown"
	PortError     = "error"
)

// PortPrev is what is known of an endpoint before this observation. Known is false for the first one.
type PortPrev struct {
	Known  bool
	Result string
}

// PortDiff explains the change between two observations of one endpoint. The first observation is a
// baseline; an error result (a blocked address, a name that did not resolve) says nothing about the
// port and neither starts nor ends anything.
func PortDiff(prev PortPrev, cur string, expected bool, host string, port int, ip string) []Event {
	if cur == PortError || !prev.Known || prev.Result == PortError || prev.Result == cur {
		return nil
	}
	key := fmt.Sprintf("%s|%d", host, port)
	payload := func() map[string]any {
		return map[string]any{"host": host, "port": port, "ip": ip, "result": cur, "previous": prev.Result, "expected": expected,
			"vantage": "api_server", "source": "external_check"}
	}
	switch {
	case cur == PortReachable:
		sev := SevInfo
		if !expected {
			sev = SevCritical
		}
		return []Event{{Category: "ports", Type: "port.public_reachable", Severity: sev, Key: key, Payload: payload()}}
	case prev.Result == PortReachable:
		p := payload()
		p["conclusive"] = cur == PortRefused // a timeout does not prove the port is closed
		sev := SevInfo
		if expected {
			sev = SevWarning
		}
		return []Event{{Category: "ports", Type: "port.public_lost", Severity: sev, Key: key, Payload: p}}
	}
	return nil
}

// TLS verdicts.
const (
	TLSOK            = "ok"
	TLSExpired       = "expired"
	TLSUntrusted     = "untrusted"
	TLSHostname      = "hostname_mismatch"
	TLSInvalid       = "invalid"
	TLSHandshake     = "handshake_error"
	TLSUnreachable   = "unreachable"
	TLSBlocked       = "error"
	expiryBandsCount = 4
)

// ExpiryBands are the days-left thresholds that each produce one notice.
var ExpiryBands = [expiryBandsCount]int{30, 14, 7, 3}

// BandOf returns the threshold a certificate with this many days left has crossed (30, 14, 7 or 3), or 0.
func BandOf(daysLeft int) int {
	band := 0
	for _, b := range ExpiryBands {
		if daysLeft <= b {
			band = b
		}
	}
	return band
}

type TLSPrev struct {
	Known       bool
	State       string
	Fingerprint string
	NotAfter    time.Time
	Band        int
}

type TLSCur struct {
	State       string // one of the TLS* verdicts
	Fingerprint string
	DaysLeft    int
	NotAfter    time.Time
	HasCert     bool
}

// TLSDiff turns a new observation into events and the band to remember. Problems are reported even on
// the first observation (a certificate with five days left is worth knowing about at once); a renewal or
// a recovery needs something earlier to compare with. Each threshold is announced once and the memory is
// cleared by a renewal, so the same notice never repeats daily.
func TLSDiff(prev TLSPrev, cur TLSCur, host string, port int) (events []Event, band int) {
	band = prev.Band
	key := fmt.Sprintf("%s|%d", host, port)
	payload := func(extra map[string]any) map[string]any {
		p := map[string]any{"host": host, "port": port, "state": cur.State, "vantage": "api_server", "source": "external_check"}
		if cur.HasCert {
			p["days_left"] = cur.DaysLeft
		}
		for k, v := range extra {
			p[k] = v
		}
		return p
	}
	if prev.Known && cur.HasCert && prev.Fingerprint != "" && cur.Fingerprint != prev.Fingerprint {
		// A different certificate that outlasts the old one is a normal rotation, not a threat; any other
		// change is reported as a change. Either way the thresholds start over for the new certificate.
		typ := "tls.fingerprint_changed"
		if cur.NotAfter.After(prev.NotAfter) {
			typ = "tls.renewed"
		}
		events = append(events, Event{Category: "tls", Type: typ, Severity: SevInfo, Key: key + "|" + cur.Fingerprint, Payload: payload(nil)})
		band = 0
	}
	switch cur.State {
	case TLSExpired:
		if prev.State != TLSExpired {
			events = append(events, Event{Category: "tls", Type: "tls.expired", Severity: SevCritical, Key: key, Payload: payload(nil)})
		}
	case TLSUntrusted, TLSHostname, TLSInvalid, TLSHandshake:
		if prev.State != cur.State {
			events = append(events, Event{Category: "tls", Type: "tls.validation_error", Severity: SevWarning, Key: key + "|" + cur.State, Payload: payload(nil)})
		}
	case TLSOK:
		if prev.Known && prev.State != TLSOK && prev.State != "" && prev.State != TLSUnreachable && prev.State != TLSBlocked {
			events = append(events, Event{Category: "tls", Type: "tls.validation_recovered", Severity: SevInfo, Key: key + "|" + prev.State, Payload: payload(nil)})
		}
	}
	if cur.HasCert && cur.State != TLSExpired {
		if b := BandOf(cur.DaysLeft); b != 0 && (band == 0 || b < band) {
			events = append(events, Event{Category: "tls", Type: "tls.expiry_threshold", Severity: SevWarning, Key: fmt.Sprintf("%s|%d", key, b), Payload: payload(map[string]any{"threshold_days": b})})
			band = b
		} else if b == 0 {
			band = 0
		}
	}
	return events, band
}
