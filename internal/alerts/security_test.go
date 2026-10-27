package alerts

import (
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

func ptr[T any](v T) *T { return &v }

func byKind(cs []store.Condition) map[string][]store.Condition {
	m := map[string][]store.Condition{}
	for _, c := range cs {
		m[c.Kind] = append(m[c.Kind], c)
	}
	return m
}

func TestSecurityConditions(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	st := store.SecAlertStates{
		Agents: []store.SecAgentAlert{
			{AgentID: "a-quiet", VPSName: "Helsinki", PanelID: "p1", LastSeen: ptr(now.Add(-8 * time.Minute))},
			{AgentID: "a-fine", VPSName: "Oslo", LastSeen: ptr(now.Add(-20 * time.Second))},
			{AgentID: "a-new", VPSName: "Waiting"}, // never connected: waiting to be installed
		},
		TLS: []store.SecTLSAlert{
			{EndpointID: "t-ok", VPSName: "H", Host: "a.example", Port: 443, State: "ok", NotAfter: ptr(now.Add(80 * day))},
			{EndpointID: "t-soon", VPSName: "H", Host: "b.example", Port: 443, State: "ok", NotAfter: ptr(now.Add(12 * day))},
			{EndpointID: "t-expired", VPSName: "H", Host: "c.example", Port: 443, State: "expired", NotAfter: ptr(now.Add(-3 * day))},
			{EndpointID: "t-host", VPSName: "H", Host: "d.example", Port: 443, State: "hostname_mismatch", NotAfter: ptr(now.Add(80 * day))},
			{EndpointID: "t-down", VPSName: "H", Host: "e.example", Port: 443, State: "unreachable"},
			{EndpointID: "t-blocked", VPSName: "H", Host: "f.example", Port: 443, State: "error"},
		},
		Ports: []store.SecPortAlert{
			{EndpointID: "p-baseline", VPSName: "H", Host: "h", Port: 22, Result: "reachable"},                                         // answering since the baseline: nothing
			{EndpointID: "p-new", VPSName: "H", Host: "h", Port: 9000, Result: "reachable", UnexpectedSince: ptr(now.Add(-time.Hour))}, // opened after the baseline
			{EndpointID: "p-ok", VPSName: "H", Host: "h", Port: 443, Expected: true, Result: "reachable"},
			{EndpointID: "p-dead", VPSName: "H", Host: "h", Port: 8443, Expected: true, Result: "refused"},
			{EndpointID: "p-slow", VPSName: "H", Host: "h", Port: 8444, Expected: true, Result: "timeout"},
			{EndpointID: "p-err", VPSName: "H", Host: "h", Port: 8445, Expected: true, Result: "error"}, // not checked: no verdict
			{EndpointID: "p-marked", VPSName: "H", Host: "h", Port: 9001, Expected: true, Result: "reachable", UnexpectedSince: ptr(now)},
		},
	}
	got := byKind(SecurityConditions(st, now))
	subjects := func(kind string) string {
		var s []string
		for _, c := range got[kind] {
			s = append(s, c.Subject)
		}
		return strings.Join(s, ",")
	}
	if subjects(store.AlertSecAgent) != "a-quiet" {
		t.Errorf("agents: %s", subjects(store.AlertSecAgent))
	}
	if subjects(store.AlertSecTLS) != "t-soon,t-expired,t-host" {
		t.Errorf("tls: %s", subjects(store.AlertSecTLS))
	}
	if subjects(store.AlertSecPort) != "p-new,p-dead,p-slow" {
		t.Errorf("ports: %s", subjects(store.AlertSecPort))
	}
	if got[store.AlertSecAgent][0].PanelID != "p1" {
		t.Errorf("an alert belongs to the server's panel: %+v", got[store.AlertSecAgent][0])
	}
	for _, c := range got[store.AlertSecPort] {
		if c.Subject == "p-slow" && !strings.Contains(c.Detail, "не доказывает") {
			t.Errorf("a timeout must not read as closed: %q", c.Detail)
		}
	}
	for _, c := range got[store.AlertSecTLS] {
		if c.Subject == "t-expired" && !strings.Contains(c.Detail, "3 дн.") {
			t.Errorf("%q", c.Detail)
		}
	}
}
