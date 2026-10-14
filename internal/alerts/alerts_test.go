package alerts

import (
	"strings"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/store"
)

var now = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func ago(d time.Duration) *time.Time { t := now.Add(-d); return &t }

func TestAgentSilenceNeedsAPastConnectionAndRealQuiet(t *testing.T) {
	agents := []store.AgentState{
		{AgentID: "a-live", PanelID: "p", Kind: "node", NodeName: "Steal", Status: "active", LastSeen: ago(20 * time.Second)},
		{AgentID: "a-gone", PanelID: "p", Kind: "node", NodeName: "Helsinki", Status: "active", LastSeen: ago(12 * time.Minute)},
		{AgentID: "a-router", PanelID: "p", Kind: "router", Name: "OpenWrt", NodeName: "Helsinki", Status: "active", LastSeen: ago(3 * time.Hour)},
		{AgentID: "a-new", PanelID: "p", Kind: "node", NodeName: "X", Status: "enrolling"},                               // never connected: waiting
		{AgentID: "a-new2", PanelID: "p", Kind: "node", NodeName: "Y", Status: "active"},                                 // no last_seen
		{AgentID: "a-edge", PanelID: "p", Kind: "node", NodeName: "Z", Status: "active", LastSeen: ago(4 * time.Minute)}, // inside the grace period
	}
	got := Conditions(agents, nil, nil, now)
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	by := map[string]store.Condition{}
	for _, c := range got {
		by[c.Subject] = c
	}
	if c := by["a-gone"]; c.Kind != store.AlertAgentSilent || c.Label != "Агент ноды Helsinki" || !strings.Contains(c.Detail, "12 мин") {
		t.Fatalf("%+v", c)
	}
	if c := by["a-router"]; c.Label != "Агент роутера OpenWrt" || !strings.Contains(c.Detail, "3 ч") {
		t.Fatalf("%+v", c)
	}
}

func TestPanelSyncAlertsOnRepeatedFailureOrAnOpenBreaker(t *testing.T) {
	soon := now.Add(10 * time.Minute)
	past := now.Add(-time.Minute)
	panels := []store.PanelState{
		{PanelID: "ok", Name: "Fine", Failures: 0},
		{PanelID: "two", Name: "Two", Failures: 2},
		{PanelID: "three", Name: "Three", Failures: 3, LastSync: ago(40 * time.Minute)},
		{PanelID: "open", Name: "Open", Failures: 1, Open: &soon},
		{PanelID: "expired", Name: "Expired", Failures: 1, Open: &past},
	}
	got := Conditions(nil, panels, nil, now)
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	for _, c := range got {
		switch c.Subject {
		case "three":
			if !strings.Contains(c.Detail, "3 неудач") || !strings.Contains(c.Detail, "40 мин") {
				t.Fatalf("%+v", c)
			}
		case "open":
			if !strings.Contains(c.Detail, "временно отключена") {
				t.Fatalf("%+v", c)
			}
		default:
			t.Fatalf("unexpected %+v", c)
		}
	}
}

func TestAChannelIsDownOnlyAfterThreeFailuresInARow(t *testing.T) {
	probes := []store.ProbeState{
		{TargetID: "ok", PanelID: "p", Name: "Fine", Recent: []bool{true, true, true}},
		{TargetID: "blip", PanelID: "p", Name: "Blip", Recent: []bool{false, true, true}},
		{TargetID: "two", PanelID: "p", Name: "Two", Recent: []bool{false, false, true}},
		{TargetID: "young", PanelID: "p", Name: "New", Recent: []bool{false, false}}, // not enough history
		{TargetID: "down", PanelID: "p", Name: "Helsinki CDN", Recent: []bool{false, false, false}, LastErr: "timeout"},
		{TargetID: "none", PanelID: "p", Name: "Silent"},
	}
	got := Conditions(nil, nil, probes, now)
	if len(got) != 1 || got[0].Subject != "down" || got[0].Kind != store.AlertProbeDown || got[0].Label != "Канал Helsinki CDN" || !strings.Contains(got[0].Detail, "timeout") {
		t.Fatalf("%+v", got)
	}
}
