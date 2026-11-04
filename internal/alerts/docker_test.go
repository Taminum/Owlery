package alerts

import (
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/store"
)

func TestDockerConditions(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) *time.Time { x := now.Add(-d); return &x }
	state := store.DockerAlertState{VPSID: "v1", Name: "exit-nl", Containers: []secproto.DockerContainer{
		{Name: "fine", State: "running", Policy: "always"},
		{Name: "loops", State: "restarting", Restarts1h: 5, Exit: 1, Policy: "always"},
		{Name: "flaps", State: "running", Restarts1h: 3, Policy: "always"},
		{Name: "twice", State: "running", Restarts1h: 2, Policy: "always"},
		{Name: "stopped", State: "exited", Policy: "unless-stopped", Finished: ago(2 * time.Hour), Exit: 137},
		{Name: "just-stopped", State: "exited", Policy: "always", Finished: ago(30 * time.Second)},
		{Name: "job", State: "exited", Policy: "no", Finished: ago(2 * time.Hour)},
		{Name: "paused", State: "paused", Policy: "always"},
	}}
	got := DockerConditions([]store.DockerAlertState{state}, now)
	by := map[string]store.Condition{}
	for _, c := range got {
		by[c.Subject] = c
	}
	if len(got) != 3 {
		t.Fatalf("%d: %+v", len(got), got)
	}
	if c := by["v1:loops"]; c.Kind != store.AlertHostContainer || !strings.Contains(c.Label, "loops (exit-nl)") || !strings.Contains(c.Detail, "сейчас перезапускается") {
		t.Errorf("%+v", c)
	}
	if c := by["v1:flaps"]; c.Kind != store.AlertHostContainer {
		t.Errorf("three restarts in an hour is enough: %+v", c)
	}
	if c := by["v1:stopped"]; c.Kind != store.AlertHostContainerDown || !strings.Contains(c.Detail, "2 ч") || !strings.Contains(c.Detail, "137") {
		t.Errorf("%+v", c)
	}
}

func TestEveryDockerKindIsKnownAndGrouped(t *testing.T) {
	for _, k := range []string{store.AlertHostContainer, store.AlertHostContainerDown} {
		found := false
		for _, x := range Kinds {
			found = found || x == k
		}
		if !found || store.AlertGroupOf(k) != "resources" {
			t.Errorf("%s: listed %v, group %q", k, found, store.AlertGroupOf(k))
		}
	}
}
