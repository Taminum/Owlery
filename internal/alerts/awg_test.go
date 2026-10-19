package alerts

import (
	"strings"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/store"
)

func TestToolsMismatchComparesTheGenerationAndNeedsBothVersions(t *testing.T) {
	for _, c := range []struct {
		tools, module string
		want          bool
	}{
		{"1.0.20210914", "3.1.20260812", true},
		{"3.1.20260812", "3.1.20260812", false},
		{"3.1.20250101", "3.1.20260812", false}, // a newer build of the same generation is fine
		{"", "3.1.20260812", false},             // unknown is not a warning
		{"1.0.20210914", "", false},             // no kernel module: nothing to compare
		{"1", "3.1", false},
	} {
		if got := ToolsMismatch(c.tools, c.module); got != c.want {
			t.Errorf("%q %q: %v", c.tools, c.module, got)
		}
	}
}

func TestAWGConditionsSeparateABrokenContainerFromOneThatMayBreak(t *testing.T) {
	now := time.Now()
	fresh := now.Add(-time.Minute)
	got := AWGConditions([]store.AWGContainerState{
		{AgentID: "a", NodeName: "Steal", Container: "amnezia-awg2", Tools: "1.0.20210914", Module: "3.1.20260812", Down: true, SeenAt: fresh},
		{AgentID: "a", NodeName: "Steal", Container: "amnezia-awg3", Tools: "3.1.20260812", Module: "3.1.20260812", SeenAt: fresh},
		{AgentID: "b", NodeName: "Helsinki", Container: "amnezia-awg2", Tools: "1.0.20210914", Module: "3.1.20260812", SeenAt: fresh},
		{AgentID: "c", NodeName: "Old", Container: "amnezia-awg2", Down: true, SeenAt: now.Add(-time.Hour)},
	}, now)
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	if got[0].Kind != store.AlertAWGDown || !strings.Contains(got[0].Detail, "не подключаются") || !strings.Contains(got[0].Detail, "1.0.20210914") {
		t.Fatalf("%+v", got[0])
	}
	if got[1].Kind != store.AlertAWGToolsOld || !strings.Contains(got[1].Detail, "после перезагрузки") {
		t.Fatalf("%+v", got[1])
	}
}
