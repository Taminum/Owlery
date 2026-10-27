package alerts

import (
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

// majorMinor reads "3.1.20260812" as "3.1"; anything else gives "".
func majorMinor(v string) string {
	p := strings.Split(strings.TrimSpace(v), ".")
	if len(p) < 2 || p[0] == "" || p[1] == "" {
		return ""
	}
	return p[0] + "." + p[1]
}

// ToolsMismatch says that the awg tools in a container are of another generation than the host's kernel module.
// Both must be known: a host with no kernel module (the userspace implementation) has nothing to compare.
func ToolsMismatch(tools, module string) bool {
	a, b := majorMinor(tools), majorMinor(module)
	return a != "" && b != "" && a != b
}

// AWGConditions lists the AmneziaWG containers that cannot work or may stop working. A container that runs
// without an interface has nobody connected; a container whose tools do not match the kernel module may be fine
// now (the module in memory is the old one) and fail at the next reboot of the host.
func AWGConditions(states []store.AWGContainerState, now time.Time) []store.Condition {
	var out []store.Condition
	for _, st := range states {
		if now.Sub(st.SeenAt) > 15*time.Minute {
			continue // not reported lately: the agent's own silence is another alert
		}
		mismatch := ToolsMismatch(st.Tools, st.Module)
		versions := ""
		if st.Tools != "" && st.Module != "" {
			versions = " Утилиты в контейнере: " + st.Tools + ", модуль ядра на хосте: " + st.Module + "."
		}
		subject := st.AgentID + ":" + st.Container
		if st.Down {
			detail := "контейнер запущен, но интерфейса AmneziaWG в нём нет: устройства не подключаются."
			if mismatch {
				detail += " Похоже, утилиты в контейнере старше модуля ядра хоста и не могут поднять интерфейс." + versions
			}
			out = append(out, store.Condition{PanelID: st.PanelID, Kind: store.AlertAWGDown, Subject: subject, Label: "AmneziaWG " + st.Container + " на " + st.NodeName + ": не работает", Detail: detail})
			continue
		}
		if mismatch {
			out = append(out, store.Condition{PanelID: st.PanelID, Kind: store.AlertAWGToolsOld, Subject: subject, Label: "AmneziaWG " + st.Container + " на " + st.NodeName + ": версии не сходятся",
				Detail: "сейчас работает, но после перезагрузки сервера интерфейс может не подняться." + versions})
		}
	}
	return out
}
