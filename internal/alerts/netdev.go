package alerts

import (
	"fmt"
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

// NetSilent is how long a router may stay silent: it reports once a minute, and a few minutes cover a slow link.
const NetSilent = 10 * time.Minute

// NetConnFullPercent is how full the connection table may get before the owner hears of it: past it a router starts dropping
// new connections, and the people behind it notice before any graph does.
const NetConnFullPercent = 80

// NetConditions flags a network device that has reported before and has now been silent for NetSilent. One that has never reported
// says nothing: its script is probably not installed yet.
func NetConditions(devs []store.NetDevice, now time.Time) []store.Condition {
	var out []store.Condition
	for _, d := range devs {
		if v := d.View; v.ConnAt != nil && v.ConnMax > 0 && now.Sub(*v.ConnAt) < NetSilent && v.Conn*100 >= v.ConnMax*NetConnFullPercent {
			out = append(out, store.Condition{Kind: store.AlertNetConnFull, Subject: d.ID, Label: "Таблица соединений почти полна: " + d.Name,
				Detail: fmt.Sprintf("%d из %d (%d%%)", v.Conn, v.ConnMax, v.Conn*100/v.ConnMax)})
		}
		if d.LastSeen == nil || now.Sub(*d.LastSeen) < NetSilent {
			continue
		}
		out = append(out, store.Condition{Kind: store.AlertNetDown, Subject: d.ID, Label: "Роутер «" + d.Name + "» не отвечает", Detail: "Последние данные: " + minutes(now.Sub(*d.LastSeen)) + " назад"})
	}
	return out
}
