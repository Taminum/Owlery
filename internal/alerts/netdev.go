package alerts

import (
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

// NetSilent is how long a router may stay silent: it reports once a minute, and a few minutes cover a slow link.
const NetSilent = 10 * time.Minute

// NetConditions flags a network device that has reported before and has now been silent for NetSilent. One that has never reported
// says nothing: its script is probably not installed yet.
func NetConditions(devs []store.NetDevice, now time.Time) []store.Condition {
	var out []store.Condition
	for _, d := range devs {
		if d.LastSeen == nil || now.Sub(*d.LastSeen) < NetSilent {
			continue
		}
		out = append(out, store.Condition{Kind: store.AlertNetDown, Subject: d.ID, Label: "Роутер «" + d.Name + "» не отвечает", Detail: "Последние данные: " + minutes(now.Sub(*d.LastSeen)) + " назад"})
	}
	return out
}
