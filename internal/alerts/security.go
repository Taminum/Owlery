package alerts

import (
	"fmt"
	"time"

	"github.com/Taminum/RemnaScope/internal/secevents"
	"github.com/Taminum/RemnaScope/internal/store"
)

// TLSWarnDays is how close to expiry a certificate must be before it is an alert of its own. The journal
// announces each of the 30, 14, 7 and 3 day thresholds once; the alert stays open as long as the
// certificate is inside the first one.
const TLSWarnDays = 30

func days(d time.Duration) string {
	n := int(d.Hours() / 24)
	if n < 1 {
		return "меньше суток"
	}
	return fmt.Sprintf("%d дн.", n)
}

var tlsProblem = map[string]string{
	secevents.TLSUntrusted: "цепочка сертификатов не доверенная",
	secevents.TLSHostname:  "имя сертификата не совпадает с адресом",
	secevents.TLSInvalid:   "сертификат недействителен",
	secevents.TLSHandshake: "TLS не отвечает: рукопожатие не удалось",
}

// SecurityConditions lists what is wrong on the servers of the security module at moment now. Like
// Conditions it is a pure function of its input. What it does not know is never a condition: a check that
// could not run (an address that was not allowed, a name that did not resolve) is not an alert.
func SecurityConditions(st store.SecAlertStates, now time.Time) []store.Condition {
	var out []store.Condition
	for _, a := range st.Agents {
		// An agent that never connected is waiting to be installed, not gone.
		if a.LastSeen == nil {
			continue
		}
		if quiet := now.Sub(*a.LastSeen); quiet > AgentSilentAfter {
			out = append(out, store.Condition{PanelID: a.PanelID, Kind: store.AlertSecAgent, Subject: a.AgentID, Label: "Агент безопасности: " + a.VPSName,
				Detail: "не выходит на связь " + minutes(quiet) + "; данные Fail2ban, портов и firewall устаревают"})
		}
	}
	for _, e := range st.TLS {
		label := fmt.Sprintf("Сертификат %s:%d (%s)", e.Host, e.Port, e.VPSName)
		var left *time.Duration
		if e.NotAfter != nil {
			d := e.NotAfter.Sub(now)
			left = &d
		}
		switch {
		case e.State == secevents.TLSExpired || (left != nil && *left < 0):
			detail := "срок действия истёк"
			if left != nil {
				detail = "истёк " + days(-*left) + " назад"
			}
			out = append(out, store.Condition{PanelID: e.PanelID, Kind: store.AlertSecTLS, Subject: e.EndpointID, Label: label, Detail: detail})
		case tlsProblem[e.State] != "":
			out = append(out, store.Condition{PanelID: e.PanelID, Kind: store.AlertSecTLS, Subject: e.EndpointID, Label: label, Detail: tlsProblem[e.State]})
		case left != nil && *left <= TLSWarnDays*24*time.Hour:
			out = append(out, store.Condition{PanelID: e.PanelID, Kind: store.AlertSecTLS, Subject: e.EndpointID, Label: label, Detail: "истекает через " + days(*left)})
		}
	}
	for _, p := range st.Ports {
		label := fmt.Sprintf("Порт %s:%d (%s)", p.Host, p.Port, p.VPSName)
		switch {
		case !p.Expected && p.Result == secevents.PortReachable && p.UnexpectedSince != nil:
			out = append(out, store.Condition{PanelID: p.PanelID, Kind: store.AlertSecPort, Subject: p.EndpointID, Label: label,
				Detail: "стал отвечать снаружи с " + p.UnexpectedSince.UTC().Format("02.01 15:04") + " UTC, а ожидаемым не отмечен (проверка с сервера RemnaScope)"})
		case p.Expected && p.Result != secevents.PortReachable && p.Result != secevents.PortError:
			detail := "ожидаемый порт не отвечает"
			if p.Result == secevents.PortRefused {
				detail += ": соединение отклонено"
			} else {
				detail += " (нет ответа; это не доказывает, что порт закрыт)"
			}
			out = append(out, store.Condition{PanelID: p.PanelID, Kind: store.AlertSecPort, Subject: p.EndpointID, Label: label, Detail: detail})
		}
	}
	return out
}
