package alerts

import (
	"fmt"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/dnsmap"
	"github.com/Taminum/Owlery/internal/store"
)

var dnsKindWords = map[string]string{
	dnsmap.ChangeNS:      "делегирование (NS)",
	dnsmap.ChangeMX:      "почтовые серверы (MX)",
	dnsmap.ChangeSPF:     "SPF",
	dnsmap.ChangeDMARC:   "DMARC",
	dnsmap.ChangeRemoved: "удалена запись",
	dnsmap.ChangeValue:   "значение записи",
}

// DNSConditions lists what is wrong with the DNS maps at moment now. An alert says what was seen and no more
// than that; a change is "observed", never "an attack", and a failed check keeps the data it had.
func DNSConditions(states []store.DNSAlertState, now time.Time) []store.Condition {
	var out []store.Condition
	for _, st := range states {
		// An alert belongs to no panel: DNS Map is the owner's, and so are its alerts.
		if st.Failed {
			out = append(out, store.Condition{Kind: store.AlertDNSFailed, Subject: st.MapID, Label: "DNS Map: " + st.Domain,
				Detail: "последняя проверка не смогла получить даже базовые записи (SOA, NS, A): резолверы не отвечают или имя недоступно; прежние данные сохранены, ничего не удалено"})
		}
		if st.Important > 0 {
			var words []string
			for _, k := range st.Kinds {
				if w := dnsKindWords[k]; w != "" {
					words = append(words, w)
				}
			}
			detail := fmt.Sprintf("за последние сутки подтверждено изменений: %d (%s)", st.Important, strings.Join(words, ", "))
			if st.Latest != nil {
				detail += "; последнее " + minutes(now.Sub(*st.Latest)) + " назад"
			}
			out = append(out, store.Condition{Kind: store.AlertDNSChange, Subject: st.MapID, Label: "DNS: изменения у " + st.Domain, Detail: detail})
		}
	}
	return out
}
