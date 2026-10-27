package alerts

import (
	"fmt"
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

// BillWarnDays is how many days before the due date a payment starts to show as an alert.
const BillWarnDays = 3

// BillConditions lists the payments that are due within BillWarnDays or are overdue. Dates are days, so the
// comparison is on the calendar day (UTC), not on a moment. An alert says what is due and when, nothing more.
func BillConditions(states []store.BillDueState, now time.Time) []store.Condition {
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	var out []store.Condition
	for _, b := range states {
		due := time.Date(b.NextDue.Year(), b.NextDue.Month(), b.NextDue.Day(), 0, 0, 0, 0, time.UTC)
		days := int(due.Sub(today) / (24 * time.Hour))
		if days > BillWarnDays {
			continue
		}
		var when string
		switch {
		case days < 0:
			when = "просрочена на " + daysWord(-days)
		case days == 0:
			when = "срок сегодня"
		default:
			when = "срок через " + daysWord(days)
		}
		detail := fmt.Sprintf("%s: %.2f %s, до %s", when, b.Amount, b.Currency, due.Format("02.01.2006"))
		if b.Provider != "" {
			detail += " (" + b.Provider + ")"
		}
		out = append(out, store.Condition{Kind: store.AlertBillDue, Subject: b.ID, Label: "Оплата: " + b.Name, Detail: detail})
	}
	return out
}
