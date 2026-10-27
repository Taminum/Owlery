package alerts

import (
	"fmt"
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

const (
	// UserExpiryWarn is how long before the end of a subscription the alert opens.
	UserExpiryWarn = 72 * time.Hour
	// UserTrafficPercent is the share of the traffic limit at which the alert opens.
	UserTrafficPercent = 90
)

func daysWord(n int) string {
	switch {
	case n%10 == 1 && n%100 != 11:
		return fmt.Sprintf("%d день", n)
	case n%10 >= 2 && n%10 <= 4 && (n%100 < 10 || n%100 >= 20):
		return fmt.Sprintf("%d дня", n)
	}
	return fmt.Sprintf("%d дней", n)
}

func gib(b int64) string {
	return fmt.Sprintf("%.1f ГБ", float64(b)/(1<<30))
}

// UserConditions lists the active users whose subscription ends soon or who have nearly used their traffic.
// The states already hold only active users; what the panel did not say is simply not raised.
func UserConditions(states []store.UserLimitState, now time.Time) []store.Condition {
	var out []store.Condition
	for _, u := range states {
		if u.ExpireAt != nil && u.ExpireAt.After(now) && u.ExpireAt.Sub(now) <= UserExpiryWarn {
			left := u.ExpireAt.Sub(now)
			var when string
			if left < 24*time.Hour {
				when = "меньше чем через сутки"
			} else {
				when = "через " + daysWord(int(left.Round(24*time.Hour)/(24*time.Hour)))
			}
			out = append(out, store.Condition{PanelID: u.PanelID, Kind: store.AlertUserExpiry, Subject: u.UserID, Label: "Подписка " + u.Username,
				Detail: "заканчивается " + when + " (" + u.ExpireAt.UTC().Format("02.01.2006 15:04") + " UTC)"})
		}
		if u.LimitBytes != nil && *u.LimitBytes > 0 && u.UsedBytes != nil && *u.UsedBytes*100 >= *u.LimitBytes*UserTrafficPercent {
			pct := int(*u.UsedBytes * 100 / *u.LimitBytes)
			out = append(out, store.Condition{PanelID: u.PanelID, Kind: store.AlertUserTraffic, Subject: u.UserID, Label: "Трафик " + u.Username,
				Detail: fmt.Sprintf("использовано %d%% лимита: %s из %s", pct, gib(*u.UsedBytes), gib(*u.LimitBytes))})
		}
	}
	return out
}
