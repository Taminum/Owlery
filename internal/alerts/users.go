package alerts

import (
	"fmt"
	"strings"
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

const (
	// SubLeakWindow is how far back the addresses a subscription was asked for from are counted.
	SubLeakWindow = 7 * 24 * time.Hour
	// SubLeakIPs is the number of different addresses within the window at which the alert opens. The page already
	// marks a subscription for a look at half of this.
	SubLeakIPs = 10
)

const (
	// TorrentWindow is how far back the reports of the torrent blocker are counted for the alert.
	TorrentWindow = 24 * time.Hour
	// TorrentReports is the number of reports within the window at which the alert opens: one report can be a mistake.
	TorrentReports = 3
)

// TorrentConditions raises one alert for each subscription the torrent blocker caught again and again. It closes by
// itself when the reports within the window fall below the limit.
func TorrentConditions(list []store.Torrent) []store.Condition {
	var out []store.Condition
	for _, t := range list {
		who := t.Name
		if who == "" {
			who = "id " + t.RemoteUser
		}
		detail := fmt.Sprintf("торрент-блокер сработал %d раз за сутки", t.Reports)
		if len(t.Nodes) > 0 {
			detail += " (" + strings.Join(t.Nodes, ", ") + ")"
		}
		out = append(out, store.Condition{PanelID: t.PanelID, Kind: store.AlertTorrent, Subject: t.RemoteUser, Label: "Подписка " + who, Detail: detail})
	}
	return out
}

// SubLeakConditions raises one alert for each subscription that was asked for from many different addresses. The
// alert closes by itself when the addresses within the window fall below the limit.
func SubLeakConditions(leaks []store.SubLeak) []store.Condition {
	var out []store.Condition
	for _, l := range leaks {
		if l.IPs < SubLeakIPs {
			continue
		}
		who := l.Name
		if who == "" {
			who = "id " + l.RemoteUser
		}
		out = append(out, store.Condition{PanelID: l.PanelID, Kind: store.AlertSubLeak, Subject: l.RemoteUser, Label: "Подписка " + who,
			Detail: fmt.Sprintf("взята с %d разных IP за неделю: возможно, ею поделились", l.IPs)})
	}
	return out
}
