package notify

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

var monthNames = [...]string{"январь", "февраль", "март", "апрель", "май", "июнь", "июль", "август", "сентябрь", "октябрь", "ноябрь", "декабрь"}
var monthNamesOf = [...]string{"января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа", "сентября", "октября", "ноября", "декабря"}

var eventNames = map[string]string{
	"fail2ban.ban":             "блокировок Fail2ban",
	"fail2ban.unban":           "снято блокировок Fail2ban",
	"firewall.rules_changed":   "изменений правил файрвола",
	"port.local_added":         "новых слушающих портов",
	"port.public_reachable":    "портов стали отвечать снаружи",
	"tls.expiry_threshold":     "сертификатов скоро истекут",
	"tls.expired":              "сертификатов истекло",
	"tls.validation_error":     "сертификатов перестали быть действительными",
	"fail2ban.bans_unobserved": "блокировок между проверками",
}

func monthTitle(month string) string {
	t, err := time.Parse("2006-01", month)
	if err != nil {
		return month
	}
	return fmt.Sprintf("%s %d", monthNames[t.Month()-1], t.Year())
}

func humanBytes(b int64) string {
	const k = 1024.0
	v := float64(b)
	for _, u := range []string{"Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ"} {
		if v < k || u == "ПБ" {
			if u == "Б" {
				return fmt.Sprintf("%d %s", b, u)
			}
			return strings.Replace(fmt.Sprintf("%.1f %s", v, u), ".", ",", 1)
		}
		v /= k
	}
	return ""
}

func minsText(m int) string {
	if m >= 60 {
		if m%60 == 0 {
			return fmt.Sprintf("%d ч", m/60)
		}
		return fmt.Sprintf("%d ч %d мин", m/60, m%60)
	}
	return fmt.Sprintf("%d мин", m)
}

func moneyText(ms []store.ReportMoney) string {
	if len(ms) == 0 {
		return "оплат не было"
	}
	var p []string
	for _, m := range ms {
		p = append(p, fmt.Sprintf("%s %s", strings.Replace(fmt.Sprintf("%.2f", m.Amount), ".", ",", 1), m.Currency))
	}
	return strings.Join(p, " + ")
}

// delta says how a number moved against the month before, or nothing when there is nothing to compare with.
func delta(cur, prev int, prevKnown bool) string {
	if !prevKnown {
		return ""
	}
	switch d := cur - prev; {
	case d > 0:
		return fmt.Sprintf(" (+%d к прошлому)", d)
	case d < 0:
		return fmt.Sprintf(" (%d к прошлому)", d)
	}
	return " (как в прошлом)"
}

// MonthlyReportText is the report as a message: short lines, what moved, and nothing for a part that has no data.
func MonthlyReportText(r store.MonthReport) string {
	c, p := r.Cur, r.Prev
	var b strings.Builder
	fmt.Fprintf(&b, "ОТЧЁТ ЗА МЕСЯЦ: %s\n\n", strings.ToUpper(monthTitle(c.Month)))
	b.WriteString("🖥 Машины\n")
	if c.Availability != nil {
		pct := strings.Replace(fmt.Sprintf("%.2f", *c.Availability), ".", ",", 1)
		extra := ""
		if p.Availability != nil {
			d := *c.Availability - *p.Availability
			if math.Abs(d) >= 0.005 {
				extra = fmt.Sprintf(" (%+.2f п.п.)", d)
				extra = strings.Replace(extra, ".", ",", 1)
			}
		}
		fmt.Fprintf(&b, "Доступность: %s%%%s\n", pct, extra)
	} else {
		b.WriteString("Доступность: данных нет\n")
	}
	for _, w := range c.Worst {
		fmt.Fprintf(&b, "Больше всего простоя: %s, %s\n", w.Name, minsText(w.DownMins))
	}
	fmt.Fprintf(&b, "Тревог: %d%s\n", c.Alerts, delta(c.Alerts, p.Alerts, p.Alerts > 0))
	if c.Noisy != nil {
		fmt.Fprintf(&b, "Самая частая: %s, %d раз\n", c.Noisy.Label, c.Noisy.Count)
	}
	if c.Longest != nil {
		fmt.Fprintf(&b, "Дольше всего длилась: %s, %s\n", c.Longest.Label, minsText(c.Longest.Mins))
	}
	b.WriteString("\n🛡 Защита\n")
	if c.EventTotal == 0 {
		b.WriteString("Событий в журнале не было\n")
	}
	for _, e := range c.Events {
		name := eventNames[e.Type]
		if name == "" {
			name = e.Type
		}
		fmt.Fprintf(&b, "%d %s\n", e.Count, name)
	}
	b.WriteString("\n🌐 Сеть и дом\n")
	if c.NetDowns == 0 {
		b.WriteString("Роутеры не пропадали\n")
	} else {
		fmt.Fprintf(&b, "Роутеры молчали %d раз, всего %s (дольше всего: %s)\n", c.NetDowns, minsText(c.NetDownMins), c.NetWorst)
	}
	fmt.Fprintf(&b, "Новых устройств: %d\n", c.NewDevices)
	if c.TrafficBytes != nil {
		extra := ""
		if p.TrafficBytes != nil && *p.TrafficBytes > 0 {
			extra = fmt.Sprintf(" (%+.0f%%)", (float64(*c.TrafficBytes)/float64(*p.TrafficBytes)-1)*100)
		}
		fmt.Fprintf(&b, "\n📶 Трафик VPN: %s%s\n", humanBytes(*c.TrafficBytes), extra)
	}
	b.WriteString("\n💳 Деньги\n")
	fmt.Fprintf(&b, "Оплачено за месяц: %s\n", moneyText(c.Paid))
	for _, d := range r.Upcoming {
		t, err := time.Parse("2006-01-02", d.Due)
		due := d.Due
		if err == nil {
			due = fmt.Sprintf("%d %s", t.Day(), monthNamesOf[t.Month()-1])
		}
		fmt.Fprintf(&b, "Скоро оплата: %s, %s, %s %s\n", d.Name, due, strings.Replace(fmt.Sprintf("%.2f", d.Amount), ".", ",", 1), d.Currency)
	}
	return strings.TrimRight(b.String(), "\n")
}

// reportHour is when the monthly report goes out on days it is due, for a channel that has no hour of its own for the digest.
const reportHour = 9

// reports sends last month's report to each channel that has not had it yet, from the morning of the first day on. A channel is
// asked once a month: what it last got is kept, so a restart or a late start sends it the same day or the next, never twice.
func (w *Worker) reports(ctx context.Context, chans []store.NotifyChannel) {
	for _, c := range chans {
		if !c.Enabled {
			continue
		}
		loc, err := time.LoadLocation(c.DigestTZ)
		if err != nil {
			loc = time.UTC
		}
		now := w.now()
		hour := reportHour
		if c.DigestHr != nil {
			hour = *c.DigestHr
		}
		local := now.In(loc)
		if local.Hour() < hour {
			continue
		}
		thisMonth := store.MonthStart(now, loc)
		last := thisMonth.AddDate(0, -1, 0)
		sent, err := w.Store.ReportMonthSent(ctx, c.ID)
		if err != nil {
			continue
		}
		if !sent.Before(time.Date(last.Year(), last.Month(), 1, 0, 0, 0, 0, time.UTC)) {
			continue // that month's report is already out
		}
		rep, err := w.Store.BuildMonthReport(ctx, last, now, loc)
		if err != nil {
			w.Log.Error("notify: building the monthly report", "err", err)
			continue
		}
		if err := w.SendTo(ctx, c, MonthlyReportText(rep)); err != nil {
			continue
		}
		if err := w.Store.MarkReportSent(ctx, c.ID, last); err != nil {
			w.Log.Error("notify: marking the monthly report", "err", err)
		}
	}
}
