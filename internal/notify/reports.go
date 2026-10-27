package notify

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

var weekdays = []string{"воскресенье", "понедельник", "вторник", "среда", "четверг", "пятница", "суббота"}
var months = []string{"", "января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа", "сентября", "октября", "ноября", "декабря"}

// flag turns a two-letter country code into the flag emoji, or "" for anything else.
func flag(cc string) string {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return ""
	}
	return string([]rune{0x1F1E6 + rune(cc[0]-'A'), 0x1F1E6 + rune(cc[1]-'A')})
}

func pct(used, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return float64(used) * 100 / float64(total)
}

func rootDisk(h store.HostRow) (float64, bool) {
	for _, d := range h.Disks {
		if d.Mount == "/" && d.Total > 0 {
			return pct(d.Used, d.Total), true
		}
	}
	if len(h.Disks) > 0 && h.Disks[0].Total > 0 {
		return pct(h.Disks[0].Used, h.Disks[0].Total), true
	}
	return 0, false
}

func bitrate(bytesPerSec float64) string {
	bits := bytesPerSec * 8
	switch {
	case bits >= 1e9:
		return fmt.Sprintf("%.1f Гбит/с", bits/1e9)
	case bits >= 1e6:
		return fmt.Sprintf("%.1f Мбит/с", bits/1e6)
	case bits >= 1e3:
		return fmt.Sprintf("%.0f Кбит/с", bits/1e3)
	}
	return fmt.Sprintf("%.0f бит/с", bits)
}

func days(t time.Time, now time.Time) int {
	a := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	b := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	return int(b.Sub(a) / (24 * time.Hour))
}

func daysText(n int) string {
	switch {
	case n < 0:
		return fmt.Sprintf("просрочено на %d дн.", -n)
	case n == 0:
		return "сегодня"
	case n == 1:
		return "завтра"
	}
	return fmt.Sprintf("через %d дн.", n)
}

func money(v float64, cur string) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", v), "0"), ".") + " " + cur
}

// hostState: 🟢 all well, 🟡 something is near its limit, 🔴 does not report, ⚪ has no agent.
func hostState(h store.HostRow) string {
	switch {
	case !h.HasData:
		return "⚪"
	case !h.Online:
		return "🔴"
	}
	if h.CPUPct != nil && *h.CPUPct >= 90 {
		return "🟡"
	}
	if pct(h.MemUsed, h.MemTotal) >= 90 {
		return "🟡"
	}
	if d, ok := rootDisk(h); ok && d >= 90 {
		return "🟡"
	}
	return "🟢"
}

func hostLine(h store.HostRow, withNet bool) string {
	var b strings.Builder
	b.WriteString(hostState(h) + " ")
	if f := flag(h.Country); f != "" {
		b.WriteString(f + " ")
	}
	b.WriteString(h.Name)
	switch {
	case !h.HasData:
		b.WriteString(" — агент ещё не присылал данные")
	case !h.Online:
		b.WriteString(" — нет связи")
	default:
		cpu := "—"
		if h.CPUPct != nil {
			cpu = fmt.Sprintf("%.0f%%", *h.CPUPct)
		}
		fmt.Fprintf(&b, " — ЦП: %s | RAM: %.0f%%", cpu, pct(h.MemUsed, h.MemTotal))
		if d, ok := rootDisk(h); ok {
			fmt.Fprintf(&b, " | диск: %.0f%%", d)
		}
		if withNet {
			fmt.Fprintf(&b, " | ↓%s ↑%s", bitrate(h.RXBps), bitrate(h.TXBps))
		}
	}
	return b.String()
}

func allHosts(ctx context.Context, st *store.Store, now time.Time) ([]store.HostRow, error) {
	return st.Hosts(ctx, store.Scope{All: true}, now)
}

func openAlerts(ctx context.Context, st *store.Store) ([]store.Alert, error) {
	panels, err := st.ListPanels(ctx, store.Scope{All: true})
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, p := range panels {
		if !p.Demo {
			ids = append(ids, p.ID)
		}
	}
	return st.ListAlerts(ctx, ids, true, true, 50)
}

// BuildStats is the summary of the whole cluster, on request.
func BuildStats(ctx context.Context, st *store.Store, now time.Time, loc *time.Location) (string, error) {
	return buildStats(ctx, st, now, loc, "СВОДКА Owlery")
}

func buildStats(ctx context.Context, st *store.Store, now time.Time, loc *time.Location, title string) (string, error) {
	l := now.In(loc)
	hosts, err := allHosts(ctx, st, now)
	if err != nil {
		return "", err
	}
	alerts, err := openAlerts(ctx, st)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "📊 %s\n\n", title)
	fmt.Fprintf(&b, "📅 Дата: %s, %d %s %d г.\n⏰ Время: %s\n\n", weekdays[l.Weekday()], l.Day(), months[l.Month()], l.Year(), l.Format("15:04:05"))

	online, attention := 0, 0
	var cpuSum, memSum float64
	var cpuN, memN int
	for _, h := range hosts {
		if h.Online {
			online++
		}
		if s := hostState(h); s == "🟡" || s == "🔴" {
			attention++
		}
		if h.Online && h.CPUPct != nil {
			cpuSum += *h.CPUPct
			cpuN++
		}
		if h.Online && h.MemTotal > 0 {
			memSum += pct(h.MemUsed, h.MemTotal)
			memN++
		}
	}
	b.WriteString("📡 Состояние инфраструктуры:\n")
	fmt.Fprintf(&b, "• Всего серверов: %d\n• В сети (Online): %d\n• Внимание / Алармы: %d\n", len(hosts), online, max(attention, len(alerts)))
	if cpuN > 0 {
		fmt.Fprintf(&b, "• Средняя нагрузка ЦП: %.0f%%\n", cpuSum/float64(cpuN))
	}
	if memN > 0 {
		fmt.Fprintf(&b, "• Среднее потребление RAM: %.0f%%\n", memSum/float64(memN))
	}
	bills, err := st.Bills(ctx)
	if err != nil {
		return "", err
	}
	monthly := map[string]float64{}
	for _, x := range bills {
		monthly[x.Currency] += x.Amount / float64(x.PeriodMonths)
	}
	if len(monthly) > 0 {
		var cs []string
		for c := range monthly {
			cs = append(cs, c)
		}
		sort.Strings(cs)
		var parts []string
		for _, c := range cs {
			parts = append(parts, "~"+money(monthly[c], c))
		}
		fmt.Fprintf(&b, "• Расходы на инфраструктуру: %s / мес\n", strings.Join(parts, " + "))
	}

	if len(hosts) > 0 {
		b.WriteString("\n🖥 Статус серверов:\n")
		for _, h := range hosts {
			b.WriteString(hostLine(h, false) + "\n")
		}
	}

	// Security: Fail2ban and certificates.
	if sum, err := st.SecuritySummaries(ctx, store.Scope{All: true}); err == nil && len(sum) > 0 {
		banned, total := 0, 0
		for _, s := range sum {
			banned += s.Banned
			total += s.TotalBanned
		}
		fmt.Fprintf(&b, "\n🛡 Безопасность:\n• Fail2ban: сейчас в бане %d адресов (за всё время %d)\n", banned, total)
	}
	if ev, err := st.SecurityEventCounts(ctx, store.Scope{All: true}, now.Add(-24*time.Hour), now); err == nil {
		for _, e := range ev {
			if e.Type == "fail2ban.ban" {
				fmt.Fprintf(&b, "• Блокировок за сутки: %d\n", e.Count)
			}
		}
	}
	if sec, err := st.SecurityAlertStates(ctx); err == nil {
		var next *store.SecTLSAlert
		for i := range sec.TLS {
			if sec.TLS[i].NotAfter != nil && (next == nil || sec.TLS[i].NotAfter.Before(*next.NotAfter)) {
				next = &sec.TLS[i]
			}
		}
		if next != nil {
			fmt.Fprintf(&b, "• Ближайший сертификат: %s:%d — %s\n", next.Host, next.Port, daysText(days(*next.NotAfter, now)))
		}
	}

	// AmneziaWG.
	if inst, err := st.AWGInstances(ctx, store.Scope{All: true}, 24*time.Hour); err == nil && len(inst) > 0 {
		on, all := 0, 0
		for _, i := range inst {
			for _, p := range i.Peers {
				if p.Gone {
					continue
				}
				all++
				if p.Handshake != nil && now.Sub(*p.Handshake) < 3*time.Minute {
					on++
				}
			}
		}
		fmt.Fprintf(&b, "\n🔐 AmneziaWG: серверов %d, устройств онлайн %d из %d\n", len(inst), on, all)
	}

	// Subscriptions that end soon.
	if subs, err := st.ListSubscriptions(ctx, store.Scope{All: true}, 500); err == nil {
		var soon []string
		for _, s := range subs {
			if s.Status == "ACTIVE" && s.ExpireAt != nil && days(*s.ExpireAt, now) >= 0 && days(*s.ExpireAt, now) <= 7 {
				soon = append(soon, fmt.Sprintf("%s (%s)", s.Username, daysText(days(*s.ExpireAt, now))))
			}
		}
		if len(soon) > 0 {
			if len(soon) > 5 {
				soon = append(soon[:5], fmt.Sprintf("и ещё %d", len(soon)-5))
			}
			fmt.Fprintf(&b, "\n👥 Подписки скоро закончатся: %s\n", strings.Join(soon, ", "))
		}
	}

	b.WriteString("\n💳 Ближайшие оплаты:\n")
	b.WriteString(payLines(bills, now))
	if len(alerts) > 0 {
		fmt.Fprintf(&b, "\n⚠️ Открытые оповещения (%d):\n", len(alerts))
		for i, a := range alerts {
			if i >= 5 {
				b.WriteString("  …\n")
				break
			}
			b.WriteString("  • " + a.Label + "\n")
		}
	}
	return b.String(), nil
}

func payLines(bills []store.Bill, now time.Time) string {
	var due []store.Bill
	for _, x := range bills {
		if t, err := time.Parse("2006-01-02", x.NextDue); err == nil && days(t, now) <= 14 {
			due = append(due, x)
		}
	}
	if len(bills) == 0 {
		return "  • Список оплат пуст (вкладка «Оплата»)\n"
	}
	if len(due) == 0 {
		return "  • Все серверы оплачены, срочных счетов нет\n"
	}
	var b strings.Builder
	for _, x := range due {
		t, _ := time.Parse("2006-01-02", x.NextDue)
		fmt.Fprintf(&b, "  • %s — %s, %s (%s)\n", x.Name, money(x.Amount, x.Currency), daysText(days(t, now)), t.Format("02.01"))
	}
	return b.String()
}

// BuildServers lists every server with its load and network.
func BuildServers(ctx context.Context, st *store.Store, now time.Time) (string, error) {
	hosts, err := allHosts(ctx, st, now)
	if err != nil {
		return "", err
	}
	if len(hosts) == 0 {
		return "Серверов пока нет.", nil
	}
	var b strings.Builder
	b.WriteString("🖥 Серверы\n\n")
	for _, h := range hosts {
		b.WriteString(hostLine(h, true) + "\n")
		if h.Online && (h.SynRecv > 0 || h.Estab > 0) {
			fmt.Fprintf(&b, "    соединений %d, полуоткрытых %d, load %.2f\n", h.Estab, h.SynRecv, h.Load1)
		}
	}
	return b.String(), nil
}

// BuildAlerts lists what is open now.
func BuildAlerts(ctx context.Context, st *store.Store, now time.Time) (string, error) {
	al, err := openAlerts(ctx, st)
	if err != nil {
		return "", err
	}
	if len(al) == 0 {
		return "✅ Открытых оповещений нет.", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "⚠️ Открытые оповещения: %d\n\n", len(al))
	for i, a := range al {
		if i >= 15 {
			b.WriteString("…\n")
			break
		}
		fmt.Fprintf(&b, "• %s (%s)\n", a.Label, sinceText(now.Sub(a.OpenedAt)))
		if a.Detail != "" {
			b.WriteString("   " + a.Detail + "\n")
		}
	}
	return b.String(), nil
}

// BuildBans says what Fail2ban holds on each server.
func BuildBans(ctx context.Context, st *store.Store, now time.Time) (string, error) {
	sum, err := st.SecuritySummaries(ctx, store.Scope{All: true})
	if err != nil {
		return "", err
	}
	vps, err := st.ListVPS(ctx, store.Scope{All: true})
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("🛡 Fail2ban\n\n")
	any := false
	for _, v := range vps {
		s, ok := sum[v.ID]
		if !ok || s.F2BStatus == "" {
			continue
		}
		any = true
		if s.F2BStatus != "ok" {
			fmt.Fprintf(&b, "• %s — Fail2ban: %s\n", v.Name, s.F2BStatus)
			continue
		}
		fmt.Fprintf(&b, "• %s — в бане сейчас %d, всего %d, клеток (jail) %d\n", v.Name, s.Banned, s.TotalBanned, s.Jails)
	}
	if !any {
		b.WriteString("Данных от агентов пока нет.\n")
	}
	if ev, err := st.SecurityEventCounts(ctx, store.Scope{All: true}, now.Add(-24*time.Hour), now); err == nil {
		for _, e := range ev {
			if e.Type == "fail2ban.ban" {
				fmt.Fprintf(&b, "\nБлокировок за сутки: %d\n", e.Count)
			}
		}
	}
	return b.String(), nil
}

// BuildCerts lists the certificates that are watched, the soonest to expire first.
func BuildCerts(ctx context.Context, st *store.Store, now time.Time) (string, error) {
	sec, err := st.SecurityAlertStates(ctx)
	if err != nil {
		return "", err
	}
	tls := sec.TLS
	if len(tls) == 0 {
		return "🔐 Сертификатов под наблюдением нет.", nil
	}
	sort.Slice(tls, func(i, j int) bool {
		a, b := tls[i].NotAfter, tls[j].NotAfter
		if a == nil || b == nil {
			return a != nil
		}
		return a.Before(*b)
	})
	var b strings.Builder
	b.WriteString("🔐 Сертификаты\n\n")
	for i, c := range tls {
		if i >= 20 {
			b.WriteString("…\n")
			break
		}
		mark := "🟢"
		when := "срок неизвестен"
		if c.NotAfter != nil {
			n := days(*c.NotAfter, now)
			when = daysText(n) + " (" + c.NotAfter.Format("02.01.2006") + ")"
			switch {
			case n < 0:
				mark = "🔴"
			case n <= 14:
				mark = "🟡"
			}
		}
		if c.State != "" && c.State != "ok" && c.NotAfter == nil {
			mark = "🔴"
			when = c.State
		}
		fmt.Fprintf(&b, "%s %s:%d (%s) — %s\n", mark, c.Host, c.Port, c.VPSName, when)
	}
	return b.String(), nil
}

// BuildPay lists the payments and what they cost per month.
func BuildPay(ctx context.Context, st *store.Store, now time.Time) (string, error) {
	bills, err := st.Bills(ctx)
	if err != nil {
		return "", err
	}
	if len(bills) == 0 {
		return "💳 Список оплат пуст. Его можно вести на вкладке «Оплата».", nil
	}
	var b strings.Builder
	b.WriteString("💳 Оплаты\n\n")
	monthly := map[string]float64{}
	for _, x := range bills {
		t, _ := time.Parse("2006-01-02", x.NextDue)
		fmt.Fprintf(&b, "• %s — %s, %s (%s)\n", x.Name, money(x.Amount, x.Currency), daysText(days(t, now)), t.Format("02.01"))
		monthly[x.Currency] += x.Amount / float64(x.PeriodMonths)
	}
	var cs []string
	for c := range monthly {
		cs = append(cs, c)
	}
	sort.Strings(cs)
	var parts []string
	for _, c := range cs {
		parts = append(parts, money(monthly[c], c))
	}
	fmt.Fprintf(&b, "\nВ месяц выходит: %s\n", strings.Join(parts, " + "))
	return b.String(), nil
}

// BuildAWG says how many devices are connected to each AmneziaWG server.
func BuildAWG(ctx context.Context, st *store.Store, now time.Time) (string, error) {
	inst, err := st.AWGInstances(ctx, store.Scope{All: true}, 24*time.Hour)
	if err != nil {
		return "", err
	}
	if len(inst) == 0 {
		return "🔐 Серверов AmneziaWG нет.", nil
	}
	var b strings.Builder
	b.WriteString("🔐 AmneziaWG\n\n")
	for _, i := range inst {
		on, all := 0, 0
		for _, p := range i.Peers {
			if p.Gone {
				continue
			}
			all++
			if p.Handshake != nil && now.Sub(*p.Handshake) < 3*time.Minute {
				on++
			}
		}
		fresh := "🟢"
		if now.Sub(i.LastReport) > 5*time.Minute {
			fresh = "🔴"
		}
		fmt.Fprintf(&b, "%s %s %s — онлайн %d из %d, порт %d\n", fresh, i.AgentName, i.Container, on, all, i.Port)
	}
	return b.String(), nil
}

// BuildDNS shows the state of the watched domains.
func BuildDNS(ctx context.Context, st *store.Store, now time.Time) (string, error) {
	maps, err := st.ListDNSMaps(ctx)
	if err != nil {
		return "", err
	}
	if len(maps) == 0 {
		return "🌐 Доменов под наблюдением нет.", nil
	}
	var b strings.Builder
	b.WriteString("🌐 DNS\n\n")
	for _, m := range maps {
		state := "🟢"
		status := "ок"
		if m.LastStatus != nil {
			status = *m.LastStatus
			if status == "failed" {
				state = "🔴"
			}
		}
		last := "ещё не проверялся"
		if m.LastRunAt != nil {
			last = "проверен " + sinceText(now.Sub(*m.LastRunAt)) + " назад"
		}
		fmt.Fprintf(&b, "%s %s — %s, %s\n", state, m.Domain, status, last)
	}
	return b.String(), nil
}

// BuildUsers lists the subscriptions that end soon or are near their traffic limit.
func BuildUsers(ctx context.Context, st *store.Store, now time.Time) (string, error) {
	subs, err := st.ListSubscriptions(ctx, store.Scope{All: true}, 500)
	if err != nil {
		return "", err
	}
	var lines []string
	for _, s := range subs {
		var notes []string
		if s.ExpireAt != nil && s.Status == "ACTIVE" && days(*s.ExpireAt, now) <= 14 {
			notes = append(notes, "срок: "+daysText(days(*s.ExpireAt, now)))
		}
		if s.LimitBytes != nil && *s.LimitBytes > 0 && s.UsedBytes != nil && s.Status == "ACTIVE" && *s.UsedBytes*100 >= *s.LimitBytes*80 {
			notes = append(notes, fmt.Sprintf("трафик %d%% лимита", *s.UsedBytes*100 / *s.LimitBytes))
		}
		if len(notes) > 0 {
			lines = append(lines, fmt.Sprintf("• %s (%s): %s", s.Username, s.PanelName, strings.Join(notes, ", ")))
		}
	}
	if len(lines) == 0 {
		return "👥 Подписки: срочного нет, всё в порядке.", nil
	}
	if len(lines) > 20 {
		lines = append(lines[:20], fmt.Sprintf("… и ещё %d", len(lines)-20))
	}
	return "👥 Подписки, на которые стоит посмотреть\n\n" + strings.Join(lines, "\n"), nil
}

const helpText = `Owlery: команды

/stats — сводка по всему кластеру
/servers — серверы: процессор, память, диск, сеть
/alerts — открытые оповещения
/bans — Fail2ban: кто в бане
/certs — сертификаты и сроки
/pay — ближайшие оплаты
/awg — AmneziaWG: устройства онлайн
/users — подписки, которые скоро закончатся
/dns — наблюдаемые домены
/mute 2 — не беспокоить (кроме срочного) на 2 часа
/unmute — снова оповещать
/help — эта подсказка`
