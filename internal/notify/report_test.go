package notify

import (
	"strings"
	"testing"

	"github.com/Taminum/Owlery/internal/store"
)

func f64(v float64) *float64 { return &v }
func i64(v int64) *int64     { return &v }

func TestMonthlyReportTellsWhatMovedAndSaysSoWhenThereIsNoData(t *testing.T) {
	r := store.MonthReport{
		Cur: store.MonthData{Month: "2026-10", Availability: f64(99.82), Alerts: 47, EventTotal: 1940, TrafficBytes: i64(4 << 40), NewDevices: 3, NetDowns: 2, NetDownMins: 40, NetWorst: "Работа",
			Worst:  []store.ReportMachine{{Name: "exit-2", DownMins: 190}},
			Noisy:  &store.ReportAlert{Label: "Диск на panel-ru", Count: 9},
			Events: []store.EventCount{{Type: "fail2ban.ban", Count: 1940}},
			Paid:   []store.ReportMoney{{Currency: "RUB", Amount: 9480}}},
		Prev:     store.MonthData{Month: "2026-09", Availability: f64(99.72), Alerts: 59, TrafficBytes: i64(4 << 40 * 94 / 100)},
		Upcoming: []store.ReportDue{{Name: "hel", Due: "2026-11-20", Amount: 700, Currency: "RUB"}},
	}
	text := MonthlyReportText(r)
	for _, want := range []string{"ОТЧЁТ ЗА МЕСЯЦ: ОКТЯБРЬ 2026", "Доступность: 99,82% (+0,10 п.п.)", "exit-2, 3 ч 10 мин", "Тревог: 47 (-12 к прошлому)", "Диск на panel-ru, 9 раз",
		"1940 блокировок Fail2ban", "молчали 2 раз, всего 40 мин (дольше всего: Работа)", "Новых устройств: 3", "Трафик VPN: 4,0 ТБ", "9480,00 RUB", "hel, 20 ноября"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	empty := MonthlyReportText(store.MonthReport{Cur: store.MonthData{Month: "2026-11"}})
	for _, want := range []string{"Доступность: данных нет", "Событий в журнале не было", "Роутеры не пропадали", "оплат не было"} {
		if !strings.Contains(empty, want) {
			t.Errorf("an empty month must say %q:\n%s", want, empty)
		}
	}
	if strings.Contains(empty, "Трафик VPN") || strings.Contains(empty, "Самая частая") {
		t.Errorf("parts without data must be left out:\n%s", empty)
	}
}
