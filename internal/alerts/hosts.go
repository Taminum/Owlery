package alerts

import (
	"fmt"
	"strings"

	"github.com/Taminum/Owlery/internal/store"
)

const (
	// HostDiskPercent is how full a file system may be before it is reported.
	HostDiskPercent = 90
	// HostCPUPercent is the mean processor use over ten minutes, HostMemPercent the mean memory use over five.
	HostCPUPercent = 90
	HostMemPercent = 95
)

// watchedDisk says whether a full disk is worth an alert. On Windows only the system drive is: the other drives of
// a workstation are usually archives kept full on purpose. Per-machine and per-disk settings come later.
func watchedDisk(mount string) bool {
	if len(mount) == 2 && mount[1] == ':' {
		return strings.EqualFold(mount, "C:")
	}
	return true
}

func gb(b int64) string { return fmt.Sprintf("%.1f ГБ", float64(b)/(1<<30)) }

// HostConditions lists the monitored servers that are running out of disk, processor or memory. A server that
// has stopped reporting is the security agent's alert, not this one.
func HostConditions(states []store.HostAlertState) []store.Condition {
	var out []store.Condition
	for _, h := range states {
		if !h.Online {
			continue
		}
		for _, d := range h.Disks {
			if d.Total <= 0 || d.Used*100 < d.Total*HostDiskPercent || !watchedDisk(d.Mount) {
				continue
			}
			pct := int(d.Used * 100 / d.Total)
			out = append(out, store.Condition{Kind: store.AlertHostDisk, Subject: h.VPSID + ":" + d.Mount, Label: "Диск почти полон: " + h.Name + " " + d.Mount,
				Detail: fmt.Sprintf("занято %d%%: %s из %s", pct, gb(d.Used), gb(d.Total))})
		}
		out = append(out, diskForecast(h)...)
		if h.CPUAvg != nil && *h.CPUAvg >= HostCPUPercent {
			out = append(out, store.Condition{Kind: store.AlertHostCPU, Subject: h.VPSID, Label: "Процессор загружен: " + h.Name,
				Detail: fmt.Sprintf("в среднем %.0f%% за последние десять минут", *h.CPUAvg)})
		}
		if h.MemAvg != nil && *h.MemAvg >= HostMemPercent {
			out = append(out, store.Condition{Kind: store.AlertHostMem, Subject: h.VPSID, Label: "Память почти кончилась: " + h.Name,
				Detail: fmt.Sprintf("занято в среднем %.0f%% за последние пять минут", *h.MemAvg)})
		}
	}
	return out
}

// daysText says a number of days the way a person would.
func daysText(days float64) string {
	switch {
	case days < 1:
		return "меньше суток"
	case days < 1.5:
		return "около суток"
	}
	n := int(days + 0.5)
	if n%10 == 1 && n%100 != 11 {
		return fmt.Sprintf("%d день", n)
	}
	if n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14) {
		return fmt.Sprintf("%d дня", n)
	}
	return fmt.Sprintf("%d дней", n)
}

// diskForecast reports a main disk that is not nearly full yet but fills steadily and will be within HostDiskForecastDays.
// Once it is nearly full the "almost full" alert says it.
func diskForecast(h store.HostAlertState) []store.Condition {
	if h.MainMount == "" || !watchedDisk(h.MainMount) {
		return nil
	}
	for _, d := range h.Disks {
		if d.Mount == h.MainMount && d.Total > 0 && d.Used*100 >= d.Total*HostDiskPercent {
			return nil
		}
	}
	days, perDay, ok := DiskDaysLeft(h.DiskTrend, h.DiskTotal)
	if !ok || days >= HostDiskForecastDays {
		return nil
	}
	var free int64
	if n := len(h.DiskTrend); n > 0 {
		free = h.DiskTotal - h.DiskTrend[n-1].Used
	}
	return []store.Condition{{Kind: store.AlertHostDiskForecast, Subject: h.VPSID + ":" + h.MainMount,
		Label:  "Диск кончится через " + daysText(days) + ": " + h.Name + " " + h.MainMount,
		Detail: fmt.Sprintf("растёт на %s в сутки, свободно %s", gb(int64(perDay)), gb(free))}}
}
