package alerts

import (
	"fmt"

	"github.com/Taminum/RemnaScope/internal/store"
)

const (
	// HostDiskPercent is how full a file system may be before it is reported.
	HostDiskPercent = 90
	// HostCPUPercent is the mean processor use over ten minutes, HostMemPercent the mean memory use over five.
	HostCPUPercent = 90
	HostMemPercent = 95
)

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
			if d.Total <= 0 || d.Used*100 < d.Total*HostDiskPercent {
				continue
			}
			pct := int(d.Used * 100 / d.Total)
			out = append(out, store.Condition{Kind: store.AlertHostDisk, Subject: h.VPSID + ":" + d.Mount, Label: "Диск почти полон: " + h.Name + " " + d.Mount,
				Detail: fmt.Sprintf("занято %d%%: %s из %s", pct, gb(d.Used), gb(d.Total))})
		}
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
