package alerts

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

const (
	// PVEFresh is how old the last reading may be before the host is left out: a silent agent has its own alert.
	PVEFresh = 5 * time.Minute
	// PVEDownLookback is how far back a guest must have been seen running for its stopping to count as a fault.
	PVEDownLookback = 7 * 24 * time.Hour
	PVEDiskPercent  = 90
	// PVEForecastDays and PVEForecastPercent: a disk that is already this full and will fill in that many days is told early.
	PVEForecastDays    = 14
	PVEForecastPercent = 60
	PVEStoragePercent  = 85
	PVEBackupStale     = 48 * time.Hour
)

// PVEFromStore reads the Proxmox hosts and what the conditions need to know beyond the last reading. With the module
// off it returns nothing, so every open Proxmox alert closes.
func PVEFromStore(ctx context.Context, st *store.Store, now time.Time) ([]store.Condition, error) {
	on, err := st.ModuleOn(ctx, "proxmox")
	if err != nil || !on {
		return nil, err
	}
	hosts, err := st.PVEHosts(ctx)
	if err != nil {
		return nil, err
	}
	was := func(vps string, id int) bool {
		ok, e := st.PVEWasRunning(ctx, vps, id, now.Add(-PVEDownLookback))
		return e == nil && ok
	}
	days := func(vps string, id int) (float64, bool) {
		pts, e := st.PVEDiskSeries(ctx, vps, id, now.Add(-14*24*time.Hour))
		if e != nil {
			return 0, false
		}
		return store.PVEDaysToFull(pts)
	}
	return PVEConditions(hosts, was, days, now), nil
}

func gbs(b int64) string { return fmt.Sprintf("%.1f ГБ", float64(b)/(1<<30)) }

// PVEConditions lists what is wrong at the Proxmox hosts. A host that has not been heard from lately is skipped.
func PVEConditions(hosts []store.PVEHost, wasRunning func(vps string, id int) bool, daysToFull func(vps string, id int) (float64, bool), now time.Time) []store.Condition {
	var out []store.Condition
	for _, h := range hosts {
		if now.Sub(h.UpdatedAt) > PVEFresh {
			continue
		}
		d := h.Data
		where := d.Node
		if where == "" {
			where = h.VPSName
		}
		if d.LastBackupOK != nil && !*d.LastBackupOK {
			out = append(out, store.Condition{Kind: store.AlertPVEBackup, Subject: h.VPSID + ":job", Label: "Бэкап Proxmox не прошёл: " + where,
				Detail: "последнее задание резервного копирования закончилось с ошибкой"})
		}
		for _, s := range d.Storages {
			if !s.Active || s.Total <= 0 || s.Used*100 < s.Total*PVEStoragePercent {
				continue
			}
			out = append(out, store.Condition{Kind: store.AlertPVEDisk, Subject: h.VPSID + ":s:" + s.Name, Label: "Хранилище почти полно: " + s.Name + " (" + where + ")",
				Detail: fmt.Sprintf("занято %d%%: %s из %s", s.Used*100/s.Total, gbs(s.Used), gbs(s.Total))})
		}
		for _, g := range d.Guests {
			if g.Template {
				continue
			}
			id := strconv.Itoa(g.ID)
			who := fmt.Sprintf("%s (%d)", g.Name, g.ID)
			if g.Status != "running" {
				if wasRunning(h.VPSID, g.ID) {
					out = append(out, store.Condition{Kind: store.AlertPVEGuest, Subject: h.VPSID + ":g:" + id, Label: "Гость остановился: " + who,
						Detail: where + ": сейчас не работает, а на этой неделе работал"})
				}
				continue
			}
			if g.DiskMax > 0 {
				pct := int(g.DiskUsed * 100 / g.DiskMax)
				days, soon := daysToFull(h.VPSID, g.ID)
				soon = soon && days <= PVEForecastDays && pct >= PVEForecastPercent
				if pct >= PVEDiskPercent || soon {
					detail := fmt.Sprintf("занято %d%%: %s из %s", pct, gbs(g.DiskUsed), gbs(g.DiskMax))
					if soon {
						detail += fmt.Sprintf("; при таком росте кончится через %.0f дн.", days)
					}
					out = append(out, store.Condition{Kind: store.AlertPVEDisk, Subject: h.VPSID + ":g:" + id, Label: "Диск гостя почти полон: " + who, Detail: detail})
				}
			}
			if g.Backup > 0 {
				if age := now.Sub(time.Unix(g.Backup, 0)); age > PVEBackupStale {
					out = append(out, store.Condition{Kind: store.AlertPVEBackup, Subject: h.VPSID + ":b:" + id, Label: "Бэкап устарел: " + who,
						Detail: fmt.Sprintf("последний был %d дн. назад", int(age.Hours()/24))})
				}
			}
			if g.TSOnline != nil && !*g.TSOnline {
				out = append(out, store.Condition{Kind: store.AlertPVETailscale, Subject: h.VPSID + ":t:" + id, Label: "Гость выпал из Tailscale: " + who,
					Detail: "дома он работает, но снаружи по Tailscale недоступен"})
			}
		}
	}
	return out
}
