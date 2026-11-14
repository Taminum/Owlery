package httpapi

import (
	"net/http"
	"time"

	"github.com/Taminum/Owlery/internal/alerts"
	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/store"
)

type pveGuestOut struct {
	secproto.PVEGuest
	DaysToFull *float64 `json:"days_to_full,omitempty"`
}

type pveHostOut struct {
	VPSID     string                `json:"vps_id"`
	Name      string                `json:"name"`
	Node      string                `json:"node"`
	Version   string                `json:"version,omitempty"`
	UpdatedAt time.Time             `json:"updated_at"`
	Fresh     bool                  `json:"fresh"` // read within the last minutes; a stale host's numbers are old
	Online    bool                  `json:"online"`
	CPUs      int                   `json:"cpus,omitempty"`
	CPUPct    float64               `json:"cpu"`
	MemUsed   int64                 `json:"mem"`
	MemTotal  int64                 `json:"mem_max"`
	DiskUsed  int64                 `json:"disk"`
	DiskTotal int64                 `json:"disk_max"`
	Uptime    int64                 `json:"up"`
	Tailnet   string                `json:"ts,omitempty"`
	BackupOK  *bool                 `json:"backup_ok,omitempty"`
	BackupAt  int64                 `json:"backup_at,omitempty"`
	LXC       int                   `json:"lxc"`
	VMs       int                   `json:"vms"`
	Running   int                   `json:"running"`
	Guests    []pveGuestOut         `json:"guests"`
	Storages  []secproto.PVEStorage `json:"storages"`
}

// proxmoxHome says how the Proxmox hosts at home are doing. It is the owner's, and empty while the module is off.
func (s *Server) proxmoxHome(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	on, err := s.Store.ModuleOn(r.Context(), "proxmox")
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if !on {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "hosts": []pveHostOut{}})
		return
	}
	hosts, err := s.Store.PVEHosts(r.Context())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	now := s.Now().UTC()
	out := make([]pveHostOut, 0, len(hosts))
	for _, h := range hosts {
		d := h.Data
		o := pveHostOut{VPSID: h.VPSID, Name: h.VPSName, Node: d.Node, Version: d.Version, UpdatedAt: h.UpdatedAt.UTC(), Fresh: now.Sub(h.UpdatedAt) <= alerts.PVEFresh,
			Online: d.Online, CPUs: d.CPUs, CPUPct: d.CPUPct, MemUsed: d.MemUsed, MemTotal: d.MemTotal, DiskUsed: d.DiskUsed, DiskTotal: d.DiskTotal,
			Uptime: d.Uptime, Tailnet: d.Tailnet, BackupOK: d.LastBackupOK, BackupAt: d.LastBackupAt, Guests: []pveGuestOut{}, Storages: d.Storages}
		if o.Storages == nil {
			o.Storages = []secproto.PVEStorage{}
		}
		for _, g := range d.Guests {
			if g.Template {
				continue
			}
			go2 := pveGuestOut{PVEGuest: g}
			if g.Kind == "lxc" {
				o.LXC++
			} else {
				o.VMs++
			}
			if g.Status == "running" {
				o.Running++
				if g.DiskMax > 0 {
					if pts, e := s.Store.PVEDiskSeries(r.Context(), h.VPSID, g.ID, now.Add(-14*24*time.Hour)); e == nil {
						if days, ok := store.PVEDaysToFull(pts); ok {
							go2.DaysToFull = &days
						}
					}
				}
			}
			o.Guests = append(o.Guests, go2)
		}
		out = append(out, o)
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "hosts": out})
}
