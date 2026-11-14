package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/Taminum/Owlery/internal/alerts"
	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/store"
)

type torrentOut struct {
	PanelID   string    `json:"panel_id"`
	PanelName string    `json:"panel_name"`
	User      string    `json:"user"`
	Label     string    `json:"label"`
	Note      string    `json:"note,omitempty"`
	Reports   int       `json:"reports"`
	Recent    int       `json:"recent"`
	Nodes     []string  `json:"nodes"`
	Last      time.Time `json:"last"`
	Repeat    bool      `json:"repeat"` // caught again and again: the alert's threshold within a day
}

func (s *Server) panelNames(w http.ResponseWriter, r *http.Request, a auth.Actor) (map[string]string, bool) {
	panels, err := s.Store.ListPanels(r.Context(), a.Scope())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return nil, false
	}
	names := map[string]string{}
	for _, p := range panels {
		names[p.ID] = p.Name
	}
	return names, true
}

// subscriptionTorrents lists the subscriptions the torrent blocker of the panels caught lately. It only reads what the
// panels reported; "seen" is false while the panels have never reported any, which is how a page tells "the plugin is
// off or nothing happened" from a list that happens to be empty for the period.
func (s *Server) subscriptionTorrents(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	days, from, to, ok := subWindow(w, r, s)
	if !ok {
		return
	}
	scope := a.Scope()
	list, err := s.Store.Torrents(r.Context(), scope, from, to, 1, 200)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	seenTorrents, _, err := s.Store.ProtectionSeen(r.Context(), scope)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	names, ok := s.panelNames(w, r, a)
	if !ok {
		return
	}
	rows, reports, nodes := []torrentOut{}, 0, map[string]bool{}
	for _, t := range list {
		o := torrentOut{PanelID: t.PanelID, PanelName: names[t.PanelID], User: t.RemoteUser, Reports: t.Reports, Recent: t.Recent, Nodes: t.Nodes,
			Last: t.Last.UTC(), Repeat: t.Recent >= alerts.TorrentReports}
		if o.Nodes == nil {
			o.Nodes = []string{}
		}
		o.Label, o.Note = s.label(a, t.PanelID, t.Name, t.RemoteUser, false)
		reports += t.Reports
		for _, n := range t.Nodes {
			nodes[t.PanelID+"\x00"+n] = true
		}
		rows = append(rows, o)
	}
	writeJSON(w, http.StatusOK, map[string]any{"days": days, "seen": seenTorrents > 0, "reports": reports, "subs": len(rows), "nodes": len(nodes),
		"alert_reports": alerts.TorrentReports, "rows": rows})
}

type subDeviceOut struct {
	PanelID   string `json:"panel_id"`
	PanelName string `json:"panel_name"`
	User      string `json:"user"`
	Label     string `json:"label"`
	Note      string `json:"note,omitempty"`
	Devices   int    `json:"devices"`
	IPs       int    `json:"ips"`
	Level     string `json:"level"` // leak: many devices and many addresses together | check: many devices
}

// subscriptionDevices lists the subscriptions with many devices registered, together with the addresses they were asked
// for from. Many devices alone is often a family; many devices and many addresses is a subscription passed on.
func (s *Server) subscriptionDevices(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	days, from, to, ok := subWindow(w, r, s)
	if !ok {
		return
	}
	min := 5
	if v := r.URL.Query().Get("min"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 2 || n > 50 {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_threshold", "min must be 2 to 50")
			return
		}
		min = n
	}
	scope := a.Scope()
	list, err := s.Store.DeviceCounts(r.Context(), scope, from, to, min, 200)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	_, seenDevices, err := s.Store.ProtectionSeen(r.Context(), scope)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	names, ok := s.panelNames(w, r, a)
	if !ok {
		return
	}
	rows, flagged := []subDeviceOut{}, 0
	for _, d := range list {
		o := subDeviceOut{PanelID: d.PanelID, PanelName: names[d.PanelID], User: d.RemoteUser, Devices: d.Devices, IPs: d.IPs, Level: "check"}
		o.Label, o.Note = s.label(a, d.PanelID, d.Name, d.RemoteUser, false)
		if d.IPs >= min {
			o.Level = "leak"
			flagged++
		}
		rows = append(rows, o)
	}
	writeJSON(w, http.StatusOK, map[string]any{"days": days, "min": min, "seen": seenDevices > 0, "subs": len(rows), "leaks": flagged, "rows": rows})
}
