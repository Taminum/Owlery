package httpapi

import (
	"net/http"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/store"
)

// maxNewDeviceWindow keeps "new device" honest: device history is kept for a limited time, and a window longer
// than that would call every old device new.
const maxNewDeviceWindow = 14 * 24 * time.Hour

type digestSite struct {
	Site        string    `json:"site"`
	Service     string    `json:"service,omitempty"`
	Category    string    `json:"category,omitempty"`
	Connections int       `json:"connections"`
	Users       int       `json:"users"`
	FirstSeen   time.Time `json:"first_seen"`
}

type digestDevice struct {
	PanelID   string `json:"panel_id"`
	PanelName string `json:"panel_name"`
	IP        string `json:"ip"`
	Name      string `json:"name"`
	UpBytes   int64  `json:"up_bytes"`
	DownBytes int64  `json:"down_bytes"`
	// FirstSeen is set only for a device that was not seen before the window.
	FirstSeen *time.Time `json:"first_seen,omitempty"`
}

type digestOut struct {
	From     time.Time             `json:"from"`
	To       time.Time             `json:"to"`
	Sites    []digestSite          `json:"new_sites"`
	Devices  []digestDevice        `json:"top_devices"`
	New      []digestDevice        `json:"new_devices"`
	NewNote  string                `json:"new_devices_note,omitempty"`
	Events   []store.EventCount    `json:"security_events"`
	DNS      *store.DNSChangeCount `json:"dns"`
	Open     int                   `json:"open_alerts"`
	Traffic  bool                  `json:"has_traffic"`
	Security bool                  `json:"has_security"`
}

// analyticsDigest answers "what changed in this period" in one place: new sites, the busiest and new devices
// at home, what the journal recorded on the servers, DNS changes and what is open now. A part with nothing to
// show is empty, not hidden, so that "nothing happened" can be read as such.
func (s *Server) analyticsDigest(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	sc, ok := s.resolveScope(w, r, a)
	if !ok {
		return
	}
	ctx := r.Context()
	fail := func() { s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error") }
	out := digestOut{From: sc.from.UTC(), To: sc.to.UTC(), Sites: []digestSite{}, Devices: []digestDevice{}, New: []digestDevice{}, Events: []store.EventCount{}}

	if len(sc.ids) > 0 {
		out.Traffic = true
		q := sc.query()
		q.NewOnly, q.Limit = true, 10
		rows, _, _, err := s.Store.Sites(ctx, q)
		if err != nil {
			fail()
			return
		}
		for _, x := range rows {
			out.Sites = append(out.Sites, digestSite{Site: x.Site, Service: x.Service, Category: catLabel(x.Category), Connections: x.Connections, Users: x.Users, FirstSeen: x.First.UTC()})
		}
		devs, err := s.Store.DevicesAnalytics(ctx, sc.query())
		if err != nil {
			fail()
			return
		}
		for i, d := range devs {
			if i >= 5 {
				break
			}
			out.Devices = append(out.Devices, digestDevice{PanelID: d.PanelID, PanelName: sc.names[d.PanelID], IP: d.IP.String(), Name: d.Name, UpBytes: d.Up, DownBytes: d.Down})
		}
		if sc.to.Sub(sc.from) <= maxNewDeviceWindow {
			nd, err := s.Store.NewDevices(ctx, sc.ids, sc.from, sc.to)
			if err != nil {
				fail()
				return
			}
			for _, d := range nd {
				f := d.First.UTC()
				out.New = append(out.New, digestDevice{PanelID: d.PanelID, PanelName: sc.names[d.PanelID], IP: d.IP, Name: d.Name, DownBytes: d.Bytes, FirstSeen: &f})
			}
		} else {
			out.NewNote = "window_too_long"
		}
	}

	ev, err := s.Store.SecurityEventCounts(ctx, a.Scope(), sc.from, sc.to)
	if err != nil {
		fail()
		return
	}
	out.Events, out.Security = ev, true

	// DNS Map belongs to the owner, like the rest of network intelligence.
	if a.IsOwner {
		c, err := s.Store.DNSChangeCounts(ctx, sc.from, sc.to)
		if err != nil {
			fail()
			return
		}
		out.DNS = &c
	}

	// Alerts with no panel (DNS, servers linked to none) are the owner's, as on the alerts page.
	al, err := s.Store.ListAlerts(ctx, sc.ids, a.IsOwner && r.URL.Query().Get("panel_ids") == "", true, 200)
	if err != nil {
		fail()
		return
	}
	out.Open = len(al)
	writeJSON(w, http.StatusOK, out)
}
