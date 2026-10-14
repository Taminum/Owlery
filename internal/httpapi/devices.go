package httpapi

import (
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/store"
)

const sourceRouter = "router_clash_api"

type deviceOut struct {
	Key          string    `json:"key"`
	PanelID      string    `json:"panel_id"`
	PanelName    string    `json:"panel_name"`
	IP           string    `json:"ip"`
	Name         string    `json:"name,omitempty"`
	Connections  int       `json:"connections"`
	Destinations int       `json:"destinations"`
	NoDomainPct  float64   `json:"no_domain_share"`
	UpBytes      int64     `json:"up_bytes"`
	DownBytes    int64     `json:"down_bytes"`
	TotalShare   float64   `json:"share"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

// deviceMeta describes a devices answer. Unlike the node views the numbers here are bytes the
// router counted, and there are no nodes involved, so coverage is about router agents.
func (s *Server) deviceMeta(r *http.Request, sc aScope) (aMeta, bool) {
	m := aMeta{State: "ok", From: sc.from, To: sc.to, Granularity: int(sc.gran.Seconds()), PanelIDs: sc.ids, MetricKind: "bytes", Source: sourceRouter}
	if m.PanelIDs == nil {
		m.PanelIDs = []string{}
	}
	if len(sc.ids) == 0 {
		m.State, m.Reason = "no_data", "no_real_panels"
		return m, true
	}
	has, err := s.Store.HasRouterAgent(r.Context(), sc.ids)
	if err != nil {
		return m, false
	}
	if !has {
		m.State, m.Reason = "no_data", "no_router"
	}
	return m, true
}

func (s *Server) analyticsDevices(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	sc, ok := s.resolveScope(w, r, a)
	if !ok {
		return
	}
	meta, ok := s.deviceMeta(r, sc)
	if !ok {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	out := struct {
		Meta  aMeta       `json:"meta"`
		Rows  []deviceOut `json:"rows"`
		Total int64       `json:"total_bytes"`
	}{Meta: meta, Rows: []deviceOut{}}
	if meta.State == "ok" {
		rows, err := s.Store.DevicesAnalytics(r.Context(), sc.query())
		if err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		for _, d := range rows {
			out.Total += d.Up + d.Down
		}
		for _, d := range rows {
			b := d.Up + d.Down
			sh := 0.0
			if out.Total > 0 {
				sh = float64(b) * 100 / float64(out.Total)
			}
			out.Rows = append(out.Rows, deviceOut{Key: d.PanelID + "|" + d.IP.String(), PanelID: d.PanelID, PanelName: sc.names[d.PanelID],
				IP: d.IP.String(), Name: d.Name, Connections: d.Connections, Destinations: d.Destinations,
				NoDomainPct: share(d.NoDomain, d.Connections), UpBytes: d.Up, DownBytes: d.Down, TotalShare: sh,
				FirstSeen: d.First.UTC(), LastSeen: d.Last.UTC()})
		}
		if len(rows) == 0 {
			out.Meta.State, out.Meta.Reason = "no_data", "no_events"
		}
	}
	writeJSON(w, http.StatusOK, out)
}

type deviceHostOut struct {
	Key         string  `json:"key"`
	Service     string  `json:"service,omitempty"`
	Connections int     `json:"connections"`
	UpBytes     int64   `json:"up_bytes"`
	DownBytes   int64   `json:"down_bytes"`
	Share       float64 `json:"share"`
}

type devicePointOut struct {
	TS          int64 `json:"ts"`
	Connections int   `json:"connections"`
	UpBytes     int64 `json:"up_bytes"`
	DownBytes   int64 `json:"down_bytes"`
}

func (s *Server) analyticsDeviceDetail(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	sc, ok := s.resolveScope(w, r, a)
	if !ok {
		return
	}
	pid, ipStr, found := strings.Cut(r.URL.Query().Get("key"), "|")
	ip, err := netip.ParseAddr(ipStr)
	// A key for a panel outside the caller's scope looks exactly like one that does not exist.
	if !found || err != nil || !contains(sc.ids, pid) {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "device not found")
		return
	}
	meta, ok := s.deviceMeta(r, sc)
	if !ok {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	d, err := s.Store.DeviceDetailFor(r.Context(), sc.query(), pid, ip)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	out := struct {
		Meta      aMeta            `json:"meta"`
		Key       string           `json:"key"`
		PanelID   string           `json:"panel_id"`
		PanelName string           `json:"panel_name"`
		IP        string           `json:"ip"`
		Name      string           `json:"name,omitempty"`
		Total     int              `json:"connections"`
		UpBytes   int64            `json:"up_bytes"`
		DownBytes int64            `json:"down_bytes"`
		Hosts     []deviceHostOut  `json:"hosts"`
		Timeline  []devicePointOut `json:"timeline"`
	}{Meta: meta, Key: pid + "|" + ip.String(), PanelID: pid, PanelName: sc.names[pid], IP: ip.String(), Name: d.Name, Total: d.Connections,
		UpBytes: d.Up, DownBytes: d.Down, Hosts: []deviceHostOut{}, Timeline: []devicePointOut{}}
	all := d.Up + d.Down
	for _, h := range d.Hosts {
		sh := 0.0
		if all > 0 {
			sh = float64(h.Up+h.Down) * 100 / float64(all)
		}
		out.Hosts = append(out.Hosts, deviceHostOut{Key: h.Key, Service: h.Service, Connections: h.Connections, UpBytes: h.Up, DownBytes: h.Down, Share: sh})
	}
	for _, p := range d.Timeline {
		out.Timeline = append(out.Timeline, devicePointOut{TS: p.TS.Unix(), Connections: p.Connections, UpBytes: p.Up, DownBytes: p.Down})
	}
	if d.Connections == 0 {
		out.Meta.State, out.Meta.Reason = "no_data", "no_events"
	}
	writeJSON(w, http.StatusOK, out)
}
