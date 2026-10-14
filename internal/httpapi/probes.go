package httpapi

import (
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/safehttp"
	"github.com/Taminum/RemnaScope/internal/store"
)

var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

type probePointOut struct {
	TS      int64 `json:"ts"`
	Ms      *int  `json:"ms"`
	Samples int   `json:"samples"`
	Failed  int   `json:"failed"`
}

type probeOut struct {
	store.ProbeTarget
	PanelName  string          `json:"panel_name"`
	State      string          `json:"state"` // up | down | unknown
	LastAt     *time.Time      `json:"last_at"`
	LastError  string          `json:"last_error,omitempty"`
	ConnectMS  *int            `json:"connect_ms"`
	TLSMS      *int            `json:"tls_ms"`
	Samples1h  int             `json:"samples_1h"`
	LossPct    float64         `json:"loss_pct"`
	P50Connect *int            `json:"p50_connect_ms"`
	P50TLS     *int            `json:"p50_tls_ms"`
	Series     []probePointOut `json:"series"`
}

// listProbes returns the targets of the visible panels with their latest result, the last hour's
// loss and median times, and 24 hours of ten-minute points for the chart.
func (s *Server) listProbes(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	req := splitCSV(r.URL.Query().Get("panel_ids"))
	for _, id := range req {
		if !a.Scope().Allows(id) {
			s.writeErr(w, r, http.StatusForbidden, "panel_forbidden", "panel is not available")
			return
		}
	}
	visible, err := s.Store.ListPanels(r.Context(), a.Scope())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	var ids []string
	names := map[string]string{}
	for _, p := range visible {
		if p.Demo || (len(req) > 0 && !contains(req, p.ID)) {
			continue
		}
		ids = append(ids, p.ID)
		names[p.ID] = p.Name
	}
	out := struct {
		Targets []probeOut `json:"targets"`
		CanEdit bool       `json:"can_edit"`
		Max     int        `json:"max_per_panel"`
	}{Targets: []probeOut{}, Max: store.MaxProbeTargets}
	for _, id := range ids {
		if a.Can(id, auth.PermAdmin) {
			out.CanEdit = true
		}
	}
	if len(ids) > 0 {
		targets, err := s.Store.ProbeTargetsOf(r.Context(), ids)
		if err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		now := s.Now().UTC()
		tids := make([]string, len(targets))
		for i, t := range targets {
			tids[i] = t.ID
		}
		sums, err := s.Store.ProbeSummaries(r.Context(), tids, now)
		if err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		for _, t := range targets {
			o := probeOut{ProbeTarget: t, PanelName: names[t.PanelID], State: "unknown", Series: []probePointOut{}}
			sm := sums[t.ID]
			o.Samples1h, o.P50Connect, o.P50TLS = sm.Samples1h, sm.P50Connect, sm.P50TLS
			if sm.Samples1h > 0 {
				o.LossPct = float64(sm.Failed1h) * 100 / float64(sm.Samples1h)
			}
			if sm.Last != nil {
				ts := sm.Last.TS.UTC()
				o.LastAt, o.ConnectMS, o.TLSMS, o.LastError = &ts, sm.Last.ConnectMS, sm.Last.TLSMS, sm.Last.Error
				o.State = "down"
				if sm.Last.OK {
					o.State = "up"
				}
				// A result older than a few minutes says nothing about now.
				if now.Sub(ts) > 5*time.Minute {
					o.State = "unknown"
				}
			}
			pts, err := s.Store.ProbeSeries(r.Context(), t.ID, now.Add(-24*time.Hour), now.Add(time.Minute), 10*time.Minute)
			if err != nil {
				s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
				return
			}
			for _, p := range pts {
				o.Series = append(o.Series, probePointOut{TS: p.TS.Unix(), Ms: p.Ms, Samples: p.Samples, Failed: p.Failed})
			}
			out.Targets = append(out.Targets, o)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// createProbe adds a target to a panel. The server will dial it every minute, so it must be a public
// address, and each panel is limited to a few targets.
func (s *Server) createProbe(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	var in struct {
		PanelID string `json:"panel_id"`
		Name    string `json:"name"`
		Host    string `json:"host"`
		Port    int    `json:"port"`
		Mode    string `json:"mode"`
		SNI     string `json:"sni"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if !a.Scope().Allows(in.PanelID) {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "panel not found")
		return
	}
	if !a.Can(in.PanelID, auth.PermAdmin) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of the panel is required")
		return
	}
	p, err := s.Store.GetPanel(r.Context(), a.Scope(), in.PanelID)
	if err != nil || p.Demo {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "panel not found")
		return
	}
	name, nameOK := validName(in.Name)
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Host), "."))
	sni := strings.ToLower(strings.TrimSpace(in.SNI))
	fail := func(code, msg string) { s.writeErr(w, r, http.StatusUnprocessableEntity, code, msg) }
	switch {
	case !nameOK:
		fail("invalid_name", "name must be 1 to 64 characters without control characters")
		return
	case in.Mode != "tcp" && in.Mode != "tls":
		fail("invalid_mode", "mode must be tcp or tls")
		return
	case in.Port < 1 || in.Port > 65535:
		fail("invalid_port", "port must be 1 to 65535")
		return
	case sni != "" && (len(sni) > 253 || !hostRe.MatchString(sni)):
		fail("invalid_sni", "SNI must be a host name")
		return
	}
	if ip, perr := netip.ParseAddr(host); perr == nil {
		if !safehttp.PublicAddr(ip) {
			fail("invalid_host", "only public addresses can be probed")
			return
		}
	} else if len(host) > 253 || !hostRe.MatchString(host) {
		fail("invalid_host", "host must be a domain name or a public IP address")
		return
	}
	t, err := s.Store.CreateProbeTarget(r.Context(), store.ProbeTarget{PanelID: in.PanelID, Name: name, Host: host, Port: in.Port, Mode: in.Mode, SNI: sni})
	switch {
	case errors.Is(err, store.ErrConflict):
		s.writeErr(w, r, http.StatusConflict, "name_taken", "this panel already has a channel with that name")
		return
	case errors.Is(err, store.ErrLimit):
		s.writeErr(w, r, http.StatusConflict, "limit", "this panel already has the most channels it can have")
		return
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, in.PanelID, "probe.create", "probe", t.ID, map[string]any{"name": name, "host": host, "port": in.Port, "mode": in.Mode})
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) deleteProbe(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	t, err := s.Store.ProbeTarget(r.Context(), r.PathValue("id"))
	if err != nil || !a.Scope().Allows(t.PanelID) {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "channel not found")
		return
	}
	if !a.Can(t.PanelID, auth.PermAdmin) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of the panel is required")
		return
	}
	if err := s.Store.DeleteProbeTarget(r.Context(), t.ID); err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "channel not found")
		return
	}
	s.audit(r, a, t.PanelID, "probe.delete", "probe", t.ID, map[string]any{"name": t.Name})
	w.WriteHeader(http.StatusNoContent)
}
