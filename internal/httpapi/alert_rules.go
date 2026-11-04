package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/alerts"
	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/store"
)

// ruleRow is one line of a machine's alert rules as the settings page shows it: what it is now and what it would be by default.
type ruleRow struct {
	Rule             string `json:"rule"`
	Kind             string `json:"kind"` // disk | forecast | cpu | mem
	Mount            string `json:"mount,omitempty"`
	Enabled          bool   `json:"enabled"`
	Threshold        int    `json:"threshold"`
	DefaultEnabled   bool   `json:"default_enabled"`
	DefaultThreshold int    `json:"default_threshold"`
	Changed          bool   `json:"changed"`
}

type rulesView struct {
	Rows    []ruleRow `json:"rows"`
	CanEdit bool      `json:"can_edit"`
}

func (s *Server) ruleRowsOf(r *http.Request, a auth.Actor, v store.VPS) (rulesView, error) {
	disks, err := s.Store.HostDisks(r.Context(), v.ID)
	if err != nil {
		return rulesView{}, err
	}
	saved, err := s.Store.GetAlertRules(r.Context(), v.ID)
	if err != nil {
		return rulesView{}, err
	}
	by := map[string]store.AlertRule{}
	for _, x := range saved {
		by[x.Rule] = x
	}
	row := func(rule, kind, mount string, defOn bool, def int) ruleRow {
		x := ruleRow{Rule: rule, Kind: kind, Mount: mount, Enabled: defOn, Threshold: def, DefaultEnabled: defOn, DefaultThreshold: def}
		if sv, ok := by[rule]; ok {
			x.Enabled = sv.Enabled
			if sv.Threshold != nil {
				x.Threshold = *sv.Threshold
			}
			x.Changed = x.Enabled != defOn || x.Threshold != def
		}
		return x
	}
	out := rulesView{Rows: []ruleRow{}, CanEdit: vpsCanEdit(a, v)}
	for _, d := range disks {
		out.Rows = append(out.Rows, row("disk:"+d.Mount, "disk", d.Mount, alerts.WatchedByDefault(d.Mount), alerts.HostDiskPercent))
	}
	if len(disks) > 0 {
		out.Rows = append(out.Rows, row("forecast", "forecast", "", true, alerts.HostDiskForecastDays))
	}
	out.Rows = append(out.Rows, row("cpu", "cpu", "", true, alerts.HostCPUPercent), row("mem", "mem", "", true, alerts.HostMemPercent))
	return out, nil
}

func (s *Server) getAlertRules(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.vpsNotFound(w, r)
		return
	}
	out, err := s.ruleRowsOf(r, a, v)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// putAlertRules saves the rules that differ from the defaults; the page sends only those, and "back to the defaults" is an
// empty list.
func (s *Server) putAlertRules(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.vpsNotFound(w, r)
		return
	}
	if !vpsCanEdit(a, v) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of a linked panel is required")
		return
	}
	var in struct {
		Rules []store.AlertRule `json:"rules"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if err := s.Store.PutAlertRules(r.Context(), v.ID, in.Rules); err != nil {
		if err == store.ErrBadBlockSettings {
			s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_rules", "a rule or its threshold is not valid")
			return
		}
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "alert.rules", "server", v.ID, map[string]any{"name": v.Name, "rules": len(in.Rules)})
	out, err := s.ruleRowsOf(r, a, v)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// snoozeAlert puts one alert off for some hours: it closes now, is not reported while the time lasts, and comes back as a
// new alert if the cause is still there afterwards. Only the owner does this, as alerts of machines are the owner's.
func (s *Server) snoozeAlert(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can put an alert off")
		return
	}
	var in struct {
		Hours int `json:"hours"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if in.Hours < 1 || in.Hours > 720 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_hours", "between 1 hour and 30 days")
		return
	}
	id := r.PathValue("id")
	kind, subject, ok, err := s.Store.AlertByID(r.Context(), id)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if !ok || !strings.HasPrefix(kind, "host_") && !strings.HasPrefix(kind, "sec_") && kind != "awg_down" {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such alert")
		return
	}
	now := time.Now().UTC()
	if err := s.Store.SnoozeAlert(r.Context(), kind, subject, now.Add(time.Duration(in.Hours)*time.Hour)); err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	_, _ = s.Store.ResolveAlert(r.Context(), id, now)
	s.audit(r, a, "", "alert.snooze", "alert", id, map[string]any{"kind": kind, "hours": in.Hours})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "until": now.Add(time.Duration(in.Hours) * time.Hour)})
}
