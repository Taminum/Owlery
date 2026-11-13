package httpapi

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/notify"
	"github.com/Taminum/Owlery/internal/store"
)

var monthRe = regexp.MustCompile(`^20[0-9]{2}-(0[1-9]|1[0-2])$`)

// reportMonth reads ?month=YYYY-MM (the month under way when it is missing) and says where that month starts.
func (s *Server) reportMonth(w http.ResponseWriter, r *http.Request, loc *time.Location) (time.Time, bool) {
	m := r.URL.Query().Get("month")
	if m == "" {
		return store.MonthStart(s.Now(), loc), true
	}
	if !monthRe.MatchString(m) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_month", "the month is YYYY-MM")
		return time.Time{}, false
	}
	t, err := time.ParseInLocation("2006-01", m, loc)
	if err != nil || t.After(s.Now()) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_month", "that month has not come yet")
		return time.Time{}, false
	}
	return t, true
}

// monthReport is the report of one month beside the month before it. For the owner: it covers every panel and machine.
func (s *Server) monthReport(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	loc := time.UTC
	month, ok := s.reportMonth(w, r, loc)
	if !ok {
		return
	}
	rep, err := s.Store.BuildMonthReport(r.Context(), month, s.Now(), loc)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, rep)
}

// sendMonthReport sends the report of a month to every channel that is on.
func (s *Server) sendMonthReport(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	month, ok := s.reportMonth(w, r, time.UTC)
	if !ok {
		return
	}
	cs, err := s.Store.ListNotifyChannels(r.Context())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	rep, err := s.Store.BuildMonthReport(r.Context(), month, s.Now(), time.UTC)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	text := notify.MonthlyReportText(rep)
	wk := &notify.Worker{Store: s.Store, Ring: s.Ring, Log: s.Log}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	sent, failed := 0, 0
	for _, c := range cs {
		if !c.Enabled {
			continue
		}
		if wk.SendTo(ctx, c, text) != nil {
			failed++
		} else {
			sent++
		}
	}
	if sent == 0 && failed == 0 {
		s.writeErr(w, r, http.StatusConflict, "no_channels", "no notification channel is on")
		return
	}
	s.audit(r, a, "", "report.send", "report", month.Format("2006-01"), map[string]any{"sent": sent, "failed": failed})
	writeJSON(w, http.StatusOK, map[string]any{"sent": sent, "failed": failed})
}
