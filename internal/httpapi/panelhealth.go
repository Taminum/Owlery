package httpapi

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/store"
)

// SlowRequest is how long an answer may take before it counts as slow.
const SlowRequest = 2 * time.Second

// healthStats counts the API's requests by hour, in memory: the page of the panel's health shows the last day since the
// server started (a restart starts the count again, and the page says since when). Only /api/ requests that ended on
// their own count: a terminal or a stream that is open for hours is not a slow answer, and a cancelled one was the
// browser's doing.
type healthStats struct {
	mu      sync.Mutex
	since   time.Time
	hours   [24]hourBucket
	worst   []worstRequest
	started bool
}

type hourBucket struct {
	hour   int64 // unix hour
	total  int
	failed int // 5xx
	slow   int
}

type worstRequest struct {
	At     time.Time `json:"at"`
	Method string    `json:"method"`
	Path   string    `json:"path"`
	Status int       `json:"status"`
	Ms     int64     `json:"ms"`
}

var idSegment = regexp.MustCompile(`^([0-9a-fA-F-]{32,36}|[0-9]+)$`)

// shapeOf replaces the ids in a path, so the same request made for different things reads as one.
func shapeOf(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if idSegment.MatchString(p) {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

func (h *healthStats) note(now time.Time, method, path string, status int, d time.Duration) {
	if !strings.HasPrefix(path, "/api/") || status == http.StatusSwitchingProtocols || status == 499 {
		return
	}
	failed := status >= 500
	slow := d >= SlowRequest
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.started {
		h.since, h.started = now, true
	}
	hr := now.Unix() / 3600
	b := &h.hours[hr%24]
	if b.hour != hr {
		*b = hourBucket{hour: hr}
	}
	b.total++
	if failed {
		b.failed++
	}
	if slow {
		b.slow++
	}
	if failed || slow {
		h.worst = append(h.worst, worstRequest{At: now.UTC(), Method: method, Path: shapeOf(path), Status: status, Ms: d.Milliseconds()})
		if len(h.worst) > 200 {
			h.worst = h.worst[len(h.worst)-200:]
		}
	}
}

type healthView struct {
	Since  *time.Time     `json:"since"`
	Total  int            `json:"total"`
	Failed int            `json:"failed"`
	Slow   int            `json:"slow"`
	Worst  []worstRequest `json:"worst"`
	Hourly []hourOut      `json:"hourly"`
}

type hourOut struct {
	Hour   time.Time `json:"hour"`
	Total  int       `json:"total"`
	Failed int       `json:"failed"`
	Slow   int       `json:"slow"`
}

func (h *healthStats) view(now time.Time) healthView {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := healthView{Worst: []worstRequest{}, Hourly: []hourOut{}}
	if h.started {
		s := h.since.UTC()
		v.Since = &s
	}
	cur := now.Unix() / 3600
	for hr := cur - 23; hr <= cur; hr++ {
		b := h.hours[hr%24]
		o := hourOut{Hour: time.Unix(hr*3600, 0).UTC()}
		if b.hour == hr {
			o.Total, o.Failed, o.Slow = b.total, b.failed, b.slow
			v.Total += b.total
			v.Failed += b.failed
			v.Slow += b.slow
		}
		v.Hourly = append(v.Hourly, o)
	}
	cut := now.Add(-24 * time.Hour)
	for _, w := range h.worst {
		if w.At.After(cut) {
			v.Worst = append(v.Worst, w)
		}
	}
	sort.SliceStable(v.Worst, func(i, j int) bool { return v.Worst[i].Ms > v.Worst[j].Ms })
	if len(v.Worst) > 12 {
		v.Worst = v.Worst[:12]
	}
	return v
}

type panelHealth struct {
	Requests healthView        `json:"requests"`
	DBBytes  int64             `json:"db_bytes"`
	DB       []store.DBSample  `json:"db_samples"`
	Backups  []store.BackupRow `json:"backups"`
	// BackupStaleHours is how long without a good dump is too long: the same limit as the alert.
	BackupStaleHours int `json:"backup_stale_hours"`
}

// panelHealth is the owner's page about Owlery itself: how its answers are going, how big the database is and grows, and
// whether the nightly dump reported.
func (s *Server) panelHealth(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can see this")
		return
	}
	now := s.Now().UTC()
	out := panelHealth{Requests: s.stats.view(now), BackupStaleHours: 30}
	var err error
	if err = s.Store.SampleDBSize(r.Context(), now); err == nil {
		out.DB, err = s.Store.DBSamples(r.Context(), 30)
	}
	if err == nil {
		out.Backups, err = s.Store.RecentBackups(r.Context(), 14)
	}
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if n := len(out.DB); n > 0 {
		out.DBBytes = out.DB[n-1].Bytes
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}
