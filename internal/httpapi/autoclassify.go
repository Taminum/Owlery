package httpapi

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/autoclassify"
	"github.com/Taminum/Owlery/internal/gemini"
	"github.com/Taminum/Owlery/internal/store"
)

var modelNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)

// modelCache keeps the model list for a few minutes so the settings page does not call the provider
// on every visit.
type modelCache struct {
	mu     sync.Mutex
	at     time.Time
	models []gemini.Model
}

func (c *modelCache) get(ctx context.Context, cl *gemini.Client, force bool) ([]gemini.Model, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && time.Since(c.at) < 5*time.Minute && c.models != nil {
		return c.models, nil
	}
	ms, err := cl.ListModels(ctx)
	if err != nil {
		return nil, err
	}
	c.models, c.at = ms, time.Now()
	return ms, nil
}

type dryRunSummary struct {
	Total        int            `json:"total"`
	Valid        int            `json:"valid"`
	Undetermined int            `json:"undetermined"`
	Invalid      int            `json:"invalid"`
	WithService  int            `json:"with_service"`
	LowConf      int            `json:"low_confidence"` // below 0.6: shown as guesses
	ByCategory   map[string]int `json:"by_category"`
	Issues       map[string]int `json:"issues"`
}

const lowConfidence = 0.6

func summarise(items []store.DryRunItem) dryRunSummary {
	s := dryRunSummary{Total: len(items), ByCategory: map[string]int{}, Issues: map[string]int{}}
	for _, it := range items {
		switch {
		case !it.Valid:
			s.Invalid++
			s.Issues[it.Issue]++
		case it.Undetermined:
			s.Undetermined++
			s.Valid++
		default:
			s.Valid++
			s.ByCategory[it.Category]++
			if it.Service != "" {
				s.WithService++
			}
			if it.Confidence < lowConfidence {
				s.LowConf++
			}
		}
	}
	return s
}

// autoStatus is what the owner sees: the settings, whether a key is present (never the key), and
// the state of the last dry run.
func (s *Server) autoStatus(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can manage automatic classification")
		return
	}
	st, err := s.Store.AutoSettings(r.Context())
	cats, err2 := s.Store.RuleCategories(r.Context())
	if err != nil || err2 != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	out := map[string]any{
		"settings":    st,
		"key_present": s.Gemini != nil && s.Gemini.HasKey(),
		"running":     s.Auto != nil && s.Auto.Running(),
		"categories":  len(cats),
	}
	if run, err := s.Store.LatestDryRun(r.Context()); err == nil {
		out["latest_run"] = run
	}
	if q, err := s.Store.QueueStatus(r.Context()); err == nil {
		out["queue"] = q
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) autoModels(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can manage automatic classification")
		return
	}
	if s.Gemini == nil || !s.Gemini.HasKey() {
		writeJSON(w, http.StatusOK, map[string]any{"models": []gemini.Model{}, "error": "no_key"})
		return
	}
	ms, err := s.models.get(r.Context(), s.Gemini, r.URL.Query().Get("refresh") == "1")
	if err != nil {
		code := "unavailable"
		var rl *gemini.RateLimited
		switch {
		case errors.Is(err, gemini.ErrAuth):
			code = "auth"
		case errors.As(err, &rl):
			code = "rate_limited"
		}
		writeJSON(w, http.StatusOK, map[string]any{"models": []gemini.Model{}, "error": code})
		return
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].Name < ms[j].Name })
	if ms == nil {
		ms = []gemini.Model{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": ms})
}

func (s *Server) autoSettings(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can manage automatic classification")
		return
	}
	var in struct {
		Model      string `json:"model"`
		BatchSize  int    `json:"batch_size"`
		DailyLimit int    `json:"daily_limit"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	switch {
	case in.Model != "" && !modelNameRe.MatchString(in.Model):
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_model", "model name is not valid")
		return
	case in.BatchSize < 5 || in.BatchSize > 30:
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_batch", "batch size must be 5 to 30")
		return
	case in.DailyLimit < 0 || in.DailyLimit > 20000:
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_limit", "daily limit must be 0 to 20000 domains")
		return
	}
	st, err := s.Store.SetAutoSettings(r.Context(), in.Model, in.BatchSize, in.DailyLimit, a.AccountID)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "autoclassify.settings", "settings", "autoclassify", map[string]any{"model": in.Model, "batch_size": in.BatchSize, "daily_limit": in.DailyLimit})
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) autoDryRunStart(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can manage automatic classification")
		return
	}
	if s.Auto == nil {
		s.writeErr(w, r, http.StatusServiceUnavailable, "unavailable", "automatic classification is not set up")
		return
	}
	id, err := s.Auto.Start(r.Context(), a.AccountID)
	switch {
	case errors.Is(err, autoclassify.ErrBusy):
		s.writeErr(w, r, http.StatusConflict, "busy", "a dry run is already in progress")
		return
	case errors.Is(err, autoclassify.ErrNoModel):
		s.writeErr(w, r, http.StatusUnprocessableEntity, "no_model", "choose a model first")
		return
	case errors.Is(err, gemini.ErrNoKey):
		s.writeErr(w, r, http.StatusUnprocessableEntity, "no_key", "no API key is configured on the server")
		return
	case errors.Is(err, autoclassify.ErrNoSites):
		s.writeErr(w, r, http.StatusUnprocessableEntity, "no_sites", "there are no unknown domains to look at")
		return
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "autoclassify.dryrun", "dryrun", id, nil)
	writeJSON(w, http.StatusAccepted, map[string]any{"run_id": id})
}

func (s *Server) autoDryRunLatest(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can manage automatic classification")
		return
	}
	run, err := s.Store.LatestDryRun(r.Context())
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"run": nil, "items": []store.DryRunItem{}, "summary": summarise(nil)})
		return
	}
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	items, err := s.Store.DryRunItems(r.Context(), run.ID)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"run": run, "items": items, "summary": summarise(items)})
}

// autoEnable is the kill switch. Turning it on is a deliberate act: the body must say that the owner
// knows unknown domain names go to an outside provider.
func (s *Server) autoEnable(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can manage automatic classification")
		return
	}
	var in struct {
		Enabled   bool `json:"enabled"`
		Confirmed bool `json:"confirmed"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if in.Enabled {
		st, err := s.Store.AutoSettings(r.Context())
		if err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		switch {
		case !in.Confirmed:
			s.writeErr(w, r, http.StatusUnprocessableEntity, "not_confirmed", "confirm that domain names are sent to the provider")
			return
		case st.Model == "" || s.Gemini == nil || !s.Gemini.HasKey():
			s.writeErr(w, r, http.StatusUnprocessableEntity, "not_ready", "choose a model and put the key on the server first")
			return
		}
	}
	if err := s.Store.SetAutoEnabled(r.Context(), in.Enabled); err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "autoclassify.enabled", "settings", "autoclassify", map[string]any{"enabled": in.Enabled})
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": in.Enabled})
}

// autoBackfill starts the one-time pass over historical unknown domains. It only queues them; the
// worker then spends the daily budget on them.
func (s *Server) autoBackfill(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can manage automatic classification")
		return
	}
	if err := s.Store.SetBackfill(r.Context(), "running"); err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "autoclassify.backfill", "settings", "autoclassify", nil)
	writeJSON(w, http.StatusOK, map[string]string{"backfill": "running"})
}
