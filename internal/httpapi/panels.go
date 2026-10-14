package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/remnawave"
	"github.com/Taminum/RemnaScope/internal/safehttp"
	"github.com/Taminum/RemnaScope/internal/store"
	"github.com/Taminum/RemnaScope/internal/syncer"
)

// panelDTO is the only shape in which a panel leaves the server. It has no field
// that could carry a token: the credential is reported as "configured" or "none".
type panelDTO struct {
	ID                  string            `json:"id"`
	Name                string            `json:"name"`
	BaseURL             string            `json:"base_url"`
	Status              string            `json:"status"`
	Demo                bool              `json:"demo"`
	UseCustomCA         bool              `json:"use_custom_ca"`
	SyncOptions         store.SyncOptions `json:"sync_options"`
	SyncIntervalSeconds int               `json:"sync_interval_seconds"`
	RetentionDays       int               `json:"retention_days"`
	APIVersion          *string           `json:"api_version"`
	Capabilities        json.RawMessage   `json:"capabilities"`
	LastProbeAt         *time.Time        `json:"last_probe_at"`
	LastProbe           json.RawMessage   `json:"last_probe"`
	LastSyncAt          *time.Time        `json:"last_sync_at"`
	LastSyncStatus      *string           `json:"last_sync_status"`
	NextSyncAt          *time.Time        `json:"next_sync_at"`
	ConsecutiveFailures int               `json:"consecutive_failures"`
	CircuitOpenUntil    *time.Time        `json:"circuit_open_until"`
	NodeCount           int               `json:"node_count"`
	UserCount           int               `json:"user_count"`
	Token               string            `json:"token"` // "configured" | "none"; never the value
	Role                string            `json:"role"`
	CreatedAt           time.Time         `json:"created_at"`
}

func toDTO(p store.Panel, a auth.Actor) panelDTO {
	tok := "none"
	if p.HasCredential {
		tok = "configured"
	}
	caps := p.Capabilities
	if len(caps) == 0 {
		caps = json.RawMessage(`{}`)
	}
	return panelDTO{ID: p.ID, Name: p.Name, BaseURL: p.BaseURL, Status: p.Status, Demo: p.Demo, UseCustomCA: p.UseCustomCA,
		SyncOptions: p.SyncOptions, SyncIntervalSeconds: p.SyncIntervalSeconds, RetentionDays: p.RetentionDays,
		APIVersion: p.APIVersion, Capabilities: caps, LastProbeAt: p.LastProbeAt, LastProbe: p.LastProbe,
		LastSyncAt: p.LastSyncAt, LastSyncStatus: p.LastSyncStatus, NextSyncAt: p.NextSyncAt,
		ConsecutiveFailures: p.ConsecutiveFailures, CircuitOpenUntil: p.CircuitOpenUntil,
		NodeCount: p.NodeCount, UserCount: p.UserCount, Token: tok, Role: a.RoleOn(p.ID), CreatedAt: p.CreatedAt}
}

// probeSummary is what we store and return from a probe: checks and capabilities, no tokens.
type probeSummary struct {
	Reachable     bool                   `json:"reachable"`
	TLSOK         bool                   `json:"tls_ok"`
	Authenticated bool                   `json:"authenticated"`
	RequiredOK    bool                   `json:"required_ok"`
	APIVersion    string                 `json:"api_version,omitempty"`
	Capabilities  remnawave.Capabilities `json:"capabilities"`
	NodeCount     int                    `json:"node_count"`
	NodesPreview  []string               `json:"nodes_preview,omitempty"`
	Checks        []remnawave.Check      `json:"checks"`
}

func summarize(r remnawave.ProbeResult) probeSummary {
	return probeSummary{Reachable: r.Reachable, TLSOK: r.TLSOK, Authenticated: r.Authenticated, RequiredOK: r.RequiredOK(),
		APIVersion: r.APIVersion, Capabilities: r.Capabilities, NodeCount: r.NodeCount, NodesPreview: r.NodesPreview, Checks: r.Checks}
}

func (ps probeSummary) stored() json.RawMessage {
	ps.NodesPreview = nil
	b, _ := json.Marshal(ps)
	return b
}

// --- validation ------------------------------------------------------------------

func validName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if n := utf8.RuneCountInString(s); n < 1 || n > 64 {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return s, true
}

func validToken(t string) bool {
	if t == "" || len(t) > 2048 {
		return false
	}
	for _, r := range t {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// runProbe validates the URL and probes the panel. It never stores anything.
func (s *Server) runProbe(ctx context.Context, baseURL, token string, useCA bool) remnawave.ProbeResult {
	ad, _, err := s.Probe(baseURL, token, useCA)
	if err != nil {
		return remnawave.ProbeResult{Checks: []remnawave.Check{
			{Name: "url", Required: true, Status: remnawave.CheckFailed, ErrorCode: safehttp.CodeOf(err)},
			{Name: "connection", Required: true, Status: remnawave.CheckSkipped},
			{Name: "auth", Required: true, Status: remnawave.CheckSkipped},
			{Name: "nodes", Required: true, Status: remnawave.CheckSkipped},
		}}
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	res := ad.Probe(ctx)
	res.Checks = append([]remnawave.Check{{Name: "url", Required: true, Status: remnawave.CheckOK}}, res.Checks...)
	return res
}

type probeIn struct {
	BaseURL     string `json:"base_url"`
	APIToken    string `json:"api_token"`
	UseCustomCA bool   `json:"use_custom_ca"`
}

func (s *Server) checkProbeIn(w http.ResponseWriter, r *http.Request, in probeIn) bool {
	if !validToken(in.APIToken) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_token", "API token is empty, too long, or contains whitespace")
		return false
	}
	if in.UseCustomCA && !s.CustomCA {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "custom_ca_unavailable", "no admin-managed CA is configured on the server")
		return false
	}
	return true
}

// --- handlers ------------------------------------------------------------------

func (s *Server) panelFor(w http.ResponseWriter, r *http.Request, a auth.Actor, perm auth.Perm) (store.Panel, bool) {
	p, err := s.Store.GetPanel(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "panel not found")
		return p, false
	}
	if !a.Can(p.ID, perm) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "your role does not allow this action")
		return p, false
	}
	return p, true
}

func (s *Server) listPanels(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	ps, err := s.Store.ListPanels(r.Context(), a.Scope())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	out := make([]panelDTO, 0, len(ps))
	for _, p := range ps {
		out = append(out, toDTO(p, a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"panels": out, "can_create": a.CanGlobal(), "custom_ca_available": s.CustomCA})
}

func (s *Server) getPanel(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if p, ok := s.panelFor(w, r, a, auth.PermView); ok {
		writeJSON(w, http.StatusOK, toDTO(p, a))
	}
}

func (s *Server) probePanel(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.CanGlobal() {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only owners can connect panels")
		return
	}
	if !s.Limits.Probe.Allow(a.AccountID) {
		s.writeErr(w, r, http.StatusTooManyRequests, "rate_limited", "too many connection tests, try again in a minute")
		return
	}
	var in probeIn
	if !s.decode(w, r, &in) || !s.checkProbeIn(w, r, in) {
		return
	}
	res := s.runProbe(r.Context(), in.BaseURL, in.APIToken, in.UseCustomCA)
	s.audit(r, a, "", "panel.probe", "panel", "", map[string]any{"required_ok": res.RequiredOK()})
	writeJSON(w, http.StatusOK, summarize(res))
}

type createIn struct {
	probeIn
	Name                string             `json:"name"`
	SyncOptions         *store.SyncOptions `json:"sync_options"`
	SyncIntervalSeconds *int               `json:"sync_interval_seconds"`
	RetentionDays       *int               `json:"retention_days"`
	AllowPartial        bool               `json:"allow_partial"`
}

func (s *Server) createPanel(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.CanGlobal() {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only owners can connect panels")
		return
	}
	if !s.Limits.Probe.Allow(a.AccountID) {
		s.writeErr(w, r, http.StatusTooManyRequests, "rate_limited", "too many connection tests, try again in a minute")
		return
	}
	var in createIn
	if !s.decode(w, r, &in) || !s.checkProbeIn(w, r, in.probeIn) {
		return
	}
	name, ok := validName(in.Name)
	if !ok {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_name", "name must be 1 to 64 characters without control characters")
		return
	}
	opts := store.SyncOptions{Nodes: true, Users: true}
	if in.SyncOptions != nil {
		opts = *in.SyncOptions
	}
	interval, retention := 300, 30
	if in.SyncIntervalSeconds != nil {
		interval = *in.SyncIntervalSeconds
	}
	if in.RetentionDays != nil {
		retention = *in.RetentionDays
	}
	if interval < 60 || interval > 86400 || retention < 1 || retention > 3650 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_settings", "interval must be 60 to 86400 seconds and retention 1 to 3650 days")
		return
	}

	// The client's own probe is never trusted: re-probe here with the same code path.
	res := s.runProbe(r.Context(), in.BaseURL, in.APIToken, in.UseCustomCA)
	sum := summarize(res)
	if !res.RequiredOK() {
		s.writeErrDetails(w, r, http.StatusUnprocessableEntity, "probe_failed", "the panel did not pass the required connection checks", sum)
		return
	}
	var gaps []string
	if opts.Users && !res.Capabilities.Users {
		gaps = append(gaps, "users")
	}
	if opts.Stats && !(res.Capabilities.SystemStats && res.Capabilities.Bandwidth) {
		gaps = append(gaps, "stats")
	}
	if len(gaps) > 0 {
		if !in.AllowPartial {
			s.writeErrDetails(w, r, http.StatusUnprocessableEntity, "partial_capabilities",
				"the panel does not support everything you asked for; confirm to continue with fewer features", map[string]any{"gaps": gaps, "probe": sum})
			return
		}
		for _, g := range gaps {
			if g == "users" {
				opts.Users = false
			}
			if g == "stats" {
				opts.Stats = false
			}
		}
	}

	_, normalized, err := s.Probe(in.BaseURL, in.APIToken, in.UseCustomCA)
	if err != nil {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_url", "URL is not acceptable")
		return
	}
	id := store.NewPanelID()
	sealed, err := s.Ring.Seal(id, []byte(in.APIToken))
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	caps, _ := json.Marshal(res.Capabilities)
	var ver *string
	if res.APIVersion != "" {
		ver = &res.APIVersion
	}
	p, err := s.Store.CreatePanel(r.Context(), id, store.PanelInput{Name: name, BaseURL: normalized, UseCustomCA: in.UseCustomCA,
		SyncOptions: opts, SyncIntervalSeconds: interval, RetentionDays: retention, APIVersion: ver, Capabilities: caps, LastProbe: sum.stored()}, &sealed)
	if errors.Is(err, store.ErrConflict) {
		s.writeErr(w, r, http.StatusConflict, "name_taken", "a panel with this name already exists")
		return
	}
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, p.ID, "panel.create", "panel", p.ID, map[string]any{"name": p.Name, "api_version": res.APIVersion, "partial": gaps, "node_count": res.NodeCount})
	writeJSON(w, http.StatusCreated, map[string]any{"panel": toDTO(p, a), "probe": sum, "partial_gaps": gaps})
}

func (s *Server) patchPanel(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	p, ok := s.panelFor(w, r, a, auth.PermAdmin)
	if !ok {
		return
	}
	var in struct {
		Name                *string            `json:"name"`
		SyncOptions         *store.SyncOptions `json:"sync_options"`
		SyncIntervalSeconds *int               `json:"sync_interval_seconds"`
		RetentionDays       *int               `json:"retention_days"`
		UseCustomCA         *bool              `json:"use_custom_ca"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	pt := store.PanelPatch{SyncOptions: in.SyncOptions, SyncIntervalSeconds: in.SyncIntervalSeconds, RetentionDays: in.RetentionDays, UseCustomCA: in.UseCustomCA}
	var changed []string
	if in.Name != nil {
		n, ok := validName(*in.Name)
		if !ok {
			s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_name", "name must be 1 to 64 characters without control characters")
			return
		}
		pt.Name = &n
		changed = append(changed, "name")
	}
	if in.SyncIntervalSeconds != nil {
		if *in.SyncIntervalSeconds < 60 || *in.SyncIntervalSeconds > 86400 {
			s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_settings", "interval must be 60 to 86400 seconds")
			return
		}
		changed = append(changed, "sync_interval_seconds")
	}
	if in.RetentionDays != nil {
		if *in.RetentionDays < 1 || *in.RetentionDays > 3650 {
			s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_settings", "retention must be 1 to 3650 days")
			return
		}
		changed = append(changed, "retention_days")
	}
	if in.UseCustomCA != nil {
		if *in.UseCustomCA && !s.CustomCA {
			s.writeErr(w, r, http.StatusUnprocessableEntity, "custom_ca_unavailable", "no admin-managed CA is configured on the server")
			return
		}
		changed = append(changed, "use_custom_ca")
	}
	if in.SyncOptions != nil {
		changed = append(changed, "sync_options")
	}
	if p.Demo && (in.UseCustomCA != nil || in.SyncOptions != nil) {
		s.writeErr(w, r, http.StatusConflict, "demo_panel", "demo panels have no connection settings")
		return
	}
	up, err := s.Store.UpdatePanel(r.Context(), a.Scope(), p.ID, pt)
	switch {
	case errors.Is(err, store.ErrConflict):
		s.writeErr(w, r, http.StatusConflict, "name_taken", "a panel with this name already exists")
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
	default:
		s.audit(r, a, p.ID, "panel.update", "panel", p.ID, map[string]any{"fields": changed})
		writeJSON(w, http.StatusOK, toDTO(up, a))
	}
}

func (s *Server) panelToken(ctx context.Context, p store.Panel) (string, error) {
	sealed, err := s.Store.Credential(ctx, p.ID)
	if err != nil {
		return "", err
	}
	raw, err := s.Ring.Open(p.ID, sealed)
	if err != nil {
		return "", err
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	return string(raw), nil
}

func (s *Server) testPanel(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	p, ok := s.panelFor(w, r, a, auth.PermOperate)
	if !ok {
		return
	}
	if p.Demo {
		s.writeErr(w, r, http.StatusConflict, "demo_panel", "demo panels have no connection to test")
		return
	}
	if !s.Limits.Test.Allow(a.AccountID + "|" + p.ID) {
		s.writeErr(w, r, http.StatusTooManyRequests, "rate_limited", "too many connection tests, try again in a minute")
		return
	}
	tok, err := s.panelToken(r.Context(), p)
	if err != nil {
		s.writeErr(w, r, http.StatusConflict, "credential_unreadable", "the stored token cannot be read; replace it")
		return
	}
	res := s.runProbe(r.Context(), p.BaseURL, tok, p.UseCustomCA)
	sum := summarize(res)
	caps, _ := json.Marshal(res.Capabilities)
	var ver *string
	if res.APIVersion != "" {
		ver = &res.APIVersion
	}
	if res.RequiredOK() {
		_ = s.Store.SavePanelProbe(r.Context(), p.ID, ver, caps, sum.stored())
	} else {
		_ = s.Store.SavePanelProbe(r.Context(), p.ID, p.APIVersion, p.Capabilities, sum.stored())
	}
	s.audit(r, a, p.ID, "panel.test", "panel", p.ID, map[string]any{"required_ok": res.RequiredOK()})
	writeJSON(w, http.StatusOK, sum)
}

func (s *Server) rotateToken(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	p, ok := s.panelFor(w, r, a, auth.PermAdmin)
	if !ok {
		return
	}
	if p.Demo {
		s.writeErr(w, r, http.StatusConflict, "demo_panel", "demo panels have no token")
		return
	}
	var in struct {
		APIToken string `json:"api_token"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if !validToken(in.APIToken) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_token", "API token is empty, too long, or contains whitespace")
		return
	}
	if !s.Limits.Test.Allow(a.AccountID + "|" + p.ID) {
		s.writeErr(w, r, http.StatusTooManyRequests, "rate_limited", "too many connection tests, try again in a minute")
		return
	}
	// Verify the new token first; a bad one must never replace a working one.
	res := s.runProbe(r.Context(), p.BaseURL, in.APIToken, p.UseCustomCA)
	sum := summarize(res)
	if !res.RequiredOK() {
		s.writeErrDetails(w, r, http.StatusUnprocessableEntity, "probe_failed", "the new token did not pass the required checks; the old token is unchanged", sum)
		return
	}
	sealed, err := s.Ring.Seal(p.ID, []byte(in.APIToken))
	if err != nil || s.Store.PutCredential(r.Context(), p.ID, sealed) != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	caps, _ := json.Marshal(res.Capabilities)
	var ver *string
	if res.APIVersion != "" {
		ver = &res.APIVersion
	}
	_ = s.Store.SavePanelProbe(r.Context(), p.ID, ver, caps, sum.stored())
	if p.Status == "error" {
		_ = s.Store.SetPanelStatus(r.Context(), p.ID, "active") // clears the breaker and schedules a sync
	}
	s.audit(r, a, p.ID, "panel.token_rotate", "panel", p.ID, map[string]any{"key_version": sealed.KeyVersion})
	up, _ := s.Store.GetPanel(r.Context(), a.Scope(), p.ID)
	writeJSON(w, http.StatusOK, map[string]any{"panel": toDTO(up, a), "probe": sum})
}

func (s *Server) setEnabled(enable bool) authedHandler {
	return func(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
		p, ok := s.panelFor(w, r, a, auth.PermAdmin)
		if !ok {
			return
		}
		if p.Demo {
			s.writeErr(w, r, http.StatusConflict, "demo_panel", "demo panels cannot be disabled")
			return
		}
		status, action := "disabled", "panel.disable"
		if enable {
			status, action = "active", "panel.enable"
		}
		if err := s.Store.SetPanelStatus(r.Context(), p.ID, status); err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		s.audit(r, a, p.ID, action, "panel", p.ID, nil)
		up, _ := s.Store.GetPanel(r.Context(), a.Scope(), p.ID)
		writeJSON(w, http.StatusOK, toDTO(up, a))
	}
}

func (s *Server) deletePanel(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	p, ok := s.panelFor(w, r, a, auth.PermOwner)
	if !ok {
		return
	}
	var in struct {
		Confirm   string `json:"confirm"`
		Retention string `json:"retention"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if in.Retention != "purge" && in.Retention != "archive" {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "retention_required", `choose what happens to the data: "purge" or "archive"`)
		return
	}
	if in.Confirm != p.Name {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "confirmation_mismatch", "type the exact panel name to confirm")
		return
	}
	if p.Demo {
		s.writeErr(w, r, http.StatusConflict, "demo_panel", "demo panels cannot be removed")
		return
	}
	s.audit(r, a, p.ID, "panel.delete", "panel", p.ID, map[string]any{"name": p.Name, "retention": in.Retention})
	if err := s.Store.DeletePanel(r.Context(), p.ID, in.Retention); err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) syncPanel(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	p, ok := s.panelFor(w, r, a, auth.PermOperate)
	if !ok {
		return
	}
	switch {
	case p.Demo:
		s.writeErr(w, r, http.StatusConflict, "demo_panel", "demo panels have nothing to sync")
		return
	case p.Status == "disabled":
		s.writeErr(w, r, http.StatusConflict, "panel_disabled", "enable the panel first")
		return
	case s.Sync == nil:
		s.writeErr(w, r, http.StatusServiceUnavailable, "sync_unavailable", "sync worker is not running")
		return
	case s.Sync.Busy(p.ID):
		s.writeErr(w, r, http.StatusConflict, "sync_in_progress", "a sync of this panel is already running")
		return
	case !s.Limits.Sync.Allow(p.ID):
		s.writeErr(w, r, http.StatusTooManyRequests, "rate_limited", "this panel was synced a moment ago")
		return
	}
	go func(id string) {
		if _, err := s.Sync.SyncPanel(context.WithoutCancel(r.Context()), id, "manual"); err != nil && !errors.Is(err, syncer.ErrBusy) {
			s.Log.Warn("manual sync", "panel", id, "err", err)
		}
	}(p.ID)
	s.audit(r, a, p.ID, "panel.sync", "panel", p.ID, nil)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
}

func (s *Server) listNodes(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	p, ok := s.panelFor(w, r, a, auth.PermView)
	if !ok {
		return
	}
	ns, err := s.Store.ListNodes(r.Context(), a.Scope(), p.ID, r.URL.Query().Get("include_removed") == "1")
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if ns == nil {
		ns = []store.Node{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": ns})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	p, ok := s.panelFor(w, r, a, auth.PermView)
	if !ok {
		return
	}
	us, next, err := s.Store.ListUsers(r.Context(), a.Scope(), p.ID, r.URL.Query().Get("cursor"), 50)
	if err != nil {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_cursor", "invalid cursor")
		return
	}
	if !a.Can(p.ID, auth.PermOperate) { // viewers see masked account names
		for i := range us {
			if us[i].Username != nil {
				m := auth.MaskUsername(*us[i].Username)
				us[i].Username = &m
			}
		}
	}
	if us == nil {
		us = []store.User{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": us, "next_cursor": next})
}

func (s *Server) listSyncRuns(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	p, ok := s.panelFor(w, r, a, auth.PermOperate)
	if !ok {
		return
	}
	runs, err := s.Store.ListSyncRuns(r.Context(), a.Scope(), p.ID, 20)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if runs == nil {
		runs = []store.SyncRun{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": runs})
}
