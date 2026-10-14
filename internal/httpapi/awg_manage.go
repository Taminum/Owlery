package httpapi

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/awgops"
	"github.com/Taminum/RemnaScope/internal/ingestproto"
	"github.com/Taminum/RemnaScope/internal/store"
)

var (
	awgNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,39}$`)
	awgSlugRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	awgCodeRe = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
)

// awgOpFailure turns what the host or the agent said into an HTTP answer. Only fixed words go out.
func (s *Server) awgOpFailure(w http.ResponseWriter, r *http.Request, err error, res ingestproto.AWGOpResult) {
	switch {
	case errors.Is(err, awgops.ErrOffline):
		s.writeErr(w, r, http.StatusServiceUnavailable, "agent_offline", "the AmneziaWG agent is not connected")
	case errors.Is(err, awgops.ErrTimeout):
		s.writeErr(w, r, http.StatusGatewayTimeout, "agent_timeout", "the agent did not answer in time; the host may or may not have made the change")
	default:
		code := res.Code
		if !awgCodeRe.MatchString(code) {
			code = "failed"
		}
		status := http.StatusBadGateway
		switch code {
		case "not_managed", "management_off", "busy", "container_not_running":
			status = http.StatusConflict
		case "bad_name", "bad_key", "bad_container", "bad_operation":
			status = http.StatusUnprocessableEntity
		case "not_found":
			status = http.StatusNotFound
		}
		s.writeErr(w, r, status, "awg_"+code, "the AmneziaWG host refused or could not do it")
	}
}

func (s *Server) awgOwner(w http.ResponseWriter, r *http.Request, a auth.Actor) bool {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can change AmneziaWG devices")
		return false
	}
	if s.AWGOps == nil {
		s.writeErr(w, r, http.StatusServiceUnavailable, "unavailable", "AmneziaWG management is not set up")
		return false
	}
	return true
}

// awgAdd adds a device on the host and returns its client configuration, once. The configuration holds
// the device's private key: it is neither stored nor logged here, and the response must not be cached.
func (s *Server) awgAdd(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.awgOwner(w, r, a) {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	name := strings.TrimSpace(in.Name)
	if !awgNameRe.MatchString(name) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_name", "name: 1 to 40 letters, digits, spaces and . _ ( ) -")
		return
	}
	instID := r.PathValue("id")
	agentID, container, mode, err := s.Store.AWGInstanceTarget(r.Context(), a.Scope(), instID)
	if err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such server")
		return
	}
	if mode != "managed" {
		s.writeErr(w, r, http.StatusConflict, "not_managed", "this server is read-only: the host does not allow changes")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
	defer cancel()
	res, err := s.AWGOps.Do(ctx, agentID, ingestproto.AWGOp{Op: "add", Container: container, Name: name})
	if err != nil || res.Status != "ok" {
		code := res.Code
		if err != nil {
			code = "agent"
		}
		_ = s.Store.RecordAWGOperation(r.Context(), instID, "add", "", name, "error", code, a.AccountID)
		s.audit(r, a, "", "awg.add", "awg_instance", instID, map[string]any{"name": name, "ok": false, "code": code})
		s.awgOpFailure(w, r, err, res)
		return
	}
	if err := s.Store.RecordAWGAdd(r.Context(), instID, res.Key, res.IP, name); err != nil {
		s.Log.Error("recording a new AmneziaWG device", "request_id", reqID(r.Context()))
	}
	_ = s.Store.RecordAWGOperation(r.Context(), instID, "add", res.Key, name, "ok", "", a.AccountID)
	s.audit(r, a, "", "awg.add", "awg_instance", instID, map[string]any{"name": name, "ok": true, "key": shortKey(res.Key)})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusCreated, map[string]any{
		"name": name, "key_short": shortKey(res.Key), "tunnel_ip": res.IP, "config": res.Config,
		"filename": strings.Trim(awgSlugRe.ReplaceAllString(name, "_"), "_") + ".conf",
	})
}

// awgRevoke removes a device from the host. It stays in the list as "gone" until it is forgotten.
func (s *Server) awgRevoke(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.awgOwner(w, r, a) {
		return
	}
	peerID := r.PathValue("id")
	inst, agentID, container, mode, key, label, gone, err := s.Store.AWGPeerTarget(r.Context(), a.Scope(), peerID)
	if err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such device")
		return
	}
	if mode != "managed" {
		s.writeErr(w, r, http.StatusConflict, "not_managed", "this server is read-only: the host does not allow changes")
		return
	}
	if gone {
		s.writeErr(w, r, http.StatusConflict, "already_gone", "the device is already removed from the server")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
	defer cancel()
	res, err := s.AWGOps.Do(ctx, agentID, ingestproto.AWGOp{Op: "revoke", Container: container, Key: key})
	if err == nil && res.Status != "ok" && res.Code == "not_found" {
		// Already absent on the host: that is what was asked for. Bring the list in line.
		_ = s.Store.MarkAWGGone(r.Context(), peerID)
	}
	if err != nil || res.Status != "ok" {
		code := res.Code
		if err != nil {
			code = "agent"
		}
		_ = s.Store.RecordAWGOperation(r.Context(), inst, "revoke", key, label, "error", code, a.AccountID)
		s.audit(r, a, "", "awg.revoke", "awg_peer", peerID, map[string]any{"name": label, "ok": false, "code": code})
		s.awgOpFailure(w, r, err, res)
		return
	}
	_ = s.Store.MarkAWGGone(r.Context(), peerID)
	_ = s.Store.RecordAWGOperation(r.Context(), inst, "revoke", key, label, "ok", "", a.AccountID)
	s.audit(r, a, "", "awg.revoke", "awg_peer", peerID, map[string]any{"name": label, "ok": true, "key": shortKey(key)})
	w.WriteHeader(http.StatusNoContent)
}

// awgRename changes only the name RemnaScope shows.
func (s *Server) awgRename(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can rename devices")
		return
	}
	var in struct {
		Label string `json:"label"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	label := strings.TrimSpace(in.Label)
	if !awgNameRe.MatchString(label) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_name", "name: 1 to 40 letters, digits, spaces and . _ ( ) -")
		return
	}
	if err := s.Store.RenameAWGPeer(r.Context(), a.Scope(), r.PathValue("id"), label); err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such device")
		return
	}
	s.audit(r, a, "", "awg.rename", "awg_peer", r.PathValue("id"), map[string]any{"name": label})
	w.WriteHeader(http.StatusNoContent)
}
