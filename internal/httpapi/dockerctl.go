package httpapi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/dockerhelper"
	"github.com/Taminum/Owlery/internal/secops"
	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/store"
)

// dockerCtlOf says whether this caller can read logs and restart containers on the machine right now: they administer it, its
// agent is connected, and the machine runs the Docker helper (the agent only announces the capability then).
func (s *Server) dockerCtlOf(r *http.Request, a auth.Actor, v store.VPS) bool {
	if !vpsCanEdit(a, v) || s.SecOps == nil {
		return false
	}
	agent, err := s.Store.SecAgentOf(r.Context(), v.ID)
	return err == nil && s.SecOps.Online(agent.ID) && slices.Contains(agent.Capabilities, secproto.CapDockerCtl)
}

// dockerAsk sends one request to the machine's agent and answers the browser with what came back.
func (s *Server) dockerAsk(w http.ResponseWriter, r *http.Request, a auth.Actor, op string, tail int, timeout time.Duration) (store.VPS, secproto.DockerResult, string, bool) {
	var none secproto.DockerResult
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.vpsNotFound(w, r)
		return v, none, "", false
	}
	if !vpsCanEdit(a, v) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of a linked panel is required")
		return v, none, "", false
	}
	name := r.PathValue("name")
	if !dockerhelper.ValidName(name) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_name", "that is not a container name")
		return v, none, "", false
	}
	agent, err := s.Store.SecAgentOf(r.Context(), v.ID)
	if err != nil || s.SecOps == nil || !s.SecOps.Online(agent.ID) {
		s.writeErr(w, r, http.StatusConflict, "agent_offline", "the machine's agent is not connected")
		return v, none, "", false
	}
	if !slices.Contains(agent.Capabilities, secproto.CapDockerCtl) {
		s.writeErr(w, r, http.StatusConflict, "not_enabled", "this machine has not been set up for container control")
		return v, none, "", false
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	res, err := s.SecOps.Docker(ctx, agent.ID, secproto.DockerReq{Op: op, Name: name, Tail: tail})
	switch {
	case errors.Is(err, secops.ErrOffline):
		s.writeErr(w, r, http.StatusConflict, "agent_offline", "the machine's agent is not connected")
		return v, none, name, false
	case err != nil:
		s.writeErr(w, r, http.StatusGatewayTimeout, "no_answer", "the machine did not answer in time")
		return v, none, name, false
	}
	if !res.OK {
		code, status := res.Code, http.StatusBadGateway
		switch res.Code {
		case dockerhelper.CodeNoSuch:
			status = http.StatusNotFound
		case dockerhelper.CodeNotAllowed:
			status = http.StatusForbidden
		case dockerhelper.CodeBadRequest:
			status = http.StatusUnprocessableEntity
		case "not_enabled", dockerhelper.CodeUnavailable:
			status = http.StatusConflict
		}
		if code == "" {
			code = "command_error"
		}
		s.writeErr(w, r, status, code, "the machine refused or could not do that")
		return v, none, name, false
	}
	return v, res, name, true
}

// getDockerLogs returns the last lines of one container's log. Reading is written to the audit log too: a log can hold anything.
func (s *Server) getDockerLogs(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	tail, _ := strconv.Atoi(r.URL.Query().Get("tail"))
	if tail <= 0 {
		tail = dockerhelper.DefaultTail
	}
	tail = min(tail, secproto.MaxDockerTail)
	v, res, name, ok := s.dockerAsk(w, r, a, secproto.DockerLogs, tail, 30*time.Second)
	if !ok {
		return
	}
	s.audit(r, a, "", "docker.logs", "server", v.ID, map[string]any{"name": v.Name, "container": name, "tail": tail})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"log": res.Log, "truncated": res.Truncated, "tail": tail})
}

// restartDockerContainer restarts one container. The caller must say so in the request body; the audit record is written before
// the restart is asked for, so that it is there even when the answer never comes.
func (s *Server) restartDockerContainer(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.vpsNotFound(w, r)
		return
	}
	if vpsCanEdit(a, v) {
		s.audit(r, a, "", "docker.restart", "server", v.ID, map[string]any{"name": v.Name, "container": r.PathValue("name")})
	}
	_, res, _, ok := s.dockerAsk(w, r, a, secproto.DockerRestart, 0, 60*time.Second)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "running": res.Running})
}
