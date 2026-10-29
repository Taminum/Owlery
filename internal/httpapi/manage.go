package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/secops"
	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/store"
)

// manage carries one management request to the machine's agent and brings its answer back: a look at the processes,
// services, startup entries, sessions, event log or connections, or a change to one of them. A change is written to the
// audit log together with what was asked, before the machine is told, so that even one that fails leaves a trace. Only
// the owner and administrators of a linked panel may do this, and only on a machine that was installed to allow it.
func (s *Server) manage(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
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
		Op   string          `json:"op"`
		Args json.RawMessage `json:"args"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	write := secproto.AdminWrites[in.Op]
	if !write && !secproto.AdminReads[in.Op] {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_op", "unknown management operation")
		return
	}
	if len(in.Args) > 4096 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_args", "the arguments are too long")
		return
	}
	agent, err := s.Store.SecAgentOf(r.Context(), v.ID)
	if err != nil || s.SecOps == nil || !s.SecOps.Online(agent.ID) {
		s.writeErr(w, r, http.StatusConflict, "agent_offline", "the machine's agent is not connected")
		return
	}
	if !slices.Contains(agent.Capabilities, secproto.CapAdmin) {
		s.writeErr(w, r, http.StatusConflict, "admin_not_allowed", "this machine does not allow management from Owlery")
		return
	}
	if write {
		meta := map[string]any{"name": v.Name, "op": in.Op}
		if len(in.Args) > 0 {
			meta["args"] = json.RawMessage(in.Args)
		}
		s.audit(r, a, "", "manage."+in.Op, "server", v.ID, meta)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
	defer cancel()
	res, err := s.SecOps.Admin(ctx, agent.ID, secproto.AdminReq{Op: in.Op, Args: in.Args})
	switch {
	case errors.Is(err, secops.ErrOffline):
		s.writeErr(w, r, http.StatusConflict, "agent_offline", "the machine's agent is not connected")
	case err != nil:
		s.writeErr(w, r, http.StatusGatewayTimeout, "no_answer", "the machine did not answer in time")
	case !res.OK:
		// The agent's own explanation is written for the administrator and is shown as it is.
		s.writeErr(w, r, http.StatusConflict, "admin_failed", res.Error)
	default:
		writeJSON(w, http.StatusOK, map[string]any{"data": res.Data})
	}
}
