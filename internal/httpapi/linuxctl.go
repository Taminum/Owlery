package httpapi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/linuxhelper"
	"github.com/Taminum/Owlery/internal/secops"
	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/store"
)

// linuxCtl carries one request about services or files to the machine's agent and brings the answer back. Changes to a service,
// and reading a journal or a file, are written to the audit log before the machine is told, so that even one that fails leaves a
// trace. The list of services and of a folder only look, and are not. Only the owner and administrators of a linked panel may do
// any of it, and only on a machine whose owner installed the helper; what that helper allows is decided on the machine.
func (s *Server) linuxCtl(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
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
		Op   string `json:"op"`
		Name string `json:"name"`
		Path string `json:"path"`
		Tail int    `json:"tail"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	write := secproto.LinuxWrites[in.Op]
	if !write && !secproto.LinuxReads[in.Op] {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_op", "unknown operation")
		return
	}
	unitOp := write || in.Op == secproto.LinuxJournal
	if unitOp && !linuxhelper.ValidUnit(in.Name) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_name", "that is not a service name")
		return
	}
	if len(in.Path) > 1024 || (in.Op == secproto.LinuxCat && in.Path == "") {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_path", "that is not a usable path")
		return
	}
	in.Tail = max(0, min(in.Tail, secproto.MaxLinuxTail))
	agent, err := s.Store.SecAgentOf(r.Context(), v.ID)
	if err != nil || s.SecOps == nil || !s.SecOps.Online(agent.ID) {
		s.writeErr(w, r, http.StatusConflict, "agent_offline", "the machine's agent is not connected")
		return
	}
	if !slices.Contains(agent.Capabilities, secproto.CapLinuxCtl) {
		s.writeErr(w, r, http.StatusConflict, "not_enabled", "this machine has not been set up for services and files")
		return
	}
	if write || in.Op == secproto.LinuxJournal || in.Op == secproto.LinuxCat {
		meta := map[string]any{"name": v.Name, "op": in.Op}
		if unitOp {
			meta["unit"] = in.Name
		} else {
			meta["path"] = in.Path
		}
		s.audit(r, a, "", "linux."+in.Op, "server", v.ID, meta)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 55*time.Second)
	defer cancel()
	res, err := s.SecOps.Linux(ctx, agent.ID, secproto.LinuxReq{Op: in.Op, Name: in.Name, Path: in.Path, Tail: in.Tail})
	switch {
	case errors.Is(err, secops.ErrOffline):
		s.writeErr(w, r, http.StatusConflict, "agent_offline", "the machine's agent is not connected")
		return
	case err != nil:
		s.writeErr(w, r, http.StatusGatewayTimeout, "no_answer", "the machine did not answer in time")
		return
	}
	if !res.OK {
		code, status := res.Code, http.StatusBadGateway
		switch res.Code {
		case linuxhelper.CodeNoSuch:
			status = http.StatusNotFound
		case linuxhelper.CodeNotAllowed:
			status = http.StatusForbidden
		case linuxhelper.CodeBadRequest, linuxhelper.CodeBinary, linuxhelper.CodeNotFile:
			status = http.StatusUnprocessableEntity
		case "not_enabled", linuxhelper.CodeUnavailable:
			status = http.StatusConflict
		}
		if code == "" {
			code = "command_error"
		}
		s.writeErr(w, r, status, code, "the machine refused or could not do that")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, struct {
		Units     []secproto.LinuxUnit  `json:"units"`
		Dir       string                `json:"dir"`
		Dirs      []string              `json:"dirs"`
		Entries   []secproto.LinuxEntry `json:"entries"`
		Text      string                `json:"text"`
		Truncated bool                  `json:"truncated"`
		Active    string                `json:"active"`
	}{nonNil(res.Units), res.Dir, nonNil(res.Dirs), nonNil(res.Entries), res.Text, res.Truncated, res.Active})
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
