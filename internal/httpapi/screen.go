package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/store"
)

// Close codes the screen page explains to the person.
const (
	screenNoAgent  = 4001 // the machine has no agent connected
	screenNotAllow = 4002 // the machine does not allow screen sharing
	screenNoAnswer = 4003 // the agent was asked and did not connect back
	screenNoHelper = 4004 // the agent answered but nobody is signed in, or the helper in their session is not running
)

// screen shows the screen of the person at the machine and relays their mouse and keyboard. The machine's helper speaks
// its own framed protocol (see package remotehelper) that passes through here as plain bytes; Owlery
// only starts and ends the session and records both in the audit log. The picture is never recorded.
func (s *Server) screen(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !sameOrigin(r) {
		s.writeErr(w, r, http.StatusForbidden, "cross_origin", "cross-origin request refused")
		return
	}
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.vpsNotFound(w, r)
		return
	}
	if !vpsCanEdit(a, v) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of a linked panel is required")
		return
	}
	b, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer b.CloseNow()
	b.SetReadLimit(256 << 10) // a chunk of an uploaded file is the largest thing the page sends
	ctx := r.Context()

	agent, err := s.Store.SecAgentOf(ctx, v.ID)
	if err != nil || s.SecOps == nil || !s.SecOps.Online(agent.ID) {
		b.Close(screenNoAgent, "the machine's agent is not connected")
		return
	}
	if !slices.Contains(agent.Capabilities, secproto.CapRemote) {
		b.Close(screenNotAllow, "this machine does not allow screen sharing")
		return
	}
	octx, cancel := context.WithTimeout(ctx, 20*time.Second)
	// The session the administrator chose in the page; none or an unreadable value means the agent chooses.
	var session uint32
	if n, err := strconv.ParseUint(r.URL.Query().Get("session"), 10, 32); err == nil {
		session = uint32(n)
	}
	m, release, err := s.SecOps.OpenRemote(octx, agent.ID, session)
	cancel()
	if err != nil {
		b.Close(screenNoAnswer, "the machine did not open a screen session")
		return
	}
	defer release()
	defer m.CloseNow()

	// The first frame says whether the helper in the person's session answered.
	fctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	typ, first, err := m.Read(fctx)
	cancel()
	if err != nil || typ != websocket.MessageText || string(first) != secproto.TunnelReady {
		b.Close(screenNoHelper, "nobody is signed in on the machine, or its screen helper is not running")
		return
	}

	started := s.Now().UTC()
	s.audit(r, a, "", "screen.open", "server", v.ID, map[string]any{"name": v.Name})
	var out, in atomic.Int64

	ctx, stop := context.WithCancel(ctx)
	defer stop()
	// The machine to the browser.
	go func() {
		defer stop()
		for {
			typ, data, err := m.Read(ctx)
			if err != nil {
				return
			}
			out.Add(int64(len(data)))
			if b.Write(ctx, typ, data) != nil {
				return
			}
		}
	}()
	// The browser to the machine.
	for {
		typ, data, err := b.Read(ctx)
		if err != nil {
			break
		}
		in.Add(int64(len(data)))
		s.auditFile(r, a, v, typ, data)
		if m.Write(ctx, typ, data) != nil {
			break
		}
	}
	stop()
	m.Close(websocket.StatusNormalClosure, "")
	b.Close(websocket.StatusNormalClosure, "")
	s.audit(r, a, "", "screen.close", "server", v.ID, map[string]any{"name": v.Name,
		"seconds": int(s.Now().UTC().Sub(started).Seconds()), "bytes_out": out.Load(), "bytes_in": in.Load()})
}

// Message types of the helper's own protocol that start a file transfer (see package remotehelper, fs_windows.go). The
// page sends each message as one WebSocket message: [1 byte type][4 bytes length][JSON], so what a transfer is for can
// be read here and written to the audit log before it is passed on.
const (
	fsGetMsg      = 0x0D
	fsPutBeginMsg = 0x0E
)

// auditFile records the start of a file download or upload with its path, the one thing the relay otherwise could not
// know. Listing a folder is not recorded: it moves no file.
func (s *Server) auditFile(r *http.Request, a auth.Actor, v store.VPS, typ websocket.MessageType, data []byte) {
	if typ != websocket.MessageBinary || len(data) < 6 || (data[0] != fsGetMsg && data[0] != fsPutBeginMsg) {
		return
	}
	var req struct {
		Path      string `json:"path"`
		Size      int64  `json:"size"`
		Overwrite bool   `json:"overwrite"`
	}
	if json.Unmarshal(data[5:], &req) != nil {
		return
	}
	if data[0] == fsGetMsg {
		s.audit(r, a, "", "screen.file.download", "server", v.ID, map[string]any{"name": v.Name, "path": req.Path})
		return
	}
	s.audit(r, a, "", "screen.file.upload", "server", v.ID, map[string]any{"name": v.Name, "path": req.Path, "size": req.Size, "overwrite": req.Overwrite})
}

// screenSessions lists the Windows sessions of a machine, so that the page can offer a choice of which one to show. It
// asks the agent for the same list the management tab uses, which a machine that only allows screens may also give.
func (s *Server) screenSessions(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.vpsNotFound(w, r)
		return
	}
	if !vpsCanEdit(a, v) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of a linked panel is required")
		return
	}
	agent, err := s.Store.SecAgentOf(r.Context(), v.ID)
	if err != nil || s.SecOps == nil || !s.SecOps.Online(agent.ID) {
		s.writeErr(w, r, http.StatusConflict, "agent_offline", "the machine's agent is not connected")
		return
	}
	if !slices.Contains(agent.Capabilities, secproto.CapRemote) {
		s.writeErr(w, r, http.StatusConflict, "screen_not_allowed", "this machine does not allow screen sharing")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	res, err := s.SecOps.Admin(ctx, agent.ID, secproto.AdminReq{Op: secproto.AdminSessions})
	switch {
	case err != nil:
		s.writeErr(w, r, http.StatusGatewayTimeout, "no_answer", "the machine did not answer in time")
	case !res.OK:
		s.writeErr(w, r, http.StatusConflict, "sessions_failed", res.Error)
	default:
		writeJSON(w, http.StatusOK, map[string]any{"data": res.Data})
	}
}
