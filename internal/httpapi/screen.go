package httpapi

import (
	"context"
	"net/http"
	"slices"
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
	b.SetReadLimit(16 << 10)
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
	m, release, err := s.SecOps.OpenRemote(octx, agent.ID)
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
