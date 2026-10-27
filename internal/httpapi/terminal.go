package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/store"
)

// maxRecordBytes caps one recording, so that a session pouring output for days cannot fill the disk.
const maxRecordBytes = 50 << 20

// Close codes the terminal page explains to the person.
const (
	termNoAgent  = 4001 // the machine has no agent connected
	termNotAllow = 4002 // the machine does not allow a terminal
	termNoAnswer = 4003 // the agent was asked and did not connect back
)

// terminal opens a terminal on a machine and relays it between the browser and the machine's agent. The agent
// connects back for the session on its own connection; what the machine prints is written to a recording as it
// arrives, and opening and closing are in the audit log.
func (s *Server) terminal(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
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
	cols, _ := strconv.Atoi(r.URL.Query().Get("cols"))
	rows, _ := strconv.Atoi(r.URL.Query().Get("rows"))
	b, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer b.CloseNow()
	b.SetReadLimit(64 << 10)
	ctx := r.Context()

	agent, err := s.Store.SecAgentOf(ctx, v.ID)
	if err != nil || s.SecOps == nil || !s.SecOps.Online(agent.ID) {
		b.Close(termNoAgent, "the machine's agent is not connected")
		return
	}
	if !slices.Contains(agent.Capabilities, secproto.CapShell) {
		b.Close(termNotAllow, "this machine does not allow a terminal")
		return
	}
	octx, cancel := context.WithTimeout(ctx, 20*time.Second)
	m, release, err := s.SecOps.OpenShell(octx, agent.ID, cols, rows)
	cancel()
	if err != nil {
		b.Close(termNoAnswer, "the machine did not open a terminal")
		return
	}
	defer release()
	defer m.CloseNow()

	started := s.Now().UTC()
	rec := s.openRecord(v.ID, started)
	recName := ""
	if rec != nil {
		recName = filepath.Base(rec.Name())
		defer rec.Close()
	}
	s.audit(r, a, "", "terminal.open", "server", v.ID, map[string]any{"name": v.Name, "record": recName})
	var out, in atomic.Int64

	ctx, stop := context.WithCancel(ctx)
	defer stop()
	// The machine to the browser, and to the recording.
	go func() {
		defer stop()
		capped := false
		for {
			typ, data, err := m.Read(ctx)
			if err != nil {
				return
			}
			out.Add(int64(len(data)))
			if rec != nil && !capped {
				if out.Load() > maxRecordBytes {
					_, _ = rec.WriteString("\r\n[Owlery: the recording stops here, it reached 50 MB; the session goes on]\r\n")
					capped = true
				} else {
					_, _ = rec.Write(data)
				}
			}
			if b.Write(ctx, typ, data) != nil {
				return
			}
		}
	}()
	// The browser to the machine: keystrokes (binary) and window sizes (text).
	for {
		typ, data, err := b.Read(ctx)
		if err != nil {
			break
		}
		if typ == websocket.MessageBinary {
			in.Add(int64(len(data)))
		}
		if m.Write(ctx, typ, data) != nil {
			break
		}
	}
	stop()
	m.Close(websocket.StatusNormalClosure, "")
	b.Close(websocket.StatusNormalClosure, "")
	s.audit(r, a, "", "terminal.close", "server", v.ID, map[string]any{"name": v.Name, "record": recName,
		"seconds": int(s.Now().UTC().Sub(started).Seconds()), "bytes_out": out.Load(), "bytes_in": in.Load()})
}

// openRecord starts the recording of a session: a file per session under the server's directory, created before the
// shell prints anything. No directory configured, or one that cannot be written: the session is not recorded.
func (s *Server) openRecord(vpsID string, at time.Time) *os.File {
	if s.RecordsDir == "" {
		return nil
	}
	dir := filepath.Join(s.RecordsDir, vpsID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.Log.Error("terminal recording", "err", err)
		return nil
	}
	f, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("%s.log", at.Format("20060102-150405"))), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		s.Log.Error("terminal recording", "err", err)
		return nil
	}
	return f
}
