// Package secingest is the WebSocket endpoint security agents report to. It is separate from the Xray
// agents' endpoint: its own credential, its own protocol, and no message that flows toward the agent
// except acknowledgements.
package secingest

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/secops"
	"github.com/Taminum/RemnaScope/internal/secproto"
	"github.com/Taminum/RemnaScope/internal/store"
)

type Server struct {
	Store    *store.Store
	Log      *slog.Logger
	Limiter  *auth.Limiter // connection attempts per client address
	ClientIP func(*http.Request) netip.Addr
	// IdleTimeout is how long a connection may stay silent. Agents report every 30 seconds.
	IdleTimeout time.Duration
	// IntervalSeconds is what the agent is told to use between reports.
	IntervalSeconds int
	Now             func() time.Time
	// Ops carries commands to agents that hold a connection and is where an agent's answer comes back (nil = no commands).
	Ops *secops.Hub
}

var dummy = sha256.Sum256([]byte("remnascope-no-such-security-agent"))

func (s *Server) idle() time.Duration {
	if s.IdleTimeout > 0 {
		return s.IdleTimeout
	}
	return 3 * time.Minute
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Origin") != "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if s.Limiter != nil && s.ClientIP != nil && !s.Limiter.Allow(s.ClientIP(r).String()) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many connection attempts", http.StatusTooManyRequests)
			return
		}
		agent, ok := s.authenticate(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="remnascope-security-agent"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		defer c.CloseNow()
		c.SetReadLimit(secproto.MaxMessageBytes)
		s.session(r.Context(), c, agent)
	})
}

// authenticate expects "Authorization: Bearer <agent id>.<secret>".
func (s *Server) authenticate(r *http.Request) (store.SecAgent, bool) {
	h, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	id, secret, found := strings.Cut(h, ".")
	if !ok || !found || id == "" || len(secret) < 20 || len(secret) > 200 {
		subtle.ConstantTimeCompare(dummy[:], dummy[:])
		return store.SecAgent{}, false
	}
	agent, want, err := s.Store.SecAgentForAuth(r.Context(), id)
	got := store.HashAgentSecret(secret)
	if err != nil {
		subtle.ConstantTimeCompare(got, dummy[:])
		return store.SecAgent{}, false
	}
	if subtle.ConstantTimeCompare(got, want) != 1 || agent.Status == "revoked" {
		return store.SecAgent{}, false
	}
	return agent, true
}

func send(ctx context.Context, c *websocket.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return c.Write(ctx, websocket.MessageText, b)
}

func closeWith(c *websocket.Conn, code int, reason string) {
	_ = c.Close(websocket.StatusCode(code), reason)
}

var knownCaps = map[string]bool{"fail2ban_read": true, "socket_read": true, "firewall_read": true, secproto.CapFail2banBan: true, secproto.CapProbe: true}

func (s *Server) session(ctx context.Context, c *websocket.Conn, agent store.SecAgent) {
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	_, data, err := c.Read(hctx)
	cancel()
	if err != nil {
		return
	}
	var hello secproto.Hello
	if json.Unmarshal(data, &hello) != nil || hello.Type != "hello" || hello.ProtoVersion != secproto.Version ||
		hello.Epoch == "" || len(hello.Epoch) > 64 || len(hello.AgentVersion) > 64 || len(hello.Hostname) > 253 || len(hello.Capabilities) > 12 {
		_ = send(ctx, c, secproto.Error{Type: "error", Code: "bad_message"})
		closeWith(c, secproto.CloseProtocol, "bad hello")
		return
	}
	// Capabilities this server does not know are ignored, so a newer agent still connects.
	var caps []string
	for _, k := range hello.Capabilities {
		if knownCaps[k] {
			caps = append(caps, k)
		}
	}
	ack, err := s.Store.SecAgentHello(ctx, agent.ID, hello.Epoch, hello.AgentVersion, hello.Hostname, caps)
	if err != nil {
		closeWith(c, secproto.CloseRevoked, "revoked")
		return
	}
	interval := s.IntervalSeconds
	if interval <= 0 {
		interval = 30
	}
	if send(ctx, c, secproto.Welcome{Type: "welcome", AckSeq: ack, IntervalSeconds: interval}) != nil {
		return
	}
	if s.Ops != nil {
		defer s.Ops.Register(agent.ID, func(ctx context.Context, v any) error { return send(ctx, c, v) })()
	}
	s.log().Info("security agent connected", "agent", agent.ID, "vps", agent.VPSID, "ack_seq", ack)

	for {
		rctx, cancel := context.WithTimeout(ctx, s.idle())
		_, data, err := c.Read(rctx)
		cancel()
		if err != nil {
			return
		}
		var head struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(data, &head) != nil {
			_ = send(ctx, c, secproto.Error{Type: "error", Code: "bad_message"})
			closeWith(c, secproto.CloseProtocol, "bad message")
			return
		}
		switch head.Type {
		case "ping":
			if err := s.Store.TouchSecAgent(ctx, agent.ID); err != nil {
				closeWith(c, secproto.CloseRevoked, "revoked")
				return
			}
			if send(ctx, c, secproto.Pong{Type: "pong"}) != nil {
				return
			}
		case "snapshot":
			if !s.snapshot(ctx, c, agent, data) {
				return
			}
		case "command_result":
			s.commandResult(ctx, agent, data)
		case "probe_result":
			var r secproto.ProbeResult
			if len(data) <= 16<<10 && json.Unmarshal(data, &r) == nil && s.Ops != nil {
				s.Ops.Deliver(agent.ID, r)
			}
		default:
			_ = send(ctx, c, secproto.Error{Type: "error", Code: "bad_message"})
			closeWith(c, secproto.CloseProtocol, "unknown message")
			return
		}
	}
}

func (s *Server) snapshot(ctx context.Context, c *websocket.Conn, agent store.SecAgent, data []byte) bool {
	bad := func() bool {
		_ = send(ctx, c, secproto.Error{Type: "error", Code: "bad_snapshot"})
		closeWith(c, secproto.CloseProtocol, "bad snapshot")
		return false
	}
	var m secproto.Snapshot
	if err := json.Unmarshal(data, &m); err != nil || m.Seq <= 0 || !secproto.ValidCategory(m.Category) || !secproto.ValidStatus(m.Status) || m.ObservedAt.IsZero() {
		return bad()
	}
	now := s.now()
	// An observation time far from the server's clock is kept as it is, with the skew recorded; only an
	// absurd value is refused, because it would corrupt every ordering that uses it.
	if d := m.ObservedAt.Sub(now); d > 24*time.Hour || d < -24*time.Hour {
		return bad()
	}
	snap, canon, hash, err := store.ParseSnapshotData(m.Category, m.Status, m.Data)
	if err != nil {
		return bad()
	}
	res, err := s.Store.CommitSnapshot(ctx, agent.ID, m.Seq, m.Category, m.ObservedAt.UTC(), snap, canon, hash, now.UTC())
	switch {
	case errors.Is(err, store.ErrNotFound):
		closeWith(c, secproto.CloseRevoked, "revoked")
		return false
	case err != nil:
		s.log().Error("committing security snapshot", "agent", agent.ID)
		_ = c.Close(websocket.StatusInternalError, "try again")
		return false
	}
	return send(ctx, c, secproto.Ack{Type: "ack", AckSeq: res.AckSeq, Stored: res.Stored}) == nil
}

// commandResult stores an agent's answer to a command. A bad, late or foreign answer is dropped: it can
// only ever settle a command that is still pending and was sent to this very agent.
func (s *Server) commandResult(ctx context.Context, agent store.SecAgent, data []byte) {
	var r secproto.CommandResult
	if len(data) > 4096 || json.Unmarshal(data, &r) != nil || len(r.ID) > 64 || len(r.Code) > 64 {
		return
	}
	cmd, err := s.Store.CompleteCommand(ctx, agent.ID, r, s.now().UTC())
	if err != nil {
		return
	}
	// The outcome joins the audit trail next to the intent that was recorded when it was requested.
	meta := map[string]any{"command_id": cmd.ID, "action": cmd.Action, "jail": cmd.Jail, "ip": cmd.IP, "state": cmd.State, "verified": cmd.Verified}
	if cmd.ResultCode != nil {
		meta["code"] = *cmd.ResultCode
	}
	if err := s.Store.WriteAudit(ctx, store.AuditEntry{ActorName: "security agent", Action: "security.fail2ban.command_result", ObjectType: "vps", ObjectID: cmd.VPSID, Metadata: meta}); err != nil {
		s.log().Error("audit write failed", "command", cmd.ID)
	}
}
