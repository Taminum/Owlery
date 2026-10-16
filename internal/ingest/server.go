// Package ingest is the WebSocket endpoint agents push access-log lines to.
package ingest

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/awgops"
	"github.com/Taminum/RemnaScope/internal/ingestproto"
	"github.com/Taminum/RemnaScope/internal/live"
	"github.com/Taminum/RemnaScope/internal/routerlog"
	"github.com/Taminum/RemnaScope/internal/store"
	"github.com/Taminum/RemnaScope/internal/xraylog"
)

type Server struct {
	Store    *store.Store
	Log      *slog.Logger
	Limiter  *auth.Limiter // connection attempts per client address
	ClientIP func(*http.Request) netip.Addr
	// Live receives the router agents' present-moment snapshots (nil = ignored).
	Live *live.Hub
	// Ops carries the add/revoke commands to AmneziaWG agents and their answers back (nil = off).
	Ops *awgops.Hub
	// IdleTimeout is how long a connection may stay silent. Agents ping well inside it.
	IdleTimeout time.Duration
}

var reasonRe = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)

func (s *Server) idle() time.Duration {
	if s.IdleTimeout > 0 {
		return s.IdleTimeout
	}
	return 90 * time.Second
}

// dummy is compared against when the agent does not exist, so "unknown agent" and "wrong
// secret" take the same time and give the same answer.
var dummy = sha256.Sum256([]byte("remnascope-no-such-agent"))

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Agents are not browsers and send no Origin; a browser that does is trying to use
		// a visitor's session-less connection to talk to us, and is refused.
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
			w.Header().Set("WWW-Authenticate", `Bearer realm="remnascope-agent"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return // Accept already wrote the HTTP error
		}
		defer c.CloseNow()
		c.SetReadLimit(ingestproto.MaxMessageBytes)
		s.session(r.Context(), c, agent)
	})
}

// authenticate expects "Authorization: Bearer <agent id>.<secret>".
func (s *Server) authenticate(r *http.Request) (store.Agent, bool) {
	h, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	id, secret, found := strings.Cut(h, ".")
	if !ok || !found || id == "" || len(secret) < 20 || len(secret) > 200 {
		subtle.ConstantTimeCompare(dummy[:], dummy[:])
		return store.Agent{}, false
	}
	agent, want, err := s.Store.AgentForAuth(r.Context(), id)
	got := store.HashAgentSecret(secret)
	if err != nil {
		subtle.ConstantTimeCompare(got, dummy[:])
		return store.Agent{}, false
	}
	if subtle.ConstantTimeCompare(got, want) != 1 || agent.Status == "revoked" {
		return store.Agent{}, false
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

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Server) session(ctx context.Context, c *websocket.Conn, agent store.Agent) {
	// 1. hello
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	_, data, err := c.Read(hctx)
	cancel()
	if err != nil {
		return
	}
	var hello ingestproto.Hello
	if json.Unmarshal(data, &hello) != nil || hello.Type != "hello" || hello.ProtoVersion != ingestproto.Version ||
		hello.Epoch == "" || len(hello.Epoch) > 64 || len(hello.AgentVersion) > 64 || len(hello.SourceID) > 200 {
		_ = send(ctx, c, ingestproto.Error{Type: "error", Code: "bad_message"})
		closeWith(c, ingestproto.CloseProtocol, "bad hello")
		return
	}
	ack, err := s.Store.AgentHello(ctx, agent.ID, hello.Epoch, hello.AgentVersion, hello.SourceID)
	if err != nil {
		closeWith(c, ingestproto.CloseRevoked, "revoked")
		return
	}
	if err := send(ctx, c, ingestproto.Welcome{Type: "welcome", AckSeq: ack, MaxBatchLines: ingestproto.MaxBatchLines}); err != nil {
		return
	}
	if agent.Kind == "awg" && s.Ops != nil {
		defer s.Ops.Register(agent.ID, func(ctx context.Context, v any) error { return send(ctx, c, v) })()
	}
	s.log().Info("agent connected", "agent", agent.ID, "panel", agent.PanelID, "node", agent.NodeID, "ack_seq", ack)

	// 2. batches
	for {
		rctx, cancel := context.WithTimeout(ctx, s.idle())
		_, data, err := c.Read(rctx)
		cancel()
		if err != nil {
			if websocket.CloseStatus(err) == websocket.StatusMessageTooBig {
				return
			}
			return
		}
		var head struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(data, &head) != nil {
			_ = send(ctx, c, ingestproto.Error{Type: "error", Code: "bad_message"})
			closeWith(c, ingestproto.CloseProtocol, "bad message")
			return
		}
		switch head.Type {
		case "ping":
			var p ingestproto.Ping
			if json.Unmarshal(data, &p) != nil || p.SpoolBytes < 0 {
				closeWith(c, ingestproto.CloseProtocol, "bad ping")
				return
			}
			if err := s.Store.TouchAgent(ctx, agent.ID, p.SpoolBytes); err != nil {
				closeWith(c, ingestproto.CloseRevoked, "revoked")
				return
			}
			if send(ctx, c, ingestproto.Pong{Type: "pong"}) != nil {
				return
			}
		case "batch":
			if !s.batch(ctx, c, agent, data) {
				return
			}
		case "live":
			// Best effort and unanswered: a bad or unwanted snapshot is dropped, never an error.
			var f ingestproto.Live
			if agent.Kind == "router" && s.Live != nil && json.Unmarshal(data, &f) == nil {
				name := ""
				if agent.Name != nil {
					name = *agent.Name
				}
				s.Live.Put(live.Source{AgentID: agent.ID, PanelID: agent.PanelID, Name: name}, f)
			}
		case "awg_flows":
			// A window of the traffic sensor: best effort, unanswered, a bad one is dropped.
			var fr ingestproto.AWGFlows
			if agent.Kind == "awg" && len(data) <= ingestproto.MaxMessageBytes && json.Unmarshal(data, &fr) == nil {
				if err := s.Store.SaveAWGFlows(ctx, agent, fr, time.Now()); err != nil {
					s.log().Error("saving awg flows", "agent", agent.ID)
				}
			}
		case "awg_op_result":
			var res ingestproto.AWGOpResult
			if agent.Kind == "awg" && s.Ops != nil && len(data) <= ingestproto.MaxAWGFilesBytes+8192 && json.Unmarshal(data, &res) == nil {
				s.Ops.Deliver(agent.ID, res)
			}
		case "awg":
			// Same rules as "live": best effort, unanswered, a bad snapshot is dropped.
			var f ingestproto.AWG
			if agent.Kind == "awg" && json.Unmarshal(data, &f) == nil {
				if s.Ops != nil {
					s.Ops.SetContainerAdmin(agent.ID, f.ContainerAdmin)
				}
				if err := s.Store.SaveAWG(ctx, agent, f, time.Now()); err != nil {
					s.log().Error("saving awg snapshot", "agent", agent.ID)
				}
			}
		default:
			_ = send(ctx, c, ingestproto.Error{Type: "error", Code: "bad_message"})
			closeWith(c, ingestproto.CloseProtocol, "unknown message")
			return
		}
	}
}

// batch handles one batch and reports whether the session should continue.
func (s *Server) batch(ctx context.Context, c *websocket.Conn, agent store.Agent, data []byte) bool {
	var b ingestproto.Batch
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || b.BatchID == "" || len(b.BatchID) > 64 || len(b.Items) == 0 ||
		len(b.Items) > ingestproto.MaxBatchLines || b.SpoolBytes < 0 || b.Dropped < 0 || len(b.Gaps) > 20 {
		_ = send(ctx, c, ingestproto.Error{Type: "error", Code: "bad_batch"})
		closeWith(c, ingestproto.CloseProtocol, "bad batch")
		return false
	}
	lines := make([]store.Line, 0, len(b.Items))
	for i, it := range b.Items {
		if it.Seq <= 0 || len(it.Line) > ingestproto.MaxLineBytes || (i > 0 && it.Seq != b.Items[i-1].Seq+1) {
			_ = send(ctx, c, ingestproto.Error{Type: "error", Code: "bad_batch"})
			closeWith(c, ingestproto.CloseProtocol, "bad batch")
			return false
		}
		fp := sha256.Sum256([]byte(it.Line))
		l := store.Line{Seq: it.Seq, FP: fp[:]}
		if agent.Kind == "router" {
			if ev, err := routerlog.Parse(it.Line, time.Now()); err == nil {
				l.Device = &ev
			}
		} else if ev, err := xraylog.ParseLine(it.Line); err == nil {
			l.Event = &ev
		}
		lines = append(lines, l)
	}
	commit := store.Commit{AgentID: agent.ID, Lines: lines, Dropped: b.Dropped, SpoolBytes: b.SpoolBytes}
	for _, g := range b.Gaps {
		if !reasonRe.MatchString(g.Reason) || g.Lines < 0 {
			_ = send(ctx, c, ingestproto.Error{Type: "error", Code: "bad_batch"})
			closeWith(c, ingestproto.CloseProtocol, "bad gap")
			return false
		}
		commit.Gaps = append(commit.Gaps, store.GapReport{From: g.From, To: g.To, Lines: g.Lines, Reason: g.Reason})
	}

	res, err := s.Store.CommitBatch(ctx, commit)
	var gap *store.ErrSeqGap
	switch {
	case errors.As(err, &gap):
		_ = send(ctx, c, ingestproto.Error{Type: "error", Code: "seq_gap", ExpectedSeq: gap.Expected})
		closeWith(c, ingestproto.CloseSeqGap, "sequence gap")
		return false
	case errors.Is(err, store.ErrNotFound):
		closeWith(c, ingestproto.CloseRevoked, "revoked")
		return false
	case err != nil:
		s.log().Error("commit failed", "agent", agent.ID)
		_ = c.Close(websocket.StatusInternalError, "try again")
		return false
	}
	return send(ctx, c, ingestproto.Ack{Type: "ack", BatchID: b.BatchID, AckSeq: res.AckSeq,
		Accepted: res.Accepted, Duplicates: res.Duplicates, ParseErrors: res.ParseErrs}) == nil
}
