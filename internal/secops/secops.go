// Package secops delivers a command to the security agent that holds a live connection. It sends and
// forgets: the answer comes back as a message on that connection and is stored by the ingest endpoint. A
// command for an agent that is not connected fails at once; nothing is kept to send later.
package secops

import (
	"context"
	"errors"
	"sync"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/Taminum/Owlery/internal/secproto"
)

var ErrOffline = errors.New("secops: the agent is not connected")

type Hub struct {
	mu     sync.Mutex
	conns  map[string]*link
	next   uint64
	probes map[string]*probeWait
	shells map[string]*shellWait
}

type probeWait struct {
	agent string
	ch    chan secproto.ProbeResult
}

type link struct {
	gen  uint64
	send func(context.Context, any) error
}

func New() *Hub { return &Hub{conns: map[string]*link{}, probes: map[string]*probeWait{}} }

// Register makes an agent's connection available. The returned function removes it, and only it: a newer
// connection of the same agent stays.
func (h *Hub) Register(agentID string, send func(context.Context, any) error) func() {
	h.mu.Lock()
	h.next++
	l := &link{gen: h.next, send: send}
	h.conns[agentID] = l
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		if h.conns[agentID] == l {
			delete(h.conns, agentID)
		}
		h.mu.Unlock()
	}
}

func (h *Hub) Online(agentID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conns[agentID] != nil
}

// Send writes v to the agent's connection.
func (h *Hub) Send(ctx context.Context, agentID string, v any) error {
	h.mu.Lock()
	l := h.conns[agentID]
	h.mu.Unlock()
	if l == nil {
		return ErrOffline
	}
	if err := l.send(ctx, v); err != nil {
		return ErrOffline
	}
	return nil
}

// ErrNoAnswer means the agent was asked and did not answer in time or the connection went away.
var ErrNoAnswer = errors.New("secops: the agent did not answer the probe")

// Probe sends a probe to an agent and waits for its answer (or ctx). The ID is set here. Only the agent the
// probe was sent to can answer it.
func (h *Hub) Probe(ctx context.Context, agentID string, p secproto.Probe) (secproto.ProbeResult, error) {
	p.Type, p.ID = "probe", uuid.NewString()
	w := &probeWait{agent: agentID, ch: make(chan secproto.ProbeResult, 1)}
	h.mu.Lock()
	h.probes[p.ID] = w
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.probes, p.ID)
		h.mu.Unlock()
	}()
	if err := h.Send(ctx, agentID, p); err != nil {
		return secproto.ProbeResult{}, err
	}
	select {
	case r := <-w.ch:
		return r, nil
	case <-ctx.Done():
		return secproto.ProbeResult{}, ErrNoAnswer
	}
}

// Deliver hands an agent's answer to whoever is waiting for it. An answer nobody asked for, or one that
// comes from a different agent than the one asked, is dropped.
func (h *Hub) Deliver(agentID string, r secproto.ProbeResult) bool {
	h.mu.Lock()
	w := h.probes[r.ID]
	h.mu.Unlock()
	if w == nil || w.agent != agentID {
		return false
	}
	select {
	case w.ch <- r:
		return true
	default:
		return false
	}
}

// ErrNoShell means the agent was asked for a terminal and did not connect back in time: its machine does not allow
// one, or it could not reach Owlery.
var ErrNoShell = errors.New("secops: the terminal did not connect back")

type shellWait struct {
	agent string
	ch    chan *websocket.Conn
	done  chan struct{}
}

// OpenShell asks an agent for a terminal and waits for its connection back. Call release when the session is over:
// it lets the agent's side of the connection end.
func (h *Hub) OpenShell(ctx context.Context, agentID string, cols, rows int) (c *websocket.Conn, release func(), err error) {
	return h.openBack(ctx, agentID, func(id string) any { return secproto.ShellOpen{Type: "shell_open", ID: id, Cols: cols, Rows: rows} })
}

// OpenTunnel asks an agent for a tunnel to one local desktop port and waits for its connection back.
func (h *Hub) OpenTunnel(ctx context.Context, agentID string, port int) (c *websocket.Conn, release func(), err error) {
	return h.openBack(ctx, agentID, func(id string) any { return secproto.TunnelOpen{Type: "tunnel_open", ID: id, Port: port} })
}

// OpenRemote asks an agent for a session with its remote-control helper and waits for its connection back.
func (h *Hub) OpenRemote(ctx context.Context, agentID string) (c *websocket.Conn, release func(), err error) {
	return h.openBack(ctx, agentID, func(id string) any { return secproto.RemoteOpen{Type: "remote_open", ID: id} })
}

// openBack sends the request built for a fresh session ID and waits for the agent to connect back with that ID.
func (h *Hub) openBack(ctx context.Context, agentID string, msg func(id string) any) (c *websocket.Conn, release func(), err error) {
	id := uuid.NewString()
	w := &shellWait{agent: agentID, ch: make(chan *websocket.Conn, 1), done: make(chan struct{})}
	h.mu.Lock()
	if h.shells == nil {
		h.shells = map[string]*shellWait{}
	}
	h.shells[id] = w
	h.mu.Unlock()
	drop := func() {
		h.mu.Lock()
		delete(h.shells, id)
		h.mu.Unlock()
	}
	if err := h.Send(ctx, agentID, msg(id)); err != nil {
		drop()
		return nil, nil, err
	}
	select {
	case c := <-w.ch:
		drop()
		var once sync.Once
		return c, func() { once.Do(func() { close(w.done) }) }, nil
	case <-ctx.Done():
		drop()
		close(w.done)
		return nil, nil, ErrNoShell
	}
}

// AttachShell hands an agent's terminal connection to the session that asked for it and returns when that session is
// over. A connection nobody asked for, or from another agent, is refused (false).
func (h *Hub) AttachShell(agentID, id string, c *websocket.Conn) bool {
	h.mu.Lock()
	w := h.shells[id]
	if w == nil || w.agent != agentID {
		h.mu.Unlock()
		return false
	}
	delete(h.shells, id)
	h.mu.Unlock()
	select {
	case w.ch <- c:
	default:
		return false
	}
	<-w.done
	return true
}
