// Package secops delivers a command to the security agent that holds a live connection. It sends and
// forgets: the answer comes back as a message on that connection and is stored by the ingest endpoint. A
// command for an agent that is not connected fails at once; nothing is kept to send later.
package secops

import (
	"context"
	"errors"
	"sync"
)

var ErrOffline = errors.New("secops: the agent is not connected")

type Hub struct {
	mu    sync.Mutex
	conns map[string]*link
	next  uint64
}

type link struct {
	gen  uint64
	send func(context.Context, any) error
}

func New() *Hub { return &Hub{conns: map[string]*link{}} }

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
