// Package awgops carries the two management commands (add a device, revoke a device) from the API to an
// AmneziaWG agent over the connection that agent already holds, and carries the answer back.
//
// Nothing here executes anything: it only delivers a command to the agent that owns the instance and
// waits for that agent's reply. A reply is accepted only from the agent the command was sent to.
package awgops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/Taminum/Owlery/internal/ingestproto"
)

var (
	ErrOffline = errors.New("awgops: the agent is not connected")
	ErrTimeout = errors.New("awgops: the agent did not answer in time")
)

type Hub struct {
	mu    sync.Mutex
	conns map[string]*link
	pend  map[string]*pending
	next  uint64
	admin map[string]bool // agents whose last snapshot said the host can create and remove containers
}

type link struct {
	gen  uint64
	send func(context.Context, any) error
}

type pending struct {
	agent string
	ch    chan ingestproto.AWGOpResult
}

func New() *Hub {
	return &Hub{conns: map[string]*link{}, pend: map[string]*pending{}, admin: map[string]bool{}}
}

// Register makes an agent's connection available for commands. The returned function removes it (and
// only it: a newer connection of the same agent stays registered).
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

// Do sends a command and waits for the answer (or ctx).
func (h *Hub) Do(ctx context.Context, agentID string, op ingestproto.AWGOp) (ingestproto.AWGOpResult, error) {
	h.mu.Lock()
	l := h.conns[agentID]
	if l == nil {
		h.mu.Unlock()
		return ingestproto.AWGOpResult{}, ErrOffline
	}
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	op.Type, op.ID = "awg_op", hex.EncodeToString(b)
	p := &pending{agent: agentID, ch: make(chan ingestproto.AWGOpResult, 1)}
	h.pend[op.ID] = p
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.pend, op.ID)
		h.mu.Unlock()
	}()
	if err := l.send(ctx, op); err != nil {
		return ingestproto.AWGOpResult{}, ErrOffline
	}
	select {
	case r := <-p.ch:
		return r, nil
	case <-ctx.Done():
		return ingestproto.AWGOpResult{}, ErrTimeout
	}
}

// Deliver hands an agent's answer to whoever is waiting for it. An answer for an unknown command, or
// from an agent other than the one asked, is dropped.
func (h *Hub) Deliver(agentID string, r ingestproto.AWGOpResult) {
	h.mu.Lock()
	p := h.pend[r.ID]
	h.mu.Unlock()
	if p == nil || p.agent != agentID {
		return
	}
	select {
	case p.ch <- r:
	default:
	}
}

// SetContainerAdmin records what an agent's latest snapshot said about container administration.
func (h *Hub) SetContainerAdmin(agentID string, v bool) {
	h.mu.Lock()
	h.admin[agentID] = v
	h.mu.Unlock()
}

// ContainerAdmin reports whether the agent's host has opted in. It is what the host said, not a promise.
func (h *Hub) ContainerAdmin(agentID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.admin[agentID]
}
