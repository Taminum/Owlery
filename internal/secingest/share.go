package secingest

import (
	"context"
	"slices"
	"time"

	"github.com/coder/websocket"

	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/store"
)

// blockAddFor is the message that passes an address on, with what is left of its block.
func blockAddFor(ip string, until *time.Time, now time.Time) (secproto.BlockAdd, bool) {
	m := secproto.BlockAdd{Type: "block_add", IP: ip}
	if until != nil {
		left := int(until.Sub(now).Seconds())
		if left <= 0 {
			return m, false
		}
		m.Seconds = left
	}
	return m, true
}

// shareNewBlocks passes what a machine blocked on to the other machines in the shared list. A block that came from
// another machine is not passed on again, and an address already on the list is passed on once.
func (s *Server) shareNewBlocks(ctx context.Context, agent store.SecAgent, w *secproto.Winsec) {
	if s.Ops == nil || w == nil || w.Block == nil || w.Block.Mode != secproto.BlockOn || len(w.Block.Active) == 0 {
		return
	}
	if !s.Store.ShareOn(ctx, agent.VPSID) {
		return
	}
	now := s.now()
	for _, e := range w.Block.Active {
		if e.Shared {
			continue
		}
		fresh, err := s.Store.ShareBlock(ctx, agent.VPSID, e.IP, e.Since, e.Until)
		if err != nil || !fresh {
			continue
		}
		msg, ok := blockAddFor(e.IP, e.Until, now)
		if !ok {
			continue
		}
		peers, err := s.Store.SharePeers(ctx, agent.VPSID)
		if err != nil {
			continue
		}
		for _, vid := range peers {
			peer, err := s.Store.SecAgentOf(ctx, vid)
			if err != nil || !slices.Contains(peer.Capabilities, secproto.CapBlockShare) || !s.Ops.Online(peer.ID) {
				continue
			}
			sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = s.Ops.Send(sctx, peer.ID, msg)
			cancel()
		}
	}
}

// sendSharedBlocks catches a machine that has just connected up with the blocks made while it was away.
func (s *Server) sendSharedBlocks(ctx context.Context, c *websocket.Conn, agent store.SecAgent) {
	if !s.Store.ShareOn(ctx, agent.VPSID) {
		return
	}
	list, err := s.Store.ActiveSharedBlocks(ctx, agent.VPSID)
	if err != nil {
		return
	}
	now := s.now()
	for _, b := range list {
		if msg, ok := blockAddFor(b.IP, b.Until, now); ok {
			if send(ctx, c, msg) != nil {
				return
			}
		}
	}
}
