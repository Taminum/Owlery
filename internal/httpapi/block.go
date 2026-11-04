package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/store"
)

// blockView is what the "Защита RDP" tab shows about one machine: how its address blocker is set up, what it has done,
// and whether it may block at all.
type blockView struct {
	Settings  store.BlockSettings `json:"settings"`
	State     *secproto.WinBlock  `json:"state"`     // what the agent last reported; nil until it reports one
	Supported bool                `json:"supported"` // a Windows agent that reads sign-ins is there
	CanBlock  bool                `json:"can_block"` // the machine was installed with -allow-block
	Online    bool                `json:"online"`
	CanEdit   bool                `json:"can_edit"`
}

func (s *Server) blockViewOf(ctx context.Context, a auth.Actor, v store.VPS) (blockView, error) {
	settings, err := s.Store.GetBlockSettings(ctx, v.ID)
	if err != nil {
		return blockView{}, err
	}
	out := blockView{Settings: settings, CanEdit: vpsCanEdit(a, v)}
	if states, err := s.Store.SnapshotStates(ctx, a.Scope(), v.ID); err == nil {
		for _, st := range states {
			if st.Category != secproto.CatWinsec || st.Status != secproto.StatusOK {
				continue
			}
			out.Supported = true
			var w secproto.Winsec
			if json.Unmarshal(st.Data, &w) == nil {
				out.State = w.Block
			}
		}
	}
	if agent, err := s.Store.SecAgentOf(ctx, v.ID); err == nil {
		out.CanBlock = slices.Contains(agent.Capabilities, secproto.CapBlock)
		out.Online = s.SecOps != nil && s.SecOps.Online(agent.ID)
	}
	return out, nil
}

func (s *Server) getBlock(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.vpsNotFound(w, r)
		return
	}
	out, err := s.blockViewOf(r.Context(), a, v)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// putBlock saves the settings and tells the agent at once if it is connected; otherwise it is told when it connects.
func (s *Server) putBlock(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.vpsNotFound(w, r)
		return
	}
	if !vpsCanEdit(a, v) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of a linked panel is required")
		return
	}
	var in store.BlockSettings
	if !s.decode(w, r, &in) {
		return
	}
	in, err = store.CleanBlockSettings(in)
	if err != nil {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_settings", "the limit, the time or an address in the whitelist is not valid")
		return
	}
	if err := s.Store.PutBlockSettings(r.Context(), v.ID, in); err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "block.settings", "server", v.ID, map[string]any{"name": v.Name, "mode": in.Mode, "threshold": in.Threshold, "window_min": in.WindowMin, "ttl_hours": in.TTLHours, "whitelist": len(in.Whitelist)})
	if agent, err := s.Store.SecAgentOf(r.Context(), v.ID); err == nil && s.SecOps != nil && s.SecOps.Online(agent.ID) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		_ = s.SecOps.Send(ctx, agent.ID, in.Message())
	}
	out, err := s.blockViewOf(r.Context(), a, v)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// unblock lifts one block by hand. The agent leaves that address alone for a day afterwards.
func (s *Server) unblock(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
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
		IP string `json:"ip"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	ip, perr := netip.ParseAddr(in.IP)
	if perr != nil {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_ip", "not an address")
		return
	}
	agent, err := s.Store.SecAgentOf(r.Context(), v.ID)
	if err != nil || s.SecOps == nil || !s.SecOps.Online(agent.ID) {
		s.writeErr(w, r, http.StatusConflict, "agent_offline", "the machine's agent is not connected")
		return
	}
	s.audit(r, a, "", "block.unblock", "server", v.ID, map[string]any{"name": v.Name, "ip": ip.String()})
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.SecOps.Send(ctx, agent.ID, secproto.BlockUnblock{Type: "block_unblock", IP: ip.String()}); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			s.writeErr(w, r, http.StatusGatewayTimeout, "no_answer", "the machine did not answer in time")
		} else {
			s.writeErr(w, r, http.StatusConflict, "agent_offline", "the machine's agent is not connected")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
