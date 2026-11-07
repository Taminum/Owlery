package httpapi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/secops"
	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/store"
)

type wolView struct {
	Enabled       bool              `json:"enabled"`
	MAC           string            `json:"mac,omitempty"`
	NICs          []secproto.WolNIC `json:"nics"`
	MachineOnline bool              `json:"machine_online"` // the machine's own agent is connected, so it is on
	CanAsk        bool              `json:"can_ask"`        // the machine's agent can name its network cards (a current version)
	Helpers       int               `json:"helpers"`        // other machines in the same network that are on and can send the packet
	CanEdit       bool              `json:"can_edit"`
}

func (s *Server) wolViewOf(r *http.Request, a auth.Actor, v store.VPS) (wolView, error) {
	out := wolView{NICs: []secproto.WolNIC{}, CanEdit: vpsCanEdit(a, v)}
	if t, ok, err := s.Store.GetWol(r.Context(), v.ID); err != nil {
		return out, err
	} else if ok {
		out.Enabled, out.MAC = true, t.MAC
		if t.NICs != nil {
			out.NICs = t.NICs
		}
	}
	if agent, err := s.Store.SecAgentOf(r.Context(), v.ID); err == nil {
		out.MachineOnline = s.SecOps != nil && s.SecOps.Online(agent.ID)
		out.CanAsk = slices.Contains(agent.Capabilities, secproto.CapWol)
	}
	if s.SecOps != nil {
		hs, err := s.wolHelpers(r.Context(), v.ID)
		if err != nil {
			return out, err
		}
		out.Helpers = len(hs)
	}
	return out, nil
}

// wolHelpers lists the connected agents of other machines in the same network that know how to send the packet.
func (s *Server) wolHelpers(ctx context.Context, vpsID string) ([]store.SecAgent, error) {
	all, err := s.Store.WolNeighbors(ctx, vpsID)
	if err != nil {
		return nil, err
	}
	var out []store.SecAgent
	for _, n := range all {
		if s.SecOps.Online(n.ID) && slices.Contains(n.Capabilities, secproto.CapWol) {
			out = append(out, n)
		}
	}
	return out, nil
}

func (s *Server) getWol(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.vpsNotFound(w, r)
		return
	}
	out, err := s.wolViewOf(r, a, v)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// putWol turns Wake-on-LAN on or off for a machine. Turning it on asks the machine's own agent to name its network cards, which is
// the only time a hardware address reaches the server; turning it off forgets the address.
func (s *Server) putWol(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
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
		Enabled bool   `json:"enabled"`
		MAC     string `json:"mac"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if !in.Enabled {
		if err := s.Store.ClearWol(r.Context(), v.ID); err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		s.audit(r, a, "", "wol.off", "server", v.ID, map[string]any{"name": v.Name})
	} else {
		agent, err := s.Store.SecAgentOf(r.Context(), v.ID)
		if err != nil || s.SecOps == nil || !s.SecOps.Online(agent.ID) {
			s.writeErr(w, r, http.StatusConflict, "agent_offline", "the machine must be on and its agent connected to turn this on")
			return
		}
		if !slices.Contains(agent.Capabilities, secproto.CapWol) {
			s.writeErr(w, r, http.StatusConflict, "agent_too_old", "the agent of this machine must be updated first")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		res, err := s.SecOps.Wol(ctx, agent.ID, secproto.WolReq{Op: secproto.WolReport})
		switch {
		case errors.Is(err, secops.ErrOffline):
			s.writeErr(w, r, http.StatusConflict, "agent_offline", "the machine's agent is not connected")
			return
		case err != nil:
			s.writeErr(w, r, http.StatusGatewayTimeout, "no_answer", "the machine did not answer in time")
			return
		case !res.OK || len(res.NICs) == 0:
			s.writeErr(w, r, http.StatusConflict, "no_nic", "the machine has no network card that can wake it")
			return
		}
		want := strings.ToLower(strings.TrimSpace(in.MAC))
		if want == "" {
			if t, ok, _ := s.Store.GetWol(r.Context(), v.ID); ok {
				want = t.MAC
			}
		}
		mac := ""
		for _, n := range res.NICs {
			if strings.EqualFold(n.MAC, want) {
				mac = strings.ToLower(n.MAC)
			}
		}
		if mac == "" {
			if in.MAC != "" {
				s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_mac", "that address is not one of the machine's network cards")
				return
			}
			mac = strings.ToLower(res.NICs[0].MAC)
		}
		for i := range res.NICs {
			res.NICs[i].MAC = strings.ToLower(res.NICs[i].MAC)
		}
		if err := s.Store.SetWol(r.Context(), v.ID, mac, res.NICs); err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		s.audit(r, a, "", "wol.on", "server", v.ID, map[string]any{"name": v.Name})
	}
	out, err := s.wolViewOf(r, a, v)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// wakeMachine asks a neighbour in the same network to broadcast the packet for this machine.
func (s *Server) wakeMachine(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.vpsNotFound(w, r)
		return
	}
	if !vpsCanEdit(a, v) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of a linked panel is required")
		return
	}
	t, ok, err := s.Store.GetWol(r.Context(), v.ID)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if !ok {
		s.writeErr(w, r, http.StatusConflict, "wol_off", "Wake-on-LAN is not turned on for this machine")
		return
	}
	if agent, err := s.Store.SecAgentOf(r.Context(), v.ID); err == nil && s.SecOps != nil && s.SecOps.Online(agent.ID) {
		s.writeErr(w, r, http.StatusConflict, "already_on", "the machine is already on")
		return
	}
	if s.SecOps == nil {
		s.writeErr(w, r, http.StatusConflict, "no_helper", "no machine in the same network is on")
		return
	}
	helpers, err := s.wolHelpers(r.Context(), v.ID)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if len(helpers) == 0 {
		s.writeErr(w, r, http.StatusConflict, "no_helper", "no other machine in the same network is on to send the signal")
		return
	}
	s.audit(r, a, "", "wol.wake", "server", v.ID, map[string]any{"name": v.Name})
	for _, h := range helpers {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		res, err := s.SecOps.Wol(ctx, h.ID, secproto.WolReq{Op: secproto.WolSend, MAC: t.MAC})
		cancel()
		if err == nil && res.OK {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sent": res.Sent})
			return
		}
	}
	s.writeErr(w, r, http.StatusBadGateway, "not_sent", "no machine managed to send the signal")
}
