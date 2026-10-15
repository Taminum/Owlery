package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/f2bhelper"
	"github.com/Taminum/RemnaScope/internal/safehttp"
	"github.com/Taminum/RemnaScope/internal/secproto"
	"github.com/Taminum/RemnaScope/internal/store"
)

// commandTTL is how long the agent has, from receiving a command, to start it, and how long the server waits
// for the answer before it calls the outcome unknown.
const commandTTL = 30 * time.Second

var idemRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// manageInfo tells the screen whether, and if not why not, a ban or unban can be sent right now.
type manageInfo struct {
	Allowed bool   `json:"allowed"` // the caller holds security.fail2ban.manage (the owner, for now)
	Ready   bool   `json:"ready"`   // the agent can take a command at this moment
	Reason  string `json:"reason,omitempty"`
}

// canManageFail2ban is the permission "security.fail2ban.manage". It belongs to the owner alone; a role on
// a panel does not carry it, because a ban is a change on a server, not a view of one.
func canManageFail2ban(a auth.Actor) bool { return a.IsOwner }

// banReadiness checks everything that can be known before sending: an agent that is connected, that
// announced the capability, and a fresh, complete read of Fail2ban to take the jail names from. It returns
// the jail names as of that read.
func (s *Server) banReadiness(ctx context.Context, a auth.Actor, vpsID string) (ag store.SecAgent, jails []string, reason string) {
	ag, err := s.Store.SecAgentOf(ctx, vpsID)
	if err != nil {
		return ag, nil, "no_agent"
	}
	if s.SecOps == nil || !s.SecOps.Online(ag.ID) {
		return ag, nil, "agent_offline"
	}
	if !slices.Contains(ag.Capabilities, secproto.CapFail2banBan) {
		return ag, nil, "no_capability"
	}
	states, err := s.Store.SnapshotStates(ctx, a.Scope(), vpsID)
	if err != nil {
		return ag, nil, "state_stale"
	}
	for _, st := range states {
		if st.Category != secproto.CatFail2ban {
			continue
		}
		if st.Status != secproto.StatusOK || s.Now().Sub(st.ReceivedAt) > secproto.StaleAfter {
			return ag, nil, "state_stale"
		}
		var f secproto.Fail2ban
		if json.Unmarshal(st.Data, &f) != nil {
			return ag, nil, "state_stale"
		}
		for _, j := range f.Jails {
			jails = append(jails, j.Name)
		}
		return ag, jails, ""
	}
	return ag, nil, "state_stale"
}

func (s *Server) manageFor(ctx context.Context, a auth.Actor, vpsID string) *manageInfo {
	m := &manageInfo{Allowed: canManageFail2ban(a)}
	if !m.Allowed {
		m.Reason = "not_owner"
		return m
	}
	if _, _, why := s.banReadiness(ctx, a, vpsID); why != "" {
		m.Reason = why
	} else {
		m.Ready = true
	}
	return m
}

// riskReasons lists why banning this address deserves a second look. They are warnings, not refusals: the
// owner may confirm them.
func (s *Server) riskReasons(r *http.Request, v store.VPS, ip netip.Addr) []string {
	var out []string
	if mine := s.clientIP(r); mine.IsValid() && mine.Unmap() == ip {
		out = append(out, "own_ip") // the address this request came from: banning it can lock the owner out
	}
	if !safehttp.PublicAddr(ip) {
		out = append(out, "private_address")
	}
	for _, ad := range v.Addresses {
		if x, err := netip.ParseAddr(ad.Address); err == nil && x.Unmap() == ip {
			out = append(out, "server_address")
		}
	}
	return out
}

type cmdOut struct {
	store.SecCommand
	Final bool `json:"final"` // nothing more will change in this command except a later settling of "unknown"
}

func cmdView(c store.SecCommand) cmdOut { return cmdOut{SecCommand: c, Final: c.State != "pending"} }

// fail2banCommand is POST /vps/{id}/fail2ban/{ban|unban}.
func (s *Server) fail2banCommand(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.visibleVPS(w, r, a)
	if !ok {
		return
	}
	if !canManageFail2ban(a) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can ban or unban")
		return
	}
	action := r.PathValue("action")
	if action != secproto.OpBan && action != secproto.OpUnban {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "unknown action")
		return
	}
	var in struct {
		Jail            string `json:"jail"`
		IP              string `json:"ip"`
		IdempotencyKey  string `json:"idempotency_key"`
		AcknowledgeRisk bool   `json:"acknowledge_risk"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	bad := func(status int, code, msg string) { s.writeErr(w, r, status, code, msg) }
	if !idemRe.MatchString(in.IdempotencyKey) {
		bad(http.StatusUnprocessableEntity, "invalid_idempotency_key", "idempotency_key must be 8 to 64 letters, digits, - or _")
		return
	}
	if !f2bhelper.ValidJail(in.Jail) {
		bad(http.StatusUnprocessableEntity, "invalid_jail", "invalid jail name")
		return
	}
	ip, code := f2bhelper.ParseIP(in.IP)
	switch code {
	case f2bhelper.CodeBadRequest:
		bad(http.StatusUnprocessableEntity, "invalid_ip", "ip must be one IPv4 or IPv6 address")
		return
	case f2bhelper.CodeProtectedIP:
		bad(http.StatusUnprocessableEntity, "protected_address", "this address cannot be banned: loopback, unspecified, multicast and broadcast are refused")
		return
	}
	if !s.cmdLimit.Allow(v.ID) {
		w.Header().Set("Retry-After", "10")
		bad(http.StatusTooManyRequests, "rate_limited", "too many commands for this server")
		return
	}

	// A repeat of a request already recorded answers with it and sends nothing: that is what makes a retry safe.
	ag, jails, why := s.banReadiness(r.Context(), a, v.ID)
	if why != "" {
		if prev, err := s.Store.CreateCommandLookup(r.Context(), a.Scope(), v.ID, in.IdempotencyKey); err == nil {
			writeJSON(w, http.StatusOK, map[string]any{"command": cmdView(prev), "repeated": true})
			return
		}
		bad(http.StatusConflict, why, "the command cannot be sent now: "+why)
		return
	}
	if !slices.Contains(jails, in.Jail) {
		bad(http.StatusUnprocessableEntity, "unknown_jail", "this jail is not in the last state read from the server")
		return
	}
	if risks := s.riskReasons(r, v, ip); len(risks) > 0 && !in.AcknowledgeRisk {
		s.writeErrDetails(w, r, http.StatusConflict, "risk", "this address needs an explicit confirmation", map[string]any{"reasons": risks})
		return
	}

	now := s.Now().UTC()
	cmd, created, err := s.Store.CreateCommand(r.Context(), a.Scope(), v.ID, store.CommandInput{Action: action, Jail: in.Jail, IP: ip.String(),
		IdempotencyKey: in.IdempotencyKey, RequestID: reqID(r.Context()), ActorID: a.AccountID, TTL: commandTTL}, now)
	switch {
	case errors.Is(err, store.ErrIdempotencyMismatch):
		bad(http.StatusConflict, "idempotency_conflict", "this idempotency_key was used for a different command")
		return
	case errors.Is(err, store.ErrNotFound):
		s.vpsNotFound(w, r)
		return
	case err != nil:
		bad(http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if !created {
		writeJSON(w, http.StatusOK, map[string]any{"command": cmdView(cmd), "repeated": true})
		return
	}
	s.audit(r, a, "", "security.fail2ban.command", "vps", v.ID, map[string]any{"command_id": cmd.ID, "action": action, "jail": in.Jail, "ip": ip.String(),
		"acknowledged_risk": in.AcknowledgeRisk})

	// Delivered over the live connection now, or not at all.
	if err := s.SecOps.Send(r.Context(), ag.ID, secproto.Command{Type: "command", ID: cmd.ID, Op: action, Jail: in.Jail, IP: ip.String(), TTLSeconds: int(commandTTL / time.Second)}); err != nil {
		_ = s.Store.FailCommand(r.Context(), cmd.ID, "agent_offline", s.Now().UTC())
		s.audit(r, a, "", "security.fail2ban.command_result", "vps", v.ID, map[string]any{"command_id": cmd.ID, "state": "failed", "code": "agent_offline"})
		bad(http.StatusConflict, "agent_offline", "the agent is not connected; nothing was sent")
		return
	}
	_ = s.Store.MarkSent(r.Context(), cmd.ID, s.Now().UTC())
	cmd.SentAt = &now
	w.Header().Set("Location", "/api/v1/security/commands/"+cmd.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{"command": cmdView(cmd)})
}

func (s *Server) getCommand(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	c, err := s.Store.GetCommand(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "command not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"command": cmdView(c)})
}

func (s *Server) listCommands(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.visibleVPS(w, r, a)
	if !ok {
		return
	}
	limit := 20
	if x := r.URL.Query().Get("limit"); x != "" {
		n, err := strconv.Atoi(x)
		if err != nil || n < 1 || n > 100 {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_limit", "limit must be 1 to 100")
			return
		}
		limit = n
	}
	list, err := s.Store.ListCommands(r.Context(), a.Scope(), v.ID, limit)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	out := make([]cmdOut, 0, len(list))
	for _, c := range list {
		out = append(out, cmdView(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}
