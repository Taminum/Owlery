package httpapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/keenetic"
	"github.com/Taminum/Owlery/internal/netdev"
	"github.com/Taminum/Owlery/internal/store"
)

var forwardRef = regexp.MustCompile(`^[0-9a-fA-F]{1,64}$`)

// routerClient opens the password kept for a router that is asked and returns a client for it.
func (s *Server) routerClient(w http.ResponseWriter, r *http.Request, id string) (*keenetic.Client, *store.PullDevice, bool) {
	if s.Ring == nil {
		s.writeErr(w, r, http.StatusServiceUnavailable, "no_keys", "no master key is configured")
		return nil, nil, false
	}
	devs, err := s.Store.PullDevices(r.Context())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return nil, nil, false
	}
	var dev *store.PullDevice
	for i := range devs {
		if devs[i].ID == id {
			dev = &devs[i]
		}
	}
	if dev == nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such router that is asked for its state")
		return nil, nil, false
	}
	raw, err := s.Ring.Open(store.NetPullAAD(dev.ID), dev.Sealed)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return nil, nil, false
	}
	password := string(raw)
	for i := range raw {
		raw[i] = 0
	}
	c, err := s.newKeenetic(dev.URL, dev.Login, password)
	if err != nil {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_url", "the address of the router is not usable")
		return nil, nil, false
	}
	return c, dev, true
}

// routerWriteError answers for a failed change, saying why in a word the page can explain.
func (s *Server) routerWriteError(w http.ResponseWriter, r *http.Request, err error) {
	switch keenetic.Code(err) {
	case "forbidden", "rejected", "unknown_host", "port_taken", "missing", "auth", "unreachable":
		code := keenetic.Code(err)
		if code == "auth" || code == "unreachable" {
			code = "router_" + code
		}
		status := http.StatusUnprocessableEntity
		if code == "missing" {
			status = http.StatusNotFound
		}
		s.writeErr(w, r, status, code, "the router could not make the change: "+keenetic.Code(err))
	default:
		s.writeErr(w, r, http.StatusBadGateway, "router_unexpected", "the router answered with something unexpected")
	}
}

// refreshRouter reads the router again right after a change so the page shows it at once. A forward the owner has just made is
// theirs, so it is marked as known before the reading is saved and no alert is opened for it.
func (s *Server) refreshRouter(ctx context.Context, c *keenetic.Client, dev *store.PullDevice, added *keenetic.ForwardSpec) {
	rep, err := c.Poll(ctx)
	if err != nil {
		return
	}
	if added != nil {
		for _, n := range rep.Nat {
			if n.Chain == "dstnat" && n.DstPort == strconv.Itoa(added.Port) && strings.HasPrefix(n.Action, "forward "+added.Protocol) {
				_ = s.Store.AllowForward(ctx, dev.ID, n)
			}
		}
	}
	_ = s.Store.SaveNetReport(ctx, dev.ID, rep, time.Now().UTC())
}

// addForward opens a port on a Keenetic that is asked.
func (s *Server) addForward(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	var in struct {
		Protocol string `json:"protocol"`
		Port     int    `json:"port"`
		ToAddr   string `json:"to_addr"`
		ToPort   int    `json:"to_port"`
		Comment  string `json:"comment"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	ip := net.ParseIP(strings.TrimSpace(in.ToAddr))
	if (in.Protocol != "tcp" && in.Protocol != "udp") || in.Port < 1 || in.Port > 65535 || in.ToPort < 0 || in.ToPort > 65535 || ip == nil || !ip.IsPrivate() || len(in.Comment) > 80 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_forward", "a protocol (tcp or udp), a port from 1 to 65535 and the home-network address of a device are required")
		return
	}
	c, dev, ok := s.routerClient(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	spec := keenetic.ForwardSpec{Protocol: in.Protocol, Port: in.Port, ToPort: in.ToPort, ToIP: ip.String(), Comment: netdev.Clean(in.Comment, 80)}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	if err := c.AddForward(ctx, spec); err != nil {
		s.audit(r, a, "", "netdevice.forward_add_failed", "netdevice", dev.ID, map[string]any{"port": in.Port, "protocol": in.Protocol, "to": spec.ToIP, "why": keenetic.Code(err)})
		s.routerWriteError(w, r, err)
		return
	}
	s.audit(r, a, "", "netdevice.forward_add", "netdevice", dev.ID, map[string]any{"port": in.Port, "protocol": in.Protocol, "to": spec.ToIP, "to_port": in.ToPort, "comment": spec.Comment})
	s.refreshRouter(ctx, c, dev, &spec)
	w.WriteHeader(http.StatusNoContent)
}

// removeForward takes a static forward away from a Keenetic that is asked.
func (s *Server) removeForward(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	ref := r.PathValue("ref")
	if !forwardRef.MatchString(ref) {
		s.writeErr(w, r, http.StatusNotFound, "missing", "no such forward")
		return
	}
	c, dev, ok := s.routerClient(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	if err := c.DeleteForward(ctx, ref); err != nil {
		s.audit(r, a, "", "netdevice.forward_remove_failed", "netdevice", dev.ID, map[string]any{"ref": ref, "why": keenetic.Code(err)})
		if errors.Is(err, keenetic.ErrMissing) {
			s.refreshRouter(ctx, c, dev, nil)
		}
		s.routerWriteError(w, r, err)
		return
	}
	s.audit(r, a, "", "netdevice.forward_remove", "netdevice", dev.ID, map[string]any{"ref": ref})
	s.refreshRouter(ctx, c, dev, nil)
	w.WriteHeader(http.StatusNoContent)
}
