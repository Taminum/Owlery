package httpapi

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/keenetic"
	"github.com/Taminum/Owlery/internal/netdev"
	"github.com/Taminum/Owlery/internal/store"
)

// routerAction runs one change on a Keenetic that is asked, for the owner only: it opens the router's own login, does the change,
// writes the journal (also when the router refuses), reads the router again and answers 204.
func (s *Server) routerAction(w http.ResponseWriter, r *http.Request, a auth.Actor, name string, detail map[string]any, change func(context.Context, *keenetic.Client) error, known func(netdev.NatRule) bool) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	c, dev, ok := s.routerClient(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	if err := change(ctx, c); err != nil {
		detail["why"] = keenetic.Code(err)
		s.audit(r, a, "", name+"_failed", "netdevice", dev.ID, detail)
		s.routerWriteError(w, r, err)
		return
	}
	s.audit(r, a, "", name, "netdevice", dev.ID, detail)
	s.refreshRouter(ctx, c, dev, known)
	w.WriteHeader(http.StatusNoContent)
}

func macParam(w http.ResponseWriter, s *Server, r *http.Request) (string, bool) {
	hw, err := net.ParseMAC(strings.TrimSpace(r.PathValue("mac")))
	if err != nil || len(hw) != 6 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "unknown_host", "not a device address")
		return "", false
	}
	return strings.ToUpper(hw.String()), true
}

// blockClient refuses a device at the router (POST) or lets it back (DELETE).
func (s *Server) blockClient(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	mac, ok := macParam(w, s, r)
	if !ok {
		return
	}
	block := r.Method == http.MethodPost
	name := "netdevice.client_unblock"
	if block {
		name = "netdevice.client_block"
	}
	s.routerAction(w, r, a, name, map[string]any{"mac": mac}, func(ctx context.Context, c *keenetic.Client) error { return c.SetBlocked(ctx, mac, block) }, nil)
}

// reserveClient makes the router keep a device's address for it (PUT) or lets it go (DELETE).
func (s *Server) reserveClient(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	mac, ok := macParam(w, s, r)
	if !ok {
		return
	}
	keep := r.Method == http.MethodPut
	name := "netdevice.client_unreserve"
	if keep {
		name = "netdevice.client_reserve"
	}
	s.routerAction(w, r, a, name, map[string]any{"mac": mac}, func(ctx context.Context, c *keenetic.Client) error { return c.SetReserved(ctx, mac, keep) }, nil)
}

// switchForward turns a forward off or on again without taking it away.
func (s *Server) switchForward(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	ref := r.PathValue("ref")
	if !forwardRef.MatchString(ref) {
		s.writeErr(w, r, http.StatusNotFound, "missing", "no such forward")
		return
	}
	var in struct {
		Off bool `json:"off"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	name := "netdevice.forward_on"
	if in.Off {
		name = "netdevice.forward_off"
	}
	// A forward the owner switches on is theirs: it raises no alert.
	var known func(netdev.NatRule) bool
	if !in.Off {
		known = func(n netdev.NatRule) bool { return n.Ref == ref }
	}
	s.routerAction(w, r, a, name, map[string]any{"ref": ref}, func(ctx context.Context, c *keenetic.Client) error { return c.SetForwardOff(ctx, ref, in.Off) }, known)
}

// rebootRouter restarts the router.
func (s *Server) rebootRouter(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	s.routerAction(w, r, a, "netdevice.reboot", map[string]any{}, func(ctx context.Context, c *keenetic.Client) error { return c.Reboot(ctx) }, nil)
}
