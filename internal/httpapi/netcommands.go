package httpapi

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/store"
)

// NetCommandsPath is where a router that reports by a script asks what it is to do, and says how it went.
const NetCommandsPath = "/ingest/net/v1/commands"

// netAuth checks the router's own token (the one it reports with) and says which router it is.
func (s *Server) netAuth(w http.ResponseWriter, r *http.Request) (string, bool) {
	h, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	id, secret, found := strings.Cut(h, ".")
	if !ok || !found || id == "" || len(secret) < 20 || len(secret) > 200 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}
	want, _, err := s.Store.NetDeviceForAuth(r.Context(), id)
	if err != nil || subtle.ConstantTimeCompare(store.HashAgentSecret(secret), want) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}
	return id, true
}

// netCommands hands a router its next command (GET), one line "id|kind|a1|a2", or answers 204 when there is none; and takes the
// answer (POST) "ack=id,ok" or "ack=id,fail,why".
func (s *Server) netCommands(w http.ResponseWriter, r *http.Request) {
	id, ok := s.netAuth(w, r)
	if !ok {
		return
	}
	now := time.Now().UTC()
	switch r.Method {
	case http.MethodGet:
		c, err := s.Store.NextNetCommand(r.Context(), id, now)
		if err != nil {
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
		if c == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, "%d|%s|%s|%s", c.ID, c.Kind, c.A1, c.A2)
	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<10))
		if err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		for _, line := range strings.Split(string(body), "\n") {
			v, found := strings.CutPrefix(strings.TrimSpace(line), "ack=")
			if !found {
				continue
			}
			f := strings.SplitN(v, ",", 3)
			n, err := strconv.ParseInt(strings.TrimSpace(f[0]), 10, 64)
			if err != nil || len(f) < 2 {
				continue
			}
			note := ""
			if len(f) > 2 {
				note = f[2]
			}
			_ = s.Store.AckNetCommand(r.Context(), id, n, strings.TrimSpace(f[1]) == "ok", note, now)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// askRouter puts something in the queue of a router that reports by a script. The owner asks; the router does it within a minute.
func (s *Server) askRouter(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	var in struct {
		Kind string `json:"kind"`
		MAC  string `json:"mac"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	devs, err := s.Store.ListNetDevices(r.Context(), time.Now().UTC())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	var dev *store.NetDevice
	for i := range devs {
		if devs[i].ID == id {
			dev = &devs[i]
		}
	}
	if dev == nil || dev.Kind == store.KindKeenetic {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such router that reports by a script")
		return
	}
	mac, a1, a2 := "", "", ""
	switch in.Kind {
	case store.CmdReboot:
	case store.CmdBlock, store.CmdUnblock, store.CmdReserve, store.CmdUnreserve:
		hw, err := net.ParseMAC(strings.TrimSpace(in.MAC))
		if err != nil || len(hw) != 6 {
			s.writeErr(w, r, http.StatusUnprocessableEntity, "unknown_host", "not a device address")
			return
		}
		mac = strings.ToUpper(hw.String())
		a1 = mac
		if in.Kind == store.CmdReserve {
			for _, c := range dev.View.Clients {
				if c.MAC == mac {
					a2 = c.IP
				}
			}
			if ip := net.ParseIP(a2); ip == nil || ip.To4() == nil {
				s.writeErr(w, r, http.StatusUnprocessableEntity, "unknown_host", "the router does not list this device with an address")
				return
			}
		}
	default:
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_command", "unknown command")
		return
	}
	n, err := s.Store.EnqueueNetCommand(r.Context(), id, in.Kind, a1, a2)
	switch {
	case errors.Is(err, store.ErrConflict):
		s.writeErr(w, r, http.StatusConflict, "too_many", "too many commands are waiting for this router")
		return
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "netdevice.command", "netdevice", id, map[string]any{"kind": in.Kind, "mac": mac, "command": n})
	w.WriteHeader(http.StatusAccepted)
}

// rotateNetToken gives a router that reports by a script a new token and the script that carries it. The old script stops working
// at once; the router has to get the new one, which also teaches it to ask for commands.
func (s *Server) rotateNetToken(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	id := r.PathValue("id")
	devs, err := s.Store.ListNetDevices(r.Context(), time.Now().UTC())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	kind := ""
	for _, d := range devs {
		if d.ID == id {
			kind = d.Kind
		}
	}
	if kind == "" || kind == store.KindKeenetic {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such router that reports by a script")
		return
	}
	secret, err := auth.NewToken()
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if err := s.Store.RotateNetToken(r.Context(), id, store.HashAgentSecret(secret)); err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "netdevice.rotate_token", "netdevice", id, nil)
	token := id + "." + secret
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "script": buildDeviceScript(kind, r.Host, token)})
}
