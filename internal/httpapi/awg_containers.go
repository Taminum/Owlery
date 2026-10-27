package httpapi

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/ingestproto"
	"github.com/Taminum/Owlery/internal/store"
)

var (
	awgContainerRe = regexp.MustCompile(`^amnezia-awg[0-9]{0,2}$`)
	awgSubnetRe    = regexp.MustCompile(`^10\.([0-9]{1,3})\.([0-9]{1,3})\.0/24$`)
)

type awgHostOut struct {
	store.AWGHost
	Online         bool `json:"online"`
	ContainerAdmin bool `json:"container_admin"`
}

// awgHosts lists the AmneziaWG hosts and whether each lets Owlery create and remove containers. Only the
// owner sees this: it is the entry point of the one operation that creates containers.
func (s *Server) awgHosts(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can see AmneziaWG hosts")
		return
	}
	hosts, err := s.Store.AWGHosts(r.Context(), a.Scope())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	out := make([]awgHostOut, 0, len(hosts))
	for _, h := range hosts {
		o := awgHostOut{AWGHost: h}
		if s.AWGOps != nil {
			o.Online = s.AWGOps.Online(h.AgentID)
			o.ContainerAdmin = o.Online && s.AWGOps.ContainerAdmin(h.AgentID)
		}
		out = append(out, o)
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": out})
}

// awgInstall creates one container on a host that opted in. The fields are fixed in kind: a container name of
// the Amnezia pattern, a port and a /24 subnet. Nothing here is a command line.
func (s *Server) awgInstall(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.awgOwner(w, r, a) {
		return
	}
	var in struct {
		Container string `json:"container"`
		Port      int    `json:"port"`
		Subnet    string `json:"subnet"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if !awgContainerRe.MatchString(in.Container) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_container", "the container name must be amnezia-awg or amnezia-awg followed by up to two digits")
		return
	}
	if in.Port < 1024 || in.Port > 65535 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_port", "the port must be 1024 to 65535")
		return
	}
	if m := awgSubnetRe.FindStringSubmatch(in.Subnet); m == nil || atoiOr(m[1], 999) > 255 || atoiOr(m[2], 999) > 255 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_subnet", "the subnet must be a /24 like 10.8.1.0/24")
		return
	}
	agentID, err := s.Store.AWGHostAgent(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such host")
		return
	}
	if !s.AWGOps.ContainerAdmin(agentID) {
		s.writeErr(w, r, http.StatusConflict, "container_admin_off", "this host has not opted in to creating containers")
		return
	}
	// Building the image can take minutes; the browser is told how it ended, not left guessing.
	ctx, cancel := context.WithTimeout(r.Context(), 13*time.Minute)
	defer cancel()
	res, err := s.AWGOps.Do(ctx, agentID, ingestproto.AWGOp{Op: "install", Container: in.Container, Port: in.Port, Subnet: in.Subnet})
	meta := map[string]any{"container": in.Container, "port": in.Port, "subnet": in.Subnet, "ok": err == nil && res.Status == "ok"}
	if err != nil || res.Status != "ok" {
		code := res.Code
		if err != nil {
			code = "agent"
		}
		meta["code"] = code
		s.audit(r, a, "", "awg.container.install", "agent", agentID, meta)
		s.awgOpFailure(w, r, err, res)
		return
	}
	s.audit(r, a, "", "awg.container.install", "agent", agentID, meta)
	writeJSON(w, http.StatusCreated, map[string]any{"container": in.Container, "port": res.Port, "server_key_short": shortKey(res.Key)})
}

// awgRemoveContainer removes a whole container with every device in it. The body must repeat the container's
// name: a click on the wrong card is not enough.
func (s *Server) awgRemoveContainer(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.awgOwner(w, r, a) {
		return
	}
	var in struct {
		Confirm string `json:"confirm"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	instID := r.PathValue("id")
	agentID, container, _, err := s.Store.AWGInstanceTarget(r.Context(), a.Scope(), instID)
	if err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such server")
		return
	}
	if in.Confirm != container {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "not_confirmed", "type the container name to confirm")
		return
	}
	if !awgContainerRe.MatchString(container) {
		s.writeErr(w, r, http.StatusConflict, "not_removable", "only containers created in the Amnezia layout can be removed here")
		return
	}
	if !s.AWGOps.ContainerAdmin(agentID) {
		s.writeErr(w, r, http.StatusConflict, "container_admin_off", "this host has not opted in to removing containers")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	res, err := s.AWGOps.Do(ctx, agentID, ingestproto.AWGOp{Op: "remove", Container: container, Confirm: "yes-delete-all-devices"})
	meta := map[string]any{"container": container, "ok": err == nil && res.Status == "ok"}
	if err != nil || res.Status != "ok" {
		code := res.Code
		if err != nil {
			code = "agent"
		}
		meta["code"] = code
		s.audit(r, a, "", "awg.container.remove", "awg_instance", instID, meta)
		s.awgOpFailure(w, r, err, res)
		return
	}
	s.audit(r, a, "", "awg.container.remove", "awg_instance", instID, meta)
	w.WriteHeader(http.StatusNoContent)
}

func atoiOr(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
