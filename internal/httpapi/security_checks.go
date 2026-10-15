package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/netintel"
	"github.com/Taminum/RemnaScope/internal/secchecks"
	"github.com/Taminum/RemnaScope/internal/store"
)

// Nudger wakes the external checker after a manual request.
type Nudger interface{ Nudge() }

// vantageOut is attached to every external result: where the check ran from, and whether that is a point
// of view independent of the servers being checked.
func vantageOut() map[string]any {
	return map[string]any{"id": secchecks.VantageID, "independent": secchecks.Independent}
}

// editableVPS loads the server and requires the right to change it.
func (s *Server) editableVPS(w http.ResponseWriter, r *http.Request, a auth.Actor) (store.VPS, bool) {
	v, ok := s.visibleVPS(w, r, a)
	if !ok {
		return v, false
	}
	if !vpsCanEdit(a, v) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of a linked panel is required")
		return v, false
	}
	return v, true
}

func (s *Server) checkTarget(w http.ResponseWriter, r *http.Request, host string, port int) (string, bool) {
	addr, ok := normAddress(host)
	if !ok {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_host", "host must be an IP address or a domain")
		return "", false
	}
	if port < 1 || port > 65535 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_port", "port must be 1 to 65535")
		return "", false
	}
	return addr.Address, true
}

func (s *Server) checkStoreErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.writeErr(w, r, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, store.ErrHostNotRegistered):
		s.writeErr(w, r, http.StatusUnprocessableEntity, "host_not_registered", "only an address or domain registered on this server can be checked")
	case errors.Is(err, store.ErrLimit):
		s.writeErr(w, r, http.StatusConflict, "limit", "too many endpoints")
	case errors.Is(err, store.ErrConflict):
		s.writeErr(w, r, http.StatusConflict, "exists", "this endpoint already exists")
	default:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
	}
}

func (s *Server) listPublicPorts(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.visibleVPS(w, r, a)
	if !ok {
		return
	}
	items, err := s.Store.ListPortEndpoints(r.Context(), a.Scope(), v.ID)
	if err != nil {
		s.checkStoreErr(w, r, err)
		return
	}
	discovery := "off"
	if v.DiscoveryScan {
		discovery = "on" // a bounded list of common ports, once a day; still not "every port"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "vantage": vantageOut(), "interval_minutes": int(secchecks.PortEvery / time.Minute),
		// Only endpoints already known are checked, and ports found by the opt-in scan. Nothing here says that
		// other ports are closed.
		"coverage": map[string]any{"kind": "known_endpoints", "discovery": discovery},
	})
}

func (s *Server) addPublicPort(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.editableVPS(w, r, a)
	if !ok {
		return
	}
	var in struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Expected bool   `json:"expected"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	host, ok := s.checkTarget(w, r, in.Host, in.Port)
	if !ok {
		return
	}
	e, err := s.Store.AddPortEndpoint(r.Context(), a.Scope(), v.ID, host, in.Port, in.Expected)
	if err != nil {
		s.checkStoreErr(w, r, err)
		return
	}
	s.audit(r, a, "", "security.port_endpoint.add", "vps", v.ID, map[string]any{"host": host, "port": in.Port, "expected": in.Expected})
	s.nudgeChecks()
	writeJSON(w, http.StatusCreated, e)
}

func (s *Server) patchPublicPort(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.editableVPS(w, r, a)
	if !ok {
		return
	}
	var in struct {
		Expected *bool `json:"expected"`
		Enabled  *bool `json:"enabled"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	e, err := s.Store.PatchPortEndpoint(r.Context(), a.Scope(), v.ID, r.PathValue("eid"), in.Expected, in.Enabled)
	if err != nil {
		s.checkStoreErr(w, r, err)
		return
	}
	s.audit(r, a, "", "security.port_endpoint.update", "vps", v.ID, map[string]any{"endpoint": e.ID})
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) listTLS(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.visibleVPS(w, r, a)
	if !ok {
		return
	}
	items, err := s.Store.ListTLSEndpoints(r.Context(), a.Scope(), v.ID)
	if err != nil {
		s.checkStoreErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "vantage": vantageOut(), "interval_hours": int(secchecks.TLSEvery / time.Hour)})
}

func (s *Server) addTLS(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.editableVPS(w, r, a)
	if !ok {
		return
	}
	var in struct {
		Host string `json:"host"`
		Port int    `json:"port"`
		SNI  string `json:"sni"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	host, ok := s.checkTarget(w, r, in.Host, in.Port)
	if !ok {
		return
	}
	sni := ""
	if in.SNI != "" {
		tg, err := netintel.Parse(in.SNI)
		if err != nil || tg.Kind != netintel.KindDomain {
			s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_sni", "SNI must be a domain")
			return
		}
		sni = tg.Value
	}
	e, err := s.Store.AddTLSEndpoint(r.Context(), a.Scope(), v.ID, host, in.Port, sni)
	if err != nil {
		s.checkStoreErr(w, r, err)
		return
	}
	s.audit(r, a, "", "security.tls_endpoint.add", "vps", v.ID, map[string]any{"host": host, "port": in.Port, "sni": sni})
	s.nudgeChecks()
	writeJSON(w, http.StatusCreated, e)
}

func (s *Server) patchTLS(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.editableVPS(w, r, a)
	if !ok {
		return
	}
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	e, err := s.Store.PatchTLSEndpoint(r.Context(), a.Scope(), v.ID, r.PathValue("eid"), in.Enabled)
	if err != nil {
		s.checkStoreErr(w, r, err)
		return
	}
	s.audit(r, a, "", "security.tls_endpoint.update", "vps", v.ID, map[string]any{"endpoint": e.ID})
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) nudgeChecks() {
	if s.SecChecks != nil {
		s.SecChecks.Nudge()
	}
}

// runChecks makes a server's endpoints of one kind due at once. It answers 202: the checker does the work
// and the result appears on the next read. A server may ask once every 30 seconds per kind.
func (s *Server) runChecks(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.editableVPS(w, r, a)
	if !ok {
		return
	}
	kind := r.PathValue("kind")
	if kind != "ports" && kind != "tls" {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "unknown check")
		return
	}
	if !s.checkLimit.Allow(v.ID + "|" + kind) {
		w.Header().Set("Retry-After", "30")
		s.writeErr(w, r, http.StatusTooManyRequests, "rate_limited", "a check was requested a moment ago")
		return
	}
	n, err := s.Store.RequestChecks(r.Context(), a.Scope(), v.ID, kind)
	if err != nil {
		s.checkStoreErr(w, r, err)
		return
	}
	s.nudgeChecks()
	s.audit(r, a, "", "security.check.run", "vps", v.ID, map[string]any{"kind": kind, "endpoints": n})
	writeJSON(w, http.StatusAccepted, map[string]any{"requested": n})
}
