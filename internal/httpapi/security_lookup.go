package httpapi

import (
	"net/http"
	"net/netip"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/store"
)

// vpsByAddress tells which of the given IP addresses belong to a registered server the caller can see. It is
// how the DNS Map links a record to the Security module: only a confirmed, registered address links.
func (s *Server) vpsByAddress(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	in := r.URL.Query()["a"]
	if len(in) > 100 {
		s.writeErr(w, r, http.StatusBadRequest, "too_many", "at most 100 addresses")
		return
	}
	norm := make([]string, 0, len(in))
	for _, x := range in {
		ip, err := netip.ParseAddr(x)
		if err != nil {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_address", "not an IP address: "+x)
			return
		}
		norm = append(norm, ip.Unmap().String())
	}
	m, err := s.Store.VPSByAddresses(r.Context(), a.Scope(), norm)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": m})
}
