package httpapi

import (
	"math/big"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/netintel"
	"github.com/Taminum/Owlery/internal/store"
)

// intelGate lets the owner (the only person who may point the server at the outside world) in, and
// parses the target. Active checks and lookups are never open to other roles.
func (s *Server) intelGate(w http.ResponseWriter, r *http.Request, a auth.Actor) (netintel.Target, bool) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can use network intelligence")
		return netintel.Target{}, false
	}
	if s.Intel == nil {
		s.writeErr(w, r, http.StatusServiceUnavailable, "unavailable", "network intelligence is not set up")
		return netintel.Target{}, false
	}
	tg, err := netintel.Parse(r.URL.Query().Get("target"))
	if err != nil {
		e, _ := netintel.IsError(err)
		code, msg := "invalid_target", "invalid target"
		if e != nil {
			code, msg = e.Code, e.Msg
		}
		s.writeErr(w, r, http.StatusUnprocessableEntity, code, msg)
		return tg, false
	}
	return tg, true
}

func send(w http.ResponseWriter, env netintel.Envelope) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, env)
}

// intelLookup is the overview: for a domain its DNS and every address it points to; for an address
// its owner and registry data; for a CIDR the arithmetic.
func (s *Server) intelLookup(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	tg, ok := s.intelGate(w, r, a)
	if !ok {
		return
	}
	refresh := r.URL.Query().Get("refresh") == "1"
	switch tg.Kind {
	case netintel.KindDomain:
		send(w, s.Intel.Domain(r.Context(), tg, refresh))
	case netintel.KindIP:
		send(w, s.Intel.IP(r.Context(), tg, refresh))
	case netintel.KindCIDR:
		now := time.Now().UTC()
		send(w, netintel.Envelope{Kind: "cidr", Target: tg.Value, Display: tg.Display, FetchedAt: now, ExpiresAt: now, Vantage: "server",
			Sources: []netintel.Source{{Name: "local", OK: true}}, Data: cidrInfo(tg.Prefix)})
	default:
		s.writeErr(w, r, http.StatusUnprocessableEntity, "unsupported", "ASN lookups are not available yet")
	}
}

func (s *Server) intelDNS(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	tg, ok := s.intelGate(w, r, a)
	if !ok {
		return
	}
	if tg.Kind != netintel.KindDomain {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_target", "a domain is needed")
		return
	}
	send(w, s.Intel.Records(r.Context(), tg, r.URL.Query().Get("refresh") == "1"))
}

func (s *Server) intelSubdomains(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	tg, ok := s.intelGate(w, r, a)
	if !ok {
		return
	}
	if tg.Kind != netintel.KindDomain {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_target", "a domain is needed")
		return
	}
	send(w, s.Intel.Subdomains(r.Context(), tg, r.URL.Query().Get("refresh") == "1"))
}

// active runs a probe with at most a few at a time, and records it.
func (s *Server) active(w http.ResponseWriter, r *http.Request, a auth.Actor, name string, run func(netintel.Target) netintel.Envelope) {
	tg, ok := s.intelGate(w, r, a)
	if !ok {
		return
	}
	select {
	case s.intelSlots <- struct{}{}:
		defer func() { <-s.intelSlots }()
	default:
		s.writeErr(w, r, http.StatusTooManyRequests, "busy", "too many checks are running, try again in a moment")
		return
	}
	s.audit(r, a, "", "intel."+name, "target", tg.Value, nil)
	send(w, run(tg))
}

func (s *Server) intelPing(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	s.active(w, r, a, "ping", func(tg netintel.Target) netintel.Envelope { return s.Intel.Ping(r.Context(), tg, count) })
}

func (s *Server) intelPorts(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	var ports []int
	for _, p := range strings.Split(r.URL.Query().Get("ports"), ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n > 0 && n < 65536 {
			ports = append(ports, n)
		}
	}
	s.active(w, r, a, "ports", func(tg netintel.Target) netintel.Envelope { return s.Intel.Ports(r.Context(), tg, ports) })
}

func (s *Server) intelTrace(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	s.active(w, r, a, "trace", func(tg netintel.Target) netintel.Envelope { return s.Intel.Trace(r.Context(), tg) })
}

func (s *Server) intelTLS(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	port, _ := strconv.Atoi(r.URL.Query().Get("port"))
	s.active(w, r, a, "tls", func(tg netintel.Target) netintel.Envelope { return s.Intel.TLS(r.Context(), tg, port) })
}

func (s *Server) intelHTTP(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	q := r.URL.Query()
	s.active(w, r, a, "http", func(tg netintel.Target) netintel.Envelope {
		return s.Intel.HTTP(r.Context(), tg, q.Get("scheme"), q.Get("path"))
	})
}

type cidrOut struct {
	CIDR      string `json:"cidr"`
	Version   int    `json:"version"`
	First     string `json:"first"`
	Last      string `json:"last"`
	Addresses string `json:"addresses"` // a decimal string: an IPv6 block does not fit a JSON number
	Netmask   string `json:"netmask,omitempty"`
	Public    bool   `json:"public"`
}

func cidrInfo(p netip.Prefix) cidrOut {
	p = p.Masked()
	out := cidrOut{CIDR: p.String(), Version: 4, First: p.Addr().String(), Public: netintel.PublicOnly(p.Addr()) == nil}
	bits := p.Addr().BitLen()
	if bits == 128 {
		out.Version = 6
	}
	size := new(big.Int).Lsh(big.NewInt(1), uint(bits-p.Bits()))
	out.Addresses = size.String()
	// last address: first + size - 1
	raw := p.Addr().AsSlice()
	n := new(big.Int).SetBytes(raw)
	n.Add(n, size).Sub(n, big.NewInt(1))
	buf := n.FillBytes(make([]byte, len(raw)))
	if last, ok := netip.AddrFromSlice(buf); ok {
		out.Last = last.String()
	}
	if bits == 32 {
		m := ^uint32(0) << (32 - p.Bits())
		if p.Bits() == 0 {
			m = 0
		}
		out.Netmask = netip.AddrFrom4([4]byte{byte(m >> 24), byte(m >> 16), byte(m >> 8), byte(m)}).String()
	}
	return out
}
