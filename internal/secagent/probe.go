package secagent

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/Taminum/RemnaScope/internal/secprobe"
	"github.com/Taminum/RemnaScope/internal/secproto"
)

const maxProbes = 4 // at once; further requests are refused rather than queued

// validProbe re-checks everything the server sent. The server is trusted to ask, not to be right: the
// agent will not dial a private address (secprobe refuses those again) and takes only these fields.
func validProbe(p secproto.Probe) bool {
	if p.Type != "probe" || len(p.ID) == 0 || len(p.ID) > 64 || p.Port < 1 || p.Port > 65535 || len(p.SNI) > 253 {
		return false
	}
	if p.Kind != secproto.ProbeTCP && p.Kind != secproto.ProbeTLS {
		return false
	}
	if p.Kind == secproto.ProbeTCP && p.SNI != "" {
		return false
	}
	if _, err := netip.ParseAddr(p.Host); err == nil {
		return true
	}
	h := p.Host
	if h == "" || len(h) > 253 || strings.ContainsAny(h, " /@:?#[]\\") || strings.HasPrefix(h, ".") || strings.HasPrefix(h, "-") {
		return false
	}
	return true
}

// probe runs one request and answers it. busy is true when the agent already runs its limit of probes.
func (a *agent) probe(ctx context.Context, p secproto.Probe, busy bool) secproto.ProbeResult {
	res := secproto.ProbeResult{Type: "probe_result", ID: p.ID, Kind: p.Kind}
	if len(res.ID) > 64 {
		res.ID = ""
	}
	if !validProbe(p) {
		res.Refused = "bad_request"
		return res
	}
	if busy {
		res.Refused = "busy"
		return res
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	switch p.Kind {
	case secproto.ProbeTCP:
		r := secprobe.TCP(ctx, p.Host, p.Port)
		res.Result, res.IP, res.RTTms, res.Error = r.Result, r.IP, r.RTTms, r.Error
	case secproto.ProbeTLS:
		r := secprobe.TLS(ctx, p.Host, p.Port, p.SNI, time.Now().UTC())
		res.TLS = &secproto.ProbeTLSResult{State: r.State, IP: r.IP, Resolved: r.Resolved, SNI: r.SNI, NameChecked: r.NameChecked, Version: r.Version,
			Fingerprint: r.Fingerprint, Subject: r.Subject, Issuer: r.Issuer, DNSNames: r.DNSNames, Serial: r.Serial,
			NotBefore: r.NotBefore, NotAfter: r.NotAfter, DaysLeft: r.DaysLeft, HasCert: r.HasCert, Error: r.Error}
	}
	return res
}
