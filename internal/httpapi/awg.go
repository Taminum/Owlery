package httpapi

import (
	"net/http"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/store"
)

// A report older than this means the collector on the AWG host is not reporting: nothing about the
// peers can be said for now (which is different from "nobody is connected").
const awgFresh = 5 * time.Minute

// Handshake ages. A WireGuard-style handshake is repeated about every two minutes while traffic
// flows, so a recent one means "was in touch lately", not "is using it right now".
const (
	awgActive = 3 * time.Minute
	awgRecent = time.Hour
)

type awgPeerOut struct {
	ID            string     `json:"id"`
	Label         string     `json:"label"`
	TunnelIP      string     `json:"tunnel_ip,omitempty"`
	KeyShort      string     `json:"key_short"`
	State         string     `json:"state"` // active | recent | stale | never | unknown
	HandshakeAt   *time.Time `json:"handshake_at"`
	FirstSeen     time.Time  `json:"first_seen"`
	Gone          bool       `json:"gone"`
	DownloadTotal int64      `json:"download_total"` // sent to the client by the server, since the interface came up
	UploadTotal   int64      `json:"upload_total"`   // received from the client
	DownloadRange int64      `json:"download_range"` // the same, over the asked period, restarts accounted for
	UploadRange   int64      `json:"upload_range"`
	SampleAt      *time.Time `json:"sample_at"`
	// What RemnaScope itself has added up since it first saw the peer, restarts of the server included.
	TrackedDownload int64      `json:"tracked_download"`
	TrackedUpload   int64      `json:"tracked_upload"`
	TrackedFrom     *time.Time `json:"tracked_from"`
	// When the device was last seen: the interface's own latest handshake if it has one, else the
	// latest RemnaScope recorded, else what the Amnezia panel had recorded. The source says which.
	LastSeenAt     *time.Time `json:"last_seen_at"`
	LastSeenSource string     `json:"last_seen_source,omitempty"` // live | recorded | panel
	// Expiry and allowance, when the owner set them. UsedBytes counts from LimitFrom.
	ExpiresAt         *time.Time `json:"expires_at"`
	TrafficLimitBytes *int64     `json:"traffic_limit_bytes"`
	LimitFrom         *time.Time `json:"limit_from"`
	UsedBytes         int64      `json:"used_bytes"`
	AutoRevoked       string     `json:"auto_revoked,omitempty"` // expired | traffic_limit: RemnaScope revoked it
	// What the Amnezia panel had recorded (a snapshot as of the instance's legacy_at).
	// The running total: what the old table recorded for the device, plus what RemnaScope has seen
	// since (which includes what the server's counters held when RemnaScope first looked).
	TotalDownload int64      `json:"total_download"`
	TotalUpload   int64      `json:"total_upload"`
	TotalSince    *time.Time `json:"total_since"`
}

type awgInstanceOut struct {
	Host          string       `json:"host"` // the agent (and so the server) the container lives on
	ID            string       `json:"id"`
	Container     string       `json:"container"`
	Interface     string       `json:"interface"`
	Port          int          `json:"port,omitempty"`
	Variant       string       `json:"variant,omitempty"`
	Mode          string       `json:"mode"`
	LastReport    time.Time    `json:"last_report"`
	LegacyAt      *time.Time   `json:"legacy_at"`
	CountersSince *time.Time   `json:"counters_since"` // the server's own counters run from about here and restart from zero with it
	ReportFresh   bool         `json:"report_fresh"`
	Peers         []awgPeerOut `json:"peers"`
}

func awgPeriod(r *http.Request) time.Duration {
	switch r.URL.Query().Get("period") {
	case "1h":
		return time.Hour
	case "7d":
		return 7 * 24 * time.Hour
	case "30d":
		return 30 * 24 * time.Hour
	}
	return 24 * time.Hour
}

func (s *Server) awgList(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	period := awgPeriod(r)
	rows, err := s.Store.AWGInstances(r.Context(), a.Scope(), period)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	now := time.Now()
	var instIDs []string
	for _, in := range rows {
		instIDs = append(instIDs, in.ID)
	}
	limits, err := s.Store.AWGPeerLimits(r.Context(), instIDs)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	out := struct {
		Instances []awgInstanceOut `json:"instances"`
		Period    string           `json:"period"`
	}{Instances: []awgInstanceOut{}, Period: period.String()}
	for _, in := range rows {
		o := awgInstanceOut{Host: in.AgentName, ID: in.ID, Container: in.Container, Interface: in.Interface, Port: in.Port, Variant: in.Variant, Mode: in.Mode,
			LastReport: in.LastReport.UTC(), CountersSince: in.Started, LegacyAt: in.LegacyAt, ReportFresh: now.Sub(in.LastReport) <= awgFresh, Peers: []awgPeerOut{}}
		for _, p := range in.Peers {
			state := "unknown"
			if o.ReportFresh {
				switch {
				case p.Handshake == nil && (p.EverHS != nil || p.LegacyHS != nil):
					state = "stale" // not since the interface was last started, but it has been seen before
				case p.Handshake == nil:
					state = "never"
				case now.Sub(*p.Handshake) <= awgActive:
					state = "active"
				case now.Sub(*p.Handshake) <= awgRecent:
					state = "recent"
				default:
					state = "stale"
				}
			}
			label := p.Label
			if label == "" {
				label = p.TunnelIP
			}
			po := awgPeerOut{ID: p.ID, Label: label, TunnelIP: p.TunnelIP, KeyShort: shortKey(p.Key), State: state, FirstSeen: p.FirstSeen.UTC(), Gone: p.Gone,
				DownloadTotal: p.TX, UploadTotal: p.RX, DownloadRange: p.PeriodTX, UploadRange: p.PeriodRX, TrackedDownload: p.TrackedTX, TrackedUpload: p.TrackedRX, TrackedFrom: p.TrackedFrom}
			if l, ok := limits[p.ID]; ok {
				po.ExpiresAt, po.TrafficLimitBytes, po.LimitFrom, po.UsedBytes, po.AutoRevoked = l.ExpiresAt, l.TrafficLimitBytes, l.LimitFrom, l.UsedBytes, l.AutoRevokedReason
			}
			if p.Handshake != nil {
				t := p.Handshake.UTC()
				po.HandshakeAt = &t
			}
			switch {
			case p.Handshake != nil:
				po.LastSeenAt, po.LastSeenSource = po.HandshakeAt, "live"
			case p.EverHS != nil:
				t := p.EverHS.UTC()
				po.LastSeenAt, po.LastSeenSource = &t, "recorded"
			case p.LegacyHS != nil:
				t := p.LegacyHS.UTC()
				po.LastSeenAt, po.LastSeenSource = &t, "panel"
			}
			po.TotalDownload, po.TotalUpload = p.TrackedTX, p.TrackedRX
			if p.LegacyDown != nil {
				po.TotalDownload += *p.LegacyDown
			}
			if p.LegacyUp != nil {
				po.TotalUpload += *p.LegacyUp
			}
			switch {
			case p.CreatedHint != nil:
				t := p.CreatedHint.UTC()
				po.TotalSince = &t
			case in.Started != nil:
				po.TotalSince = in.Started
			default:
				po.TotalSince = p.TrackedFrom
			}
			if p.SampleAt != nil {
				t := p.SampleAt.UTC()
				po.SampleAt = &t
			}
			o.Peers = append(o.Peers, po)
		}
		out.Instances = append(out.Instances, o)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

func shortKey(k string) string {
	if len(k) <= 10 {
		return k
	}
	return k[:6] + "…" + k[len(k)-4:]
}

type awgPointOut struct {
	TS       time.Time `json:"ts"`
	Download int64     `json:"download"`
	Upload   int64     `json:"upload"`
}

func (s *Server) awgSeries(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	var span, bucket time.Duration
	switch r.URL.Query().Get("range") {
	case "7d":
		span, bucket = 7*24*time.Hour, 6*time.Hour
	case "30d":
		span, bucket = 30*24*time.Hour, 24*time.Hour
	case "1h":
		span, bucket = time.Hour, 5*time.Minute
	default:
		span, bucket = 24*time.Hour, time.Hour
	}
	to := time.Now().UTC()
	from := to.Add(-span).Truncate(bucket)
	pts, err := s.Store.AWGSeries(r.Context(), a.Scope(), r.PathValue("id"), from, to, bucket)
	if err != nil {
		if err == store.ErrNotFound {
			s.writeErr(w, r, http.StatusNotFound, "not_found", "peer not found")
			return
		}
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	out := struct {
		BucketSeconds int           `json:"bucket_seconds"`
		From          time.Time     `json:"from"`
		To            time.Time     `json:"to"`
		Points        []awgPointOut `json:"points"` // a bucket with no sample is absent: that is "no data", not zero
	}{BucketSeconds: int(bucket.Seconds()), From: from, To: to, Points: []awgPointOut{}}
	for _, p := range pts {
		out.Points = append(out.Points, awgPointOut{TS: p.TS.UTC(), Download: p.TX, Upload: p.RX})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// awgForget removes a device that is gone from the server, with its history.
func (s *Server) awgForget(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can remove a device from the history")
		return
	}
	if err := s.Store.DeleteGoneAWGPeer(r.Context(), a.Scope(), r.PathValue("id")); err != nil {
		if err == store.ErrNotFound {
			s.writeErr(w, r, http.StatusNotFound, "not_found", "no such removed device")
			return
		}
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "awg.forget", "awg_peer", r.PathValue("id"), nil)
	w.WriteHeader(http.StatusNoContent)
}
