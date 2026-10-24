// Package httpapi exposes the REST API. Every route except health and login needs a
// session; every state-changing route also needs a CSRF token and a same-origin request.
package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/autoclassify"
	"github.com/Taminum/RemnaScope/internal/awgops"
	"github.com/Taminum/RemnaScope/internal/gemini"
	"github.com/Taminum/RemnaScope/internal/ingestproto"
	"github.com/Taminum/RemnaScope/internal/live"
	"github.com/Taminum/RemnaScope/internal/netintel"
	"github.com/Taminum/RemnaScope/internal/remnawave"
	"github.com/Taminum/RemnaScope/internal/safehttp"
	"github.com/Taminum/RemnaScope/internal/secops"
	"github.com/Taminum/RemnaScope/internal/secproto"
	"github.com/Taminum/RemnaScope/internal/secrets"
	"github.com/Taminum/RemnaScope/internal/store"
	"github.com/Taminum/RemnaScope/internal/syncer"
)

const (
	CookieSession = "rs_session"
	maxBody       = 64 << 10
)

// ProbeFactory builds a read-only adapter for an operator-supplied URL. It must
// validate the URL (returning a *safehttp.Error) and never follow redirects.
type ProbeFactory func(baseURL, token string, useCustomCA bool) (remnawave.PanelAdapter, string, error)

type Limits struct {
	Login  *auth.Limiter // per client IP
	Probe  *auth.Limiter // per account
	Test   *auth.Limiter // per account+panel
	Sync   *auth.Limiter // per panel
	Writes *auth.Limiter // per account, all other state changes
}

func DefaultLimits() Limits {
	return Limits{
		Login:  auth.NewLimiter(10.0/60, 10),
		Probe:  auth.NewLimiter(10.0/60, 5),
		Test:   auth.NewLimiter(6.0/60, 3),
		Sync:   auth.NewLimiter(3.0/60, 2),
		Writes: auth.NewLimiter(60.0/60, 30),
	}
}

type Server struct {
	Store        *store.Store
	Ring         *secrets.Keyring
	Probe        ProbeFactory
	Sync         *syncer.Syncer
	Ingest       http.Handler // the agents' WebSocket endpoint; authenticates by agent credential, not by session
	SecIngest    http.Handler // the security agents' endpoint, with its own credentials
	SecChecks    Nudger       // the external checker, woken by a manual request (nil = none)
	SecOps       *secops.Hub  // carries ban/unban to security agents that are connected (nil = commands off)
	DNSWorker    Nudger       // the DNS Map worker, woken by a refresh (nil = none)
	dnsLimit     *auth.Limiter
	checkLimit   *auth.Limiter
	cmdLimit     *auth.Limiter
	Limits       Limits
	Live         *live.Hub     // present-moment router snapshots (nil = none)
	Pulse        *syncer.Pulse // the latest speed of every panel's nodes (nil = none)
	Gemini       *gemini.Client
	Auto         *autoclassify.Runner
	Intel        *netintel.Tool
	AWGOps       *awgops.Hub   // carries add/revoke to AmneziaWG agents (nil = management off)
	intelSlots   chan struct{} // limits how many active checks run at once
	models       modelCache
	Hash         auth.Argon2Params
	CookieSecure bool
	Trusted      []netip.Prefix // proxies whose X-Real-IP we believe
	CustomCA     bool           // an admin-managed CA bundle is configured
	SessionTTL   time.Duration
	IdleTTL      time.Duration
	Log          *slog.Logger
	Now          func() time.Time

	dummyHash string
	csrfKey   []byte
}

func (s *Server) init() {
	if s.dnsLimit == nil {
		s.dnsLimit = auth.NewLimiter(1.0/60, 1)
	}
	if s.cmdLimit == nil {
		s.cmdLimit = auth.NewLimiter(1.0/6, 5)
	}
	if s.checkLimit == nil {
		s.checkLimit = auth.NewLimiter(1.0/30, 1)
	}
	if s.intelSlots == nil {
		s.intelSlots = make(chan struct{}, 4)
	}
	if s.Log == nil {
		s.Log = slog.Default()
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.SessionTTL == 0 {
		s.SessionTTL = 12 * time.Hour
	}
	if s.IdleTTL == 0 {
		s.IdleTTL = 2 * time.Hour
	}
	if s.Hash.MemoryKiB == 0 {
		s.Hash = auth.DefaultParams
	}
	if s.Limits.Login == nil {
		s.Limits = DefaultLimits()
	}
	s.dummyHash, _ = auth.HashPassword("remnascope-dummy-password", s.Hash)
	if s.Ring != nil {
		s.csrfKey = s.Ring.DeriveKey("csrf")
	}
}

type ctxKey int

const (
	keyActor ctxKey = iota
	keySession
	keyReqID
)

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
	Details   any    `json:"details,omitempty"`
}

func (s *Server) Handler() http.Handler {
	s.init()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", s.ready)

	if s.Ingest != nil {
		mux.Handle(ingestproto.Path, s.Ingest)
	}

	if s.SecIngest != nil {
		mux.Handle(secproto.Path, s.SecIngest)
	}

	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.Handle("POST /api/v1/auth/logout", s.session(s.logout))
	mux.Handle("GET /api/v1/auth/me", s.session(s.me))
	mux.Handle("POST /api/v1/auth/password", s.session(s.changeOwnPassword))
	mux.HandleFunc("POST /api/v1/auth/mfa", s.loginMFA)
	mux.Handle("POST /api/v1/account/mfa/setup", s.session(s.mfaSetup))
	mux.Handle("POST /api/v1/account/mfa/enable", s.session(s.mfaEnable))
	mux.Handle("POST /api/v1/account/mfa/disable", s.session(s.mfaDisable))

	mux.Handle("GET /api/v1/scope", s.session(s.scope))
	mux.Handle("GET /api/v1/overview", s.session(s.overview))

	mux.Handle("POST /api/v1/panels/probe", s.session(s.probePanel))
	mux.Handle("POST /api/v1/panels", s.session(s.createPanel))
	mux.Handle("GET /api/v1/panels", s.session(s.listPanels))
	mux.Handle("GET /api/v1/panels/{id}", s.session(s.getPanel))
	mux.Handle("PATCH /api/v1/panels/{id}", s.session(s.patchPanel))
	mux.Handle("DELETE /api/v1/panels/{id}", s.session(s.deletePanel))
	mux.Handle("POST /api/v1/panels/{id}/test", s.session(s.testPanel))
	mux.Handle("PUT /api/v1/panels/{id}/token", s.session(s.rotateToken))
	mux.Handle("POST /api/v1/panels/{id}/sync", s.session(s.syncPanel))
	mux.Handle("POST /api/v1/panels/{id}/disable", s.session(s.setEnabled(false)))
	mux.Handle("POST /api/v1/panels/{id}/enable", s.session(s.setEnabled(true)))
	mux.Handle("GET /api/v1/panels/{id}/nodes", s.session(s.listNodes))
	mux.Handle("GET /api/v1/panels/{id}/users", s.session(s.listUsers))
	mux.Handle("GET /api/v1/subscriptions", s.session(s.subscriptions))
	mux.Handle("GET /api/v1/hosts", s.session(s.hostList))
	mux.Handle("GET /api/v1/onboarding", s.session(s.onboarding))
	mux.Handle("GET /api/v1/hosts/{id}/series", s.session(s.hostSeries))
	mux.Handle("GET /api/v1/pulse/nodes", s.session(s.pulseNodes))
	mux.Handle("GET /api/v1/billing", s.session(s.listBills))
	mux.Handle("POST /api/v1/billing", s.session(s.createBill))
	mux.Handle("PUT /api/v1/billing/{id}", s.session(s.updateBill))
	mux.Handle("DELETE /api/v1/billing/{id}", s.session(s.deleteBill))
	mux.Handle("POST /api/v1/billing/{id}/paid", s.session(s.payBill))
	mux.Handle("GET /api/v1/panels/{id}/sync-runs", s.session(s.listSyncRuns))
	mux.Handle("GET /api/v1/panels/{id}/agents", s.session(s.listAgents))
	mux.Handle("POST /api/v1/panels/{id}/agents", s.session(s.createAgent))
	mux.Handle("DELETE /api/v1/panels/{id}/agents/{agent}", s.session(s.revokeAgent))

	mux.Handle("GET /api/v1/analytics/destinations", s.session(s.analyticsDestinations))
	mux.Handle("GET /api/v1/analytics/users", s.session(s.analyticsUsers))
	mux.Handle("GET /api/v1/analytics/users/detail", s.session(s.analyticsUserDetail))
	mux.Handle("GET /api/v1/analytics/nodes", s.session(s.analyticsNodes))
	mux.Handle("GET /api/v1/analytics/sites", s.session(s.analyticsSites))
	mux.Handle("GET /api/v1/analytics/sites/detail", s.session(s.analyticsSiteDetail))
	mux.Handle("GET /api/v1/analytics/subjects", s.session(s.analyticsSubjects))
	mux.Handle("GET /api/v1/analytics/activity", s.session(s.analyticsActivity))
	mux.Handle("GET /api/v1/analytics/countries", s.session(s.analyticsCountries))
	mux.Handle("GET /api/v1/analytics/networks", s.session(s.analyticsNetworks))
	mux.Handle("GET /api/v1/alerts", s.session(s.listAlerts))
	mux.Handle("GET /api/v1/autoclassify", s.session(s.autoStatus))
	mux.Handle("GET /api/v1/autoclassify/models", s.session(s.autoModels))
	mux.Handle("PUT /api/v1/autoclassify/settings", s.session(s.autoSettings))
	mux.Handle("PUT /api/v1/autoclassify/enabled", s.session(s.autoEnable))
	mux.Handle("POST /api/v1/autoclassify/backfill", s.session(s.autoBackfill))
	mux.Handle("POST /api/v1/autoclassify/dryrun", s.session(s.autoDryRunStart))
	mux.Handle("GET /api/v1/autoclassify/dryrun", s.session(s.autoDryRunLatest))
	mux.Handle("GET /api/v1/intel/dns/maps", s.session(s.listDNSMaps))
	mux.Handle("POST /api/v1/intel/dns/maps", s.session(s.createDNSMap))
	mux.Handle("GET /api/v1/intel/dns/maps/{id}", s.session(s.getDNSMap))
	mux.Handle("PATCH /api/v1/intel/dns/maps/{id}", s.session(s.patchDNSMap))
	mux.Handle("DELETE /api/v1/intel/dns/maps/{id}", s.session(s.archiveDNSMap))
	mux.Handle("POST /api/v1/intel/dns/maps/{id}/refresh", s.session(s.refreshDNSMap))
	mux.Handle("GET /api/v1/intel/dns/maps/{id}/records", s.session(s.dnsRecords))
	mux.Handle("GET /api/v1/intel/dns/maps/{id}/graph", s.session(s.dnsGraph))
	mux.Handle("GET /api/v1/intel/dns/maps/{id}/changes", s.session(s.dnsChanges))
	mux.Handle("GET /api/v1/intel/dns/maps/{id}/checks", s.session(s.dnsChecks))
	mux.Handle("GET /api/v1/intel/lookup", s.session(s.intelLookup))
	mux.Handle("GET /api/v1/intel/dns", s.session(s.intelDNS))
	mux.Handle("GET /api/v1/intel/subdomains", s.session(s.intelSubdomains))
	mux.Handle("GET /api/v1/intel/ping", s.session(s.intelPing))
	mux.Handle("GET /api/v1/intel/ports", s.session(s.intelPorts))
	mux.Handle("GET /api/v1/intel/trace", s.session(s.intelTrace))
	mux.Handle("GET /api/v1/intel/tls", s.session(s.intelTLS))
	mux.Handle("GET /api/v1/intel/http", s.session(s.intelHTTP))
	mux.Handle("GET /api/v1/awg", s.session(s.awgList))
	mux.Handle("GET /api/v1/awg/peers/{id}/series", s.session(s.awgSeries))
	mux.Handle("DELETE /api/v1/awg/peers/{id}", s.session(s.awgForget))
	mux.Handle("PATCH /api/v1/awg/peers/{id}", s.session(s.awgRename))
	mux.Handle("POST /api/v1/awg/peers/{id}/revoke", s.session(s.awgRevoke))
	mux.Handle("PUT /api/v1/awg/peers/{id}/limits", s.session(s.awgSetLimits))
	mux.Handle("POST /api/v1/awg/instances/{id}/peers", s.session(s.awgAdd))
	mux.Handle("GET /api/v1/awg/hosts", s.session(s.awgHosts))
	mux.Handle("POST /api/v1/awg/hosts/{id}/containers", s.session(s.awgInstall))
	mux.Handle("POST /api/v1/awg/instances/{id}/remove", s.session(s.awgRemoveContainer))
	mux.Handle("POST /api/v1/awg/instances/{id}/backup", s.session(s.awgBackup))
	mux.Handle("POST /api/v1/awg/instances/{id}/transfer", s.session(s.awgTransfer))
	mux.Handle("POST /api/v1/awg/hosts/{id}/restore", s.session(s.awgRestore))
	mux.Handle("GET /api/v1/probes", s.session(s.listProbes))
	mux.Handle("POST /api/v1/probes", s.session(s.createProbe))
	mux.Handle("DELETE /api/v1/probes/{id}", s.session(s.deleteProbe))
	mux.Handle("GET /api/v1/live", s.session(s.liveNow))
	mux.Handle("GET /api/v1/rules", s.session(s.listRules))
	mux.Handle("POST /api/v1/rules", s.session(s.createRule))
	mux.Handle("DELETE /api/v1/rules/{id}", s.session(s.deleteRule))
	mux.Handle("GET /api/v1/analytics/traffic", s.session(s.analyticsTraffic))
	mux.Handle("GET /api/v1/analytics/devices", s.session(s.analyticsDevices))
	mux.Handle("GET /api/v1/analytics/digest", s.session(s.analyticsDigest))
	mux.Handle("GET /api/v1/analytics/devices/detail", s.session(s.analyticsDeviceDetail))

	mux.Handle("GET /api/v1/security/vps", s.session(s.listVPS))
	mux.Handle("POST /api/v1/security/vps", s.session(s.createVPS))
	mux.Handle("GET /api/v1/security/vps/{id}", s.session(s.getVPS))
	mux.Handle("PATCH /api/v1/security/vps/{id}", s.session(s.patchVPS))
	mux.Handle("DELETE /api/v1/security/vps/{id}", s.session(s.archiveVPS))
	mux.Handle("POST /api/v1/security/vps/{id}/links", s.session(s.addVPSLink))
	mux.Handle("DELETE /api/v1/security/vps/{id}/links/{link}", s.session(s.removeVPSLink))
	mux.Handle("GET /api/v1/security/vps-by-address", s.session(s.vpsByAddress))
	mux.Handle("GET /api/v1/notify/channels", s.session(s.notifyList))
	mux.Handle("POST /api/v1/notify/channels", s.session(s.notifyCreate))
	mux.Handle("PATCH /api/v1/notify/channels/{id}", s.session(s.notifyPatch))
	mux.Handle("DELETE /api/v1/notify/channels/{id}", s.session(s.notifyDelete))
	mux.Handle("POST /api/v1/notify/channels/{id}/test", s.session(s.notifyTest))
	mux.Handle("POST /api/v1/notify/telegram/discover", s.session(s.notifyDiscover))
	mux.Handle("GET /api/v1/security/events", s.session(s.secJournal))
	mux.Handle("GET /api/v1/security/events/{id}", s.session(s.secEventDetail))
	mux.Handle("GET /api/v1/security/vps/{id}/overview", s.session(s.secOverview))
	mux.Handle("GET /api/v1/security/settings", s.session(s.secSettings))
	mux.Handle("POST /api/v1/security/vps/{id}/fail2ban/{action}", s.session(s.fail2banCommand))
	mux.Handle("GET /api/v1/security/vps/{id}/commands", s.session(s.listCommands))
	mux.Handle("GET /api/v1/security/commands/{id}", s.session(s.getCommand))
	mux.Handle("GET /api/v1/security/vps/{id}/agent", s.session(s.getSecAgent))
	mux.Handle("POST /api/v1/security/vps/{id}/agent", s.session(s.createSecAgent))
	mux.Handle("DELETE /api/v1/security/vps/{id}/agent", s.session(s.revokeSecAgent))
	mux.Handle("GET /api/v1/security/vps/{id}/fail2ban", s.session(s.secCategory(secproto.CatFail2ban)))
	mux.Handle("GET /api/v1/security/vps/{id}/ports", s.session(s.secCategory(secproto.CatSockets)))
	mux.Handle("GET /api/v1/security/vps/{id}/firewall", s.session(s.secCategory(secproto.CatFirewall)))
	mux.Handle("GET /api/v1/security/vps/{id}/firewall/history", s.session(s.fwHistory))
	mux.Handle("GET /api/v1/security/vps/{id}/firewall/diff", s.session(s.fwDiff))
	mux.Handle("GET /api/v1/security/vps/{id}/events", s.session(s.secEvents))
	mux.Handle("GET /api/v1/security/vps/{id}/public-ports", s.session(s.listPublicPorts))
	mux.Handle("POST /api/v1/security/vps/{id}/public-ports", s.session(s.addPublicPort))
	mux.Handle("POST /api/v1/security/vps/{id}/public-ports/accept-open", s.session(s.acceptOpenPorts))
	mux.Handle("PATCH /api/v1/security/vps/{id}/public-ports/{eid}", s.session(s.patchPublicPort))
	mux.Handle("GET /api/v1/security/vps/{id}/tls", s.session(s.listTLS))
	mux.Handle("POST /api/v1/security/vps/{id}/tls", s.session(s.addTLS))
	mux.Handle("PATCH /api/v1/security/vps/{id}/tls/{eid}", s.session(s.patchTLS))
	mux.Handle("POST /api/v1/security/vps/{id}/checks/{kind}/run", s.session(s.runChecks))

	mux.Handle("GET /api/v1/accounts", s.session(s.listAccounts))
	mux.Handle("POST /api/v1/accounts", s.session(s.createAccount))
	mux.Handle("PATCH /api/v1/accounts/{id}", s.session(s.patchAccount))
	mux.Handle("PUT /api/v1/accounts/{id}/memberships", s.session(s.setMemberships))
	mux.Handle("GET /api/v1/audit", s.session(s.listAudit))

	return s.recoverer(s.requestID()(secure(s.accessLog(mux))))
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "database": "not_configured"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Store.Pool().Ping(ctx); err != nil {
		s.writeErr(w, r, http.StatusServiceUnavailable, "database_unavailable", "database is not reachable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "database": "ok"})
}

// --- middleware ----------------------------------------------------------------

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.Log.Error("panic in handler", "request_id", reqID(r.Context()), "path", r.URL.Path)
				s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			id := hex.EncodeToString(b)
			w.Header().Set("X-Request-Id", id)
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyReqID, id)))
		})
	}
}

func reqID(ctx context.Context) string {
	id, _ := ctx.Value(keyReqID).(string)
	return id
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(c int) { w.status = c; w.ResponseWriter.WriteHeader(c) }

// Unwrap lets http.ResponseController (and WebSocket upgrades) reach the underlying connection.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("httpapi: the connection cannot be hijacked")
	}
	w.status = http.StatusSwitchingProtocols
	return h.Hijack()
}

// accessLog records method, path (never the query string), status and duration.
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		s.Log.Info("request", "request_id", reqID(r.Context()), "method", r.Method, "path", r.URL.Path, "status", sw.status, "ms", time.Since(start).Milliseconds())
	})
}

func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// authedHandler receives the resolved actor and session.
type authedHandler func(w http.ResponseWriter, r *http.Request, a auth.Actor, sess store.Session)

// session authenticates the cookie, enforces idle/absolute expiry, and for unsafe
// methods requires a same-origin request carrying the CSRF token.
func (s *Server) session(h authedHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(CookieSession)
		if err != nil || c.Value == "" {
			s.writeErr(w, r, http.StatusUnauthorized, "unauthenticated", "sign in required")
			return
		}
		hash := auth.HashToken(c.Value)
		sess, acc, err := s.Store.SessionByTokenHash(r.Context(), hash)
		if err != nil {
			s.clearCookie(w)
			s.writeErr(w, r, http.StatusUnauthorized, "unauthenticated", "sign in required")
			return
		}
		now := s.Now()
		if now.Sub(sess.LastSeenAt) > s.IdleTTL {
			_ = s.Store.DeleteSession(r.Context(), hash)
			s.clearCookie(w)
			s.writeErr(w, r, http.StatusUnauthorized, "session_expired", "session expired")
			return
		}
		if now.Sub(sess.LastSeenAt) > time.Minute {
			_ = s.Store.TouchSession(r.Context(), sess.ID)
		}

		if unsafeMethod(r.Method) {
			if !sameOrigin(r) {
				s.writeErr(w, r, http.StatusForbidden, "cross_origin", "cross-origin request refused")
				return
			}
			if !auth.CSRFValid(s.csrfKey, sess.ID, r.Header.Get("X-CSRF-Token")) {
				s.writeErr(w, r, http.StatusForbidden, "csrf", "missing or invalid CSRF token")
				return
			}
		}
		ms, err := s.Store.Memberships(r.Context(), acc.ID)
		if err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		actor := auth.NewActor(acc, ms)
		if unsafeMethod(r.Method) && !s.Limits.Writes.Allow(acc.ID) {
			s.writeErr(w, r, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
		ctx := context.WithValue(r.Context(), keyActor, actor)
		h(w, r.WithContext(ctx), actor, sess)
	})
}

func unsafeMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

// sameOrigin allows requests with no Origin (non-browser clients cannot be forged
// cross-site) or an Origin whose host equals the Host header; Sec-Fetch-Site, when
// present, must not say cross-site.
func sameOrigin(r *http.Request) bool {
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs == "cross-site" || sfs == "same-site" {
		return false
	}
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func (s *Server) clientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	ip = ip.Unmap()
	for _, p := range s.Trusted {
		if p.Contains(ip) {
			if v, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
				return v.Unmap()
			}
		}
	}
	return ip
}

// ClientAddr is the caller's address as the rate limits and audit see it (honouring trusted proxies).
func (s *Server) ClientAddr(r *http.Request) netip.Addr { return s.clientIP(r) }

func (s *Server) setCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: CookieSession, Value: token, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.CookieSecure, SameSite: http.SameSiteStrictMode})
}

func (s *Server) clearCookie(w http.ResponseWriter) { s.setCookie(w, "", -1) }

// --- audit helper ------------------------------------------------------------

func (s *Server) audit(r *http.Request, a auth.Actor, panelID, action, objectType, objectID string, meta map[string]any) {
	err := s.Store.WriteAudit(r.Context(), store.AuditEntry{
		ActorID: a.AccountID, ActorName: a.Username, PanelID: panelID, Action: action, ObjectType: objectType, ObjectID: objectID,
		IP: s.clientIP(r).String(), RequestID: reqID(r.Context()), Metadata: meta,
	})
	if err != nil {
		s.Log.Error("audit write failed", "action", action, "request_id", reqID(r.Context()))
	}
}

// --- JSON helpers --------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		http.Error(w, `{"code":"internal","message":"internal error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) writeErr(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	writeJSON(w, status, apiError{Code: code, Message: msg, RequestID: reqID(r.Context())})
}

func (s *Server) writeErrDetails(w http.ResponseWriter, r *http.Request, status int, code, msg string, details any) {
	writeJSON(w, status, apiError{Code: code, Message: msg, RequestID: reqID(r.Context()), Details: details})
}

// decode reads a bounded JSON body and rejects unknown fields.
func (s *Server) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		s.writeErr(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			s.writeErr(w, r, http.StatusRequestEntityTooLarge, "body_too_large", "request body is too large")
			return false
		}
		s.writeErr(w, r, http.StatusBadRequest, "invalid_body", "request body is not valid for this endpoint")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		s.writeErr(w, r, http.StatusBadRequest, "invalid_body", "request body must contain a single JSON value")
		return false
	}
	return true
}

// NewProbeFactory is the production factory: URL validation and the hardened client.
func NewProbeFactory(policy safehttp.Policy) ProbeFactory {
	return func(baseURL, token string, useCA bool) (remnawave.PanelAdapter, string, error) {
		u, err := safehttp.ParseBaseURL(baseURL, &policy)
		if err != nil {
			return nil, "", err
		}
		return remnawave.NewV3(u.String(), token, safehttp.New(policy, useCA)), u.String(), nil
	}
}
