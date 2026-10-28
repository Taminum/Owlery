package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/store"
)

// Web services: an admin panel bound to 127.0.0.1 on a machine, opened at https://<slug>.<ServicesDomain> through the
// machine's agent. Each service has an origin of its own, so its pages can neither read Owlery's cookies nor call its
// API (a request from a sibling subdomain is "same-site", which sameOrigin refuses).
//
// Signing in to a service: the session cookie of Owlery belongs to Owlery's own host and never reaches a service. A
// visit without the service's own cookie goes to Owlery, which checks the person and sends them back with a ticket
// good for a minute; the service host trades it for a cookie of its own (8 hours), which is taken out of every
// request before it reaches the panel.

const (
	svcCookie    = "owlery_svc"
	svcTicketTTL = time.Minute
	svcCookieTTL = 8 * time.Hour
	svcAuthPath  = "/__owlery/auth"
)

var slugRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)

// svcSign makes a token for one service: kind ("t" ticket, "c" cookie), the slug, the account and when it expires.
func (s *Server) svcSign(kind, slug, account string, until time.Time) string {
	payload := strings.Join([]string{kind, slug, account, strconv.FormatInt(until.Unix(), 10)}, "|")
	m := hmac.New(sha256.New, s.svcKey)
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// svcVerify checks a token and returns its account.
func (s *Server) svcVerify(tok, kind, slug string) (string, bool) {
	p, sig, ok := strings.Cut(tok, ".")
	if !ok {
		return "", false
	}
	payload, err1 := base64.RawURLEncoding.DecodeString(p)
	got, err2 := base64.RawURLEncoding.DecodeString(sig)
	if err1 != nil || err2 != nil {
		return "", false
	}
	m := hmac.New(sha256.New, s.svcKey)
	m.Write(payload)
	if !hmac.Equal(got, m.Sum(nil)) {
		return "", false
	}
	f := strings.Split(string(payload), "|")
	if len(f) != 4 || f[0] != kind || f[1] != slug {
		return "", false
	}
	until, err := strconv.ParseInt(f[3], 10, 64)
	if err != nil || s.Now().Unix() > until {
		return "", false
	}
	return f[2], true
}

// serviceSlug is the slug when the request is for a service host, else "".
func (s *Server) serviceSlug(r *http.Request) string {
	if s.ServicesDomain == "" {
		return ""
	}
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	slug, ok := strings.CutSuffix(host, "."+s.ServicesDomain)
	if !ok || !slugRe.MatchString(slug) {
		return ""
	}
	return slug
}

// serviceHosts sends requests for a service host to its panel and everything else on to Owlery.
func (s *Server) serviceHosts(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slug := s.serviceSlug(r)
		if slug == "" {
			next.ServeHTTP(w, r)
			return
		}
		s.serveService(w, r, slug)
	})
}

func (s *Server) serveService(w http.ResponseWriter, r *http.Request, slug string) {
	if r.URL.Path == svcAuthPath {
		account, ok := s.svcVerify(r.URL.Query().Get("t"), "t", slug)
		if !ok {
			http.Error(w, "Ссылка для входа устарела. Откройте службу из Owlery ещё раз.", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: svcCookie, Value: s.svcSign("c", slug, account, s.Now().Add(svcCookieTTL)), Path: "/",
			HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: int(svcCookieTTL.Seconds())})
		http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusFound)
		return
	}
	c, err := r.Cookie(svcCookie)
	if err != nil {
		s.svcSignIn(w, r, slug)
		return
	}
	if _, ok := s.svcVerify(c.Value, "c", slug); !ok {
		s.svcSignIn(w, r, slug)
		return
	}
	svc, err := s.Store.WebServiceBySlug(r.Context(), slug)
	if err != nil {
		http.Error(w, "Такой службы нет или её убрали из Owlery.", http.StatusNotFound)
		return
	}
	s.webProxy(svc).ServeHTTP(w, r)
}

// svcSignIn sends a page visit to Owlery to check who it is; anything else is refused.
func (s *Server) svcSignIn(w http.ResponseWriter, r *http.Request, slug string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Войдите в службу через Owlery.", http.StatusUnauthorized)
		return
	}
	u := "https://" + s.ServicesDomain + "/api/v1/services/" + slug + "/enter?next=" + url.QueryEscape(r.URL.RequestURI())
	http.Redirect(w, r, u, http.StatusFound)
}

// safeNext keeps a return path on the service's own host.
func safeNext(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return "/"
	}
	return p
}

// serviceEnter is on Owlery's own host: it checks the person may open the service and sends them to it with a ticket.
func (s *Server) serviceEnter(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	slug := r.PathValue("slug")
	svc, err := s.Store.WebServiceBySlug(r.Context(), slug)
	if err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such service")
		return
	}
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), svc.VPSID)
	if err != nil || !vpsCanEdit(a, v) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of a linked panel is required")
		return
	}
	s.audit(r, a, "", "web.open", "server", v.ID, map[string]any{"name": v.Name, "service": svc.Title, "slug": svc.Slug, "port": svc.Port})
	t := s.svcSign("t", slug, a.AccountID, s.Now().Add(svcTicketTTL))
	http.Redirect(w, r, "https://"+slug+"."+s.ServicesDomain+svcAuthPath+"?t="+url.QueryEscape(t)+"&next="+url.QueryEscape(safeNext(r.URL.Query().Get("next"))), http.StatusFound)
}

// tlsAsk answers Caddy before it gets a certificate for a name: only names of published services get one. Caddy
// calls it on the internal network; the public entrances never route /internal/ to the API.
func (s *Server) tlsAsk(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.URL.Query().Get("domain"))
	slug, ok := strings.CutSuffix(host, "."+s.ServicesDomain)
	if s.ServicesDomain == "" || !ok || !slugRe.MatchString(slug) {
		http.Error(w, "no", http.StatusNotFound)
		return
	}
	if _, err := s.Store.WebServiceBySlug(r.Context(), slug); err != nil {
		http.Error(w, "no", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// webProxy is the reverse proxy of one service. Its connections are opened through the machine's agent and kept
// alive between requests, so a page with many files does not open a tunnel for each.
func (s *Server) webProxy(svc store.WebService) http.Handler {
	s.proxiesMu.Lock()
	defer s.proxiesMu.Unlock()
	key := svc.ID + ":" + strconv.Itoa(svc.Port)
	if p, ok := s.proxies[key]; ok {
		return p
	}
	if s.proxies == nil {
		s.proxies = map[string]http.Handler{}
	}
	target := &url.URL{Scheme: "http", Host: "127.0.0.1:" + strconv.Itoa(svc.Port)}
	tr := &http.Transport{
		DialContext:         func(ctx context.Context, _, _ string) (net.Conn, error) { return s.dialService(ctx, svc) },
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
	}
	p := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host // the panel builds its links from the address the person sees
			pr.SetXForwarded()
			dropCookie(pr.Out, svcCookie)
		},
		Transport: tr,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			msg := "Не удалось достучаться до службы на машине."
			switch {
			case errors.Is(err, errPortClosed):
				msg = fmt.Sprintf("На машине никто не отвечает на порту %d. Служба запущена?", svc.Port)
			case errors.Is(err, errNoWeb):
				msg = "Агент этой машины не на связи или не разрешает открывать веб-службы (нужен флаг -allow-web)."
			}
			http.Error(w, msg, http.StatusBadGateway)
		},
	}
	s.proxies[key] = p
	return p
}

var (
	errPortClosed = errors.New("nothing answers on the service port")
	errNoWeb      = errors.New("the machine's agent is offline or does not allow web services")
)

// dialService opens one connection to the service through the machine's agent.
func (s *Server) dialService(ctx context.Context, svc store.WebService) (net.Conn, error) {
	agent, err := s.Store.SecAgentOf(ctx, svc.VPSID)
	if err != nil || s.SecOps == nil || !s.SecOps.Online(agent.ID) || !slices.Contains(agent.Capabilities, secproto.CapWeb) {
		return nil, errNoWeb
	}
	octx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	m, release, err := s.SecOps.OpenProxy(octx, agent.ID, svc.Port)
	if err != nil {
		return nil, errNoWeb
	}
	typ, first, err := m.Read(octx)
	if err != nil || typ != websocket.MessageText || string(first) != secproto.TunnelReady {
		m.CloseNow()
		release()
		return nil, errPortClosed
	}
	// The connection outlives this dial: it lives as long as the transport keeps it.
	return &releasingConn{Conn: websocket.NetConn(context.Background(), m, websocket.MessageBinary), release: release}, nil
}

type releasingConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *releasingConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// dropCookie takes one cookie out of a request and leaves the others as they were.
func dropCookie(r *http.Request, name string) {
	cs := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cs {
		if c.Name != name {
			r.AddCookie(c)
		}
	}
}

// --- the services of a machine, on Owlery's own host ---

type webServicesOut struct {
	Services []store.WebService `json:"services"`
	Domain   string             `json:"domain"`  // empty: web services are not set up on this Owlery
	Allowed  bool               `json:"allowed"` // the machine's agent allows web services
	Online   bool               `json:"online"`
}

func (s *Server) webServicesFor(w http.ResponseWriter, r *http.Request, a auth.Actor) (store.VPS, bool) {
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.vpsNotFound(w, r)
		return v, false
	}
	if !vpsCanEdit(a, v) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of a linked panel is required")
		return v, false
	}
	return v, true
}

func (s *Server) listWebServices(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.webServicesFor(w, r, a)
	if !ok {
		return
	}
	list, err := s.Store.ListWebServices(r.Context(), v.ID)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	out := webServicesOut{Services: list, Domain: s.ServicesDomain}
	if agent, err := s.Store.SecAgentOf(r.Context(), v.ID); err == nil {
		out.Allowed = slices.Contains(agent.Capabilities, secproto.CapWeb)
		out.Online = s.SecOps != nil && s.SecOps.Online(agent.ID)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createWebService(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.webServicesFor(w, r, a)
	if !ok {
		return
	}
	if s.ServicesDomain == "" {
		s.writeErr(w, r, http.StatusServiceUnavailable, "web_off", "web services are not set up on this server (SERVICES_DOMAIN)")
		return
	}
	var in struct {
		Title string `json:"title"`
		Slug  string `json:"slug"`
		Port  int    `json:"port"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	title, ok := validName(in.Title)
	if !ok {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_title", "the name must be 1 to 64 characters")
		return
	}
	slug := strings.ToLower(strings.TrimSpace(in.Slug))
	if !slugRe.MatchString(slug) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_slug", "the address may have Latin letters, digits and hyphens, up to 40")
		return
	}
	if in.Port < 1 || in.Port > 65535 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_port", "the port must be 1 to 65535")
		return
	}
	svc, err := s.Store.CreateWebService(r.Context(), v.ID, slug, title, in.Port, a.AccountID)
	if errors.Is(err, store.ErrConflict) {
		s.writeErr(w, r, http.StatusConflict, "slug_taken", "this address is taken (or was used before)")
		return
	}
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "web.create", "server", v.ID, map[string]any{"name": v.Name, "service": svc.Title, "slug": svc.Slug, "port": svc.Port})
	writeJSON(w, http.StatusCreated, svc)
}

func (s *Server) deleteWebService(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, ok := s.webServicesFor(w, r, a)
	if !ok {
		return
	}
	if err := s.Store.ArchiveWebService(r.Context(), v.ID, r.PathValue("sid")); err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such service")
		return
	}
	s.proxiesMu.Lock()
	for k := range s.proxies {
		if strings.HasPrefix(k, r.PathValue("sid")+":") {
			delete(s.proxies, k)
		}
	}
	s.proxiesMu.Unlock()
	s.audit(r, a, "", "web.delete", "server", v.ID, map[string]any{"name": v.Name, "service_id": r.PathValue("sid")})
	w.WriteHeader(http.StatusNoContent)
}
