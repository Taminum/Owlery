package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/store"
)

type accountDTO struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	IsOwner  bool   `json:"is_owner"`
}

type meResponse struct {
	Account           accountDTO         `json:"account"`
	Memberships       []store.Membership `json:"memberships"`
	CSRFToken         string             `json:"csrf_token"`
	SessionExpiresAt  time.Time          `json:"session_expires_at"`
	CustomCAAvailable bool               `json:"custom_ca_available"`
	MFAEnabled        bool               `json:"mfa_enabled"`
}

func (s *Server) meFor(a auth.Actor, sess store.Session, mfa bool) meResponse {
	ms := make([]store.Membership, 0, len(a.Roles))
	for id, r := range a.Roles {
		ms = append(ms, store.Membership{PanelID: id, Role: string(r)})
	}
	return meResponse{
		Account:           accountDTO{ID: a.AccountID, Username: a.Username, IsOwner: a.IsOwner},
		Memberships:       ms,
		CSRFToken:         auth.CSRFToken(s.csrfKey, sess.ID),
		SessionExpiresAt:  sess.ExpiresAt,
		CustomCAAvailable: s.CustomCA,
		MFAEnabled:        mfa,
	}
}

const genericLoginFailure = "wrong username or password, or sign-in is temporarily restricted"

func (s *Server) loginFail(w http.ResponseWriter, r *http.Request, accountID, reason string) {
	// The attempted username is never logged: people sometimes type a password there.
	_ = s.Store.WriteAudit(r.Context(), store.AuditEntry{ActorID: accountID, Action: "auth.login_failed", ObjectType: "account",
		IP: s.clientIP(r).String(), RequestID: reqID(r.Context()), Metadata: map[string]any{"reason": reason}})
	s.writeErr(w, r, http.StatusUnauthorized, "invalid_credentials", genericLoginFailure)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		s.writeErr(w, r, http.StatusForbidden, "cross_origin", "cross-origin request refused")
		return
	}
	ip := s.clientIP(r)
	if !s.Limits.Login.Allow(ip.String()) {
		w.Header().Set("Retry-After", "60")
		s.writeErr(w, r, http.StatusTooManyRequests, "rate_limited", "too many sign-in attempts, try again later")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	in.Username = strings.TrimSpace(in.Username)

	acc, err := s.Store.AccountByUsername(r.Context(), in.Username)
	locked := err == nil && acc.LockedUntil != nil && acc.LockedUntil.After(s.Now())
	if err != nil || acc.Disabled || locked || in.Username == "" {
		// Same work and same answer whether the account is unknown, disabled or locked.
		auth.VerifyPassword(in.Password, s.dummyHash)
		reason, id := "unknown_user", ""
		if err == nil {
			id = acc.ID
			reason = map[bool]string{true: "locked", false: "disabled"}[locked]
		}
		s.loginFail(w, r, id, reason)
		return
	}
	ok, rehash := auth.VerifyPassword(in.Password, acc.PasswordHash)
	if !ok {
		_, _ = s.Store.RecordLoginFailure(r.Context(), acc.ID, 5, 30*time.Second, 15*time.Minute)
		s.loginFail(w, r, acc.ID, "bad_password")
		return
	}
	if rehash {
		if h, err := auth.HashPassword(in.Password, s.Hash); err == nil {
			_ = s.Store.UpgradeHash(r.Context(), acc.ID, h)
		}
	}
	if acc.TOTPEnabled {
		// The password is right; the second factor is still owed. No session exists yet.
		s.startMFAChallenge(w, r, acc)
		return
	}
	s.openSession(w, r, acc, "password")
}

// openSession records a successful sign-in and starts the session.
func (s *Server) openSession(w http.ResponseWriter, r *http.Request, acc store.Account, method string) {
	ip := s.clientIP(r)
	_ = s.Store.RecordLoginSuccess(r.Context(), acc.ID)

	token, err := auth.NewToken()
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	expires := s.Now().Add(s.SessionTTL)
	sid, err := s.Store.CreateSession(r.Context(), acc.ID, auth.HashToken(token), expires, ip, r.UserAgent())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.setCookie(w, token, int(s.SessionTTL.Seconds()))

	ms, _ := s.Store.Memberships(r.Context(), acc.ID)
	actor := auth.NewActor(acc, ms)
	s.audit(r, actor, "", "auth.login", "account", acc.ID, map[string]any{"method": method})
	writeJSON(w, http.StatusOK, s.meFor(actor, store.Session{ID: sid, AccountID: acc.ID, ExpiresAt: expires}, acc.TOTPEnabled))
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if c, err := r.Cookie(CookieSession); err == nil {
		_ = s.Store.DeleteSession(r.Context(), auth.HashToken(c.Value))
	}
	s.clearCookie(w)
	s.audit(r, a, "", "auth.logout", "account", a.AccountID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, a auth.Actor, sess store.Session) {
	mfa := false
	if acc, err := s.Store.AccountByID(r.Context(), a.AccountID); err == nil {
		mfa = acc.TOTPEnabled
	}
	writeJSON(w, http.StatusOK, s.meFor(a, sess, mfa))
}

func (s *Server) changeOwnPassword(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	var in struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	acc, err := s.Store.AccountByID(r.Context(), a.AccountID)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if ok, _ := auth.VerifyPassword(in.Current, acc.PasswordHash); !ok {
		s.writeErr(w, r, http.StatusForbidden, "invalid_credentials", "current password is wrong")
		return
	}
	if err := auth.ValidatePassword(a.Username, in.New); err != nil {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "weak_password", err.Error())
		return
	}
	h, err := auth.HashPassword(in.New, s.Hash)
	if err != nil || s.Store.SetPassword(r.Context(), a.AccountID, h) != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.clearCookie(w) // every session of this account, including this one, was ended
	s.audit(r, a, "", "account.password_change", "account", a.AccountID, nil)
	w.WriteHeader(http.StatusNoContent)
}
