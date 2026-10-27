package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/store"
)

const (
	mfaChallengeTTL = 5 * time.Minute
	mfaMaxAttempts  = 5
	recoveryCount   = 10
	totpIssuer      = "Owlery"
)

// startMFAChallenge answers a correct password with "now send a code". It reveals nothing a
// password alone would not: whoever has the password learns that the account uses a second factor.
func (s *Server) startMFAChallenge(w http.ResponseWriter, r *http.Request, acc store.Account) {
	token, err := auth.NewToken()
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if err := s.Store.CreateMFAChallenge(r.Context(), acc.ID, auth.HashToken(token), s.Now().Add(mfaChallengeTTL)); err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mfa_required": true, "mfa_token": token, "expires_in": int(mfaChallengeTTL.Seconds())})
}

const genericMFAFailure = "the code is wrong or has expired, or sign-in is temporarily restricted"

func (s *Server) mfaFail(w http.ResponseWriter, r *http.Request, accountID, reason string) {
	_ = s.Store.WriteAudit(r.Context(), store.AuditEntry{ActorID: accountID, Action: "auth.mfa_failed", ObjectType: "account",
		IP: s.clientIP(r).String(), RequestID: reqID(r.Context()), Metadata: map[string]any{"reason": reason}})
	s.writeErr(w, r, http.StatusUnauthorized, "invalid_code", genericMFAFailure)
}

// checkSecondFactor accepts a six-digit code or a recovery code. A correct TOTP code is spent
// (it cannot sign in again); a recovery code is spent too.
func (s *Server) checkSecondFactor(r *http.Request, acc store.Account, input string) (method string, ok bool) {
	ctx := r.Context()
	if auth.LooksLikeTOTP(input) {
		t, have, err := s.Store.AccountTOTP(ctx, acc.ID)
		if err != nil || !have || !t.Enabled || s.Ring == nil {
			return "", false
		}
		secret, err := s.Ring.Open(store.TOTPAAD(acc.ID), t.Sealed)
		if err != nil {
			return "", false
		}
		defer func() {
			for i := range secret {
				secret[i] = 0
			}
		}()
		step, good := auth.VerifyTOTP(secret, input, s.Now(), t.LastStep)
		if !good {
			return "", false
		}
		won, err := s.Store.AdvanceTOTPStep(ctx, acc.ID, step)
		return "totp", err == nil && won
	}
	code := auth.NormaliseRecoveryCode(input)
	if len(code) != 10 {
		return "", false
	}
	used, err := s.Store.UseRecoveryCode(ctx, acc.ID, code)
	return "recovery", err == nil && used
}

// loginMFA completes a sign-in that the password started.
func (s *Server) loginMFA(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		s.writeErr(w, r, http.StatusForbidden, "cross_origin", "cross-origin request refused")
		return
	}
	if !s.Limits.Login.Allow(s.clientIP(r).String()) {
		w.Header().Set("Retry-After", "60")
		s.writeErr(w, r, http.StatusTooManyRequests, "rate_limited", "too many sign-in attempts, try again later")
		return
	}
	var in struct {
		Token string `json:"mfa_token"`
		Code  string `json:"code"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if len(in.Token) < 20 || len(in.Token) > 200 || len(in.Code) > 32 {
		s.mfaFail(w, r, "", "malformed")
		return
	}
	hash := auth.HashToken(in.Token)
	id, ok, err := s.Store.MFAAttempt(r.Context(), hash, s.Now(), mfaMaxAttempts)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if !ok {
		s.mfaFail(w, r, "", "no_challenge")
		return
	}
	acc, err := s.Store.AccountByID(r.Context(), id)
	if err != nil || acc.Disabled || (acc.LockedUntil != nil && acc.LockedUntil.After(s.Now())) || !acc.TOTPEnabled {
		s.mfaFail(w, r, id, "unavailable")
		return
	}
	method, good := s.checkSecondFactor(r, acc, in.Code)
	if !good {
		_, _ = s.Store.RecordLoginFailure(r.Context(), acc.ID, 5, 30*time.Second, 15*time.Minute)
		s.mfaFail(w, r, acc.ID, "bad_code")
		return
	}
	_ = s.Store.DeleteMFAChallenge(r.Context(), hash)
	s.openSession(w, r, acc, method)
}

// --- enrolment (signed in) -------------------------------------------------------------

// mfaSetup creates a pending secret and returns it once, to be added to an authenticator app.
func (s *Server) mfaSetup(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if s.Ring == nil {
		s.writeErr(w, r, http.StatusServiceUnavailable, "unavailable", "key store is not available")
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	sealed, err := s.Ring.Seal(store.TOTPAAD(a.AccountID), secret)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if err := s.Store.SetPendingTOTP(r.Context(), a.AccountID, sealed); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.writeErr(w, r, http.StatusConflict, "mfa_enabled", "two-factor sign-in is already on; turn it off first")
			return
		}
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "mfa.setup", "account", a.AccountID, nil)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"secret": auth.TOTPSecretText(secret), "uri": auth.TOTPURI(totpIssuer, a.Username, secret)})
}

// mfaEnable confirms the secret with a code and returns the recovery codes, once.
func (s *Server) mfaEnable(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	var in struct {
		Code string `json:"code"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	t, have, err := s.Store.AccountTOTP(r.Context(), a.AccountID)
	if err != nil || !have || t.Enabled || s.Ring == nil {
		s.writeErr(w, r, http.StatusConflict, "mfa_not_pending", "start the set-up first")
		return
	}
	secret, err := s.Ring.Open(store.TOTPAAD(a.AccountID), t.Sealed)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	step, ok := auth.VerifyTOTP(secret, in.Code, s.Now(), 0)
	for i := range secret {
		secret[i] = 0
	}
	if !ok {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_code", "that code does not match; check the time on your phone and try the next code")
		return
	}
	codes, err := auth.NewRecoveryCodes(recoveryCount)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	norm := make([]string, len(codes))
	for i, c := range codes {
		norm[i] = auth.NormaliseRecoveryCode(c)
	}
	if err := s.Store.EnableTOTP(r.Context(), a.AccountID, step, norm); err != nil {
		s.writeErr(w, r, http.StatusConflict, "mfa_not_pending", "start the set-up first")
		return
	}
	s.audit(r, a, "", "mfa.enable", "account", a.AccountID, nil)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// mfaDisable needs the password and a current code (or a recovery code): a stolen session alone
// cannot switch the second factor off.
func (s *Server) mfaDisable(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	var in struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	acc, err := s.Store.AccountByID(r.Context(), a.AccountID)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if ok, _ := auth.VerifyPassword(in.Password, acc.PasswordHash); !ok {
		s.writeErr(w, r, http.StatusForbidden, "invalid_credentials", "current password is wrong")
		return
	}
	if acc.TOTPEnabled {
		if _, ok := s.checkSecondFactor(r, acc, strings.TrimSpace(in.Code)); !ok {
			s.writeErr(w, r, http.StatusForbidden, "invalid_code", "the code is wrong or has expired")
			return
		}
	}
	if err := s.Store.DisableTOTP(r.Context(), a.AccountID); err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "mfa.disable", "account", a.AccountID, nil)
	w.WriteHeader(http.StatusNoContent)
}
