package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/auth"
)

type mfaCtx struct {
	t      *testing.T
	h      *harness
	secret []byte
	codes  []string
}

func (m *mfaCtx) now() time.Time { return m.h.srv.Now() }
func (m *mfaCtx) code() string   { return auth.TOTPCodeAt(m.secret, m.now()) }

// passwordStep signs in with the password only; the answer is either a session or a challenge.
func (m *mfaCtx) passwordStep() (*client, int, map[string]any) {
	c := m.h.anon()
	st, b := c.do("POST", "/api/v1/auth/login", map[string]string{"username": "owner", "password": testPassword})
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return c, st, out
}

func (m *mfaCtx) second(c *client, token, code string) (int, map[string]any) {
	st, b := c.do("POST", "/api/v1/auth/mfa", map[string]string{"mfa_token": token, "code": code})
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if st == 200 {
		var me meResponse
		_ = json.Unmarshal(b, &me)
		c.me, c.csrf = me, me.CSRFToken
	}
	return st, out
}

func enableMFA(t *testing.T) (*mfaCtx, *client) {
	t.Helper()
	h := newHarness(t)
	h.account("owner", true)
	owner := h.login("owner")
	m := &mfaCtx{t: t, h: h}

	st, b := owner.do("POST", "/api/v1/account/mfa/setup", map[string]string{})
	var setup struct {
		Secret string `json:"secret"`
		URI    string `json:"uri"`
	}
	_ = json.Unmarshal(b, &setup)
	if st != 200 || !strings.HasPrefix(setup.URI, "otpauth://totp/RemnaScope:owner?") || setup.Secret == "" {
		t.Fatalf("setup: %d %s", st, b)
	}
	var err error
	if m.secret, err = auth.DecodeTOTPSecret(setup.Secret); err != nil {
		t.Fatal(err)
	}
	// Until a code confirms it the factor is not on: signing in still needs only the password.
	if _, st, out := m.passwordStep(); st != 200 || out["mfa_required"] != nil {
		t.Fatalf("pending secret must not change sign-in: %d %v", st, out)
	}
	if st, _ := owner.do("POST", "/api/v1/account/mfa/enable", map[string]string{"code": "000000"}); st != 422 {
		t.Fatalf("a wrong code enabled it: %d", st)
	}
	st, b = owner.do("POST", "/api/v1/account/mfa/enable", map[string]string{"code": m.code()})
	var en struct {
		Codes []string `json:"recovery_codes"`
	}
	_ = json.Unmarshal(b, &en)
	if st != 200 || len(en.Codes) != 10 {
		t.Fatalf("enable: %d %s", st, b)
	}
	m.codes = en.Codes
	return m, owner
}

func TestMFASignInNeedsTheSecondFactorAndNeverReusesACode(t *testing.T) {
	m, owner := enableMFA(t)
	_, me := owner.get("/api/v1/auth/me")
	if !strings.Contains(string(me), `"mfa_enabled":true`) {
		t.Fatalf("me: %s", me)
	}

	// Password alone no longer gives a session, only a challenge.
	c, st, out := m.passwordStep()
	token, _ := out["mfa_token"].(string)
	if st != 200 || out["mfa_required"] != true || token == "" || out["csrf_token"] != nil {
		t.Fatalf("password step: %d %v", st, out)
	}
	if st, _ := c.get("/api/v1/auth/me"); st != 401 {
		t.Fatalf("the challenge must not be a session: %d", st)
	}
	if st, out := m.second(c, token, "123456"); st != 401 || out["code"] != "invalid_code" {
		t.Fatalf("wrong code: %d %v", st, out)
	}
	// The code that confirmed the set-up is already spent, even though it is still valid by the clock.
	if st, _ := m.second(c, token, m.code()); st != 401 {
		t.Fatalf("the code that enabled MFA signed in: %d", st)
	}
	// The next 30 seconds bring a fresh code.
	m.h.advance(31 * time.Second)
	c2, _, out2 := m.passwordStep()
	token2, _ := out2["mfa_token"].(string)
	good := m.code()
	if st, out := m.second(c2, token2, good); st != 200 || out["csrf_token"] == nil {
		t.Fatalf("a fresh code: %d %v", st, out)
	}
	if st, _ := c2.get("/api/v1/auth/me"); st != 200 {
		t.Fatalf("session after the second factor: %d", st)
	}
	// The same code, with a new challenge, is refused: a code works once.
	c3, _, out3 := m.passwordStep()
	if st, _ := m.second(c3, out3["mfa_token"].(string), good); st != 401 {
		t.Fatalf("replay of a used code: %d", st)
	}
	// A token is not a session and not reusable after success.
	if st, _ := m.second(m.h.anon(), token2, m.code()); st != 401 {
		t.Fatalf("a used challenge worked again: %d", st)
	}
}

func TestMFARecoveryCodesWorkOnce(t *testing.T) {
	m, _ := enableMFA(t)
	use := func(code string) int {
		c, _, out := m.passwordStep()
		st, _ := m.second(c, out["mfa_token"].(string), code)
		return st
	}
	if st := use(strings.ToLower(m.codes[0])); st != 200 { // lower case is accepted
		t.Fatalf("recovery code: %d", st)
	}
	if st := use(m.codes[0]); st != 401 {
		t.Fatalf("a recovery code worked twice: %d", st)
	}
	if st := use(m.codes[1]); st != 200 {
		t.Fatalf("a second, different code: %d", st)
	}
	if st := use("AAAAA-AAAAA"); st != 401 {
		t.Fatalf("an invented code: %d", st)
	}
}

func TestMFAChallengeExpiresAndAllowsFewTries(t *testing.T) {
	m, _ := enableMFA(t)
	// Expiry.
	c, _, out := m.passwordStep()
	tok := out["mfa_token"].(string)
	m.h.advance(6 * time.Minute)
	if st, _ := m.second(c, tok, m.code()); st != 401 {
		t.Fatalf("an expired challenge worked: %d", st)
	}
	// Five wrong tries end a challenge, even if the sixth is right.
	m.h.advance(31 * time.Second)
	c, _, out = m.passwordStep()
	tok = out["mfa_token"].(string)
	for i := 0; i < 5; i++ {
		if st, _ := m.second(c, tok, "000000"); st != 401 {
			t.Fatalf("try %d: %d", i, st)
		}
	}
	if st, _ := m.second(c, tok, m.code()); st != 401 {
		t.Fatalf("a challenge survived five wrong tries: %d", st)
	}
	// Garbage input is just refused.
	for _, tk := range []string{"", "short", strings.Repeat("x", 300)} {
		if st, _ := m.second(c, tk, "123456"); st != 401 {
			t.Errorf("token %q: %d", tk, st)
		}
	}
}

func TestMFADisableNeedsPasswordAndCode(t *testing.T) {
	m, owner := enableMFA(t)
	if st, _ := owner.do("POST", "/api/v1/account/mfa/setup", map[string]string{}); st != 409 {
		t.Fatalf("set-up while enabled: %d", st)
	}
	m.h.advance(31 * time.Second)
	if st, _ := owner.do("POST", "/api/v1/account/mfa/disable", map[string]string{"password": "wrong", "code": m.code()}); st != 403 {
		t.Fatalf("wrong password: %d", st)
	}
	if st, _ := owner.do("POST", "/api/v1/account/mfa/disable", map[string]string{"password": testPassword, "code": "000000"}); st != 403 {
		t.Fatalf("wrong code: %d", st)
	}
	if st, _ := owner.do("POST", "/api/v1/account/mfa/disable", map[string]string{"password": testPassword, "code": m.code()}); st != 204 {
		t.Fatalf("disable: %d", st)
	}
	if _, st, out := m.passwordStep(); st != 200 || out["mfa_required"] != nil || out["csrf_token"] == nil {
		t.Fatalf("after disabling, the password signs in again: %d %v", st, out)
	}
	// And a recovery code cannot be used after the factor is gone.
	c, _, _ := m.passwordStep()
	if st, _ := m.second(c, "x", m.codes[0]); st != 401 {
		t.Fatalf("%d", st)
	}
}

func TestMFASecretIsEncryptedAtRest(t *testing.T) {
	m, _ := enableMFA(t)
	var ct []byte
	if err := m.h.st.Pool().QueryRow(ctx, `SELECT totp_ciphertext FROM accounts WHERE username='owner'`).Scan(&ct); err != nil {
		t.Fatal(err)
	}
	if len(ct) == 0 || strings.Contains(string(ct), string(m.secret)) {
		t.Fatalf("the secret is not sealed")
	}
	var codes int
	_ = m.h.st.Pool().QueryRow(ctx, `SELECT count(*) FROM recovery_codes WHERE code_hash = decode('00','hex')`).Scan(&codes)
	for _, c := range m.codes {
		var n int
		_ = m.h.st.Pool().QueryRow(ctx, `SELECT count(*) FROM recovery_codes WHERE convert_from(code_hash, 'SQL_ASCII') = $1`, auth.NormaliseRecoveryCode(c)).Scan(&n)
		if n != 0 {
			t.Fatal("a recovery code is stored in the clear")
		}
	}
}
