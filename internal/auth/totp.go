package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 / authenticator apps use HMAC-SHA1
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpPeriod = 30
	totpDigits = 6
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns 20 random bytes (the size RFC 4226 recommends).
func NewTOTPSecret() ([]byte, error) {
	b := make([]byte, 20)
	_, err := rand.Read(b)
	return b, err
}

func TOTPSecretText(secret []byte) string { return b32.EncodeToString(secret) }

// TOTPURI is what authenticator apps read from a QR code.
func TOTPURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{"secret": {TOTPSecretText(secret)}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// totpCode is the code for one 30-second step.
func totpCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, v%1_000_000)
}

// TOTPStep is the step number for a moment in time.
func TOTPStep(t time.Time) int64 { return t.Unix() / totpPeriod }

// VerifyTOTP accepts the code of the current step and of one step either side (clock drift). It
// returns the step that matched, and refuses any step at or before lastStep: a code that was
// already used, or an older one, never works again.
func VerifyTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	cur := TOTPStep(now)
	matched := int64(0)
	for d := int64(-1); d <= 1; d++ { // every candidate is compared, so timing does not reveal which
		step := cur + d
		if subtle.ConstantTimeCompare([]byte(code), []byte(totpCode(secret, step))) == 1 && step > lastStep && step > matched {
			matched = step
		}
	}
	return matched, matched != 0
}

// NewRecoveryCodes returns n codes shaped XXXXX-XXXXX (50 random bits each).
func NewRecoveryCodes(n int) ([]string, error) {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		b := make([]byte, 7)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		s := b32.EncodeToString(b)[:10]
		out = append(out, s[:5]+"-"+s[5:])
	}
	return out, nil
}

// NormaliseRecoveryCode makes what a person typed comparable: upper case, no spaces or dashes.
func NormaliseRecoveryCode(s string) string {
	return strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(s)))
}

// LooksLikeTOTP tells a six-digit code from a recovery code.
func LooksLikeTOTP(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != totpDigits {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// TOTPCodeAt is the code an authenticator app shows at a moment in time. The server only needs
// it for tests and tools; people read it off their phone.
func TOTPCodeAt(secret []byte, t time.Time) string { return totpCode(secret, TOTPStep(t)) }

// DecodeTOTPSecret reads the text form shown at set-up.
func DecodeTOTPSecret(s string) ([]byte, error) {
	return b32.DecodeString(strings.ToUpper(strings.TrimSpace(s)))
}
