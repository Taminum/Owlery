package auth

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B test vectors (SHA-1), last six digits of the published 8-digit codes.
func TestTOTPMatchesRFC6238(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037", 20000000000: "353130"} {
		if got := totpCode(secret, unix/30); got != want {
			t.Errorf("t=%d: %s, want %s", unix, got, want)
		}
	}
}

func TestVerifyTOTPWindowAndReplay(t *testing.T) {
	secret, _ := NewTOTPSecret()
	now := time.Unix(1_800_000_000, 0)
	cur := TOTPStep(now)
	if step, ok := VerifyTOTP(secret, totpCode(secret, cur), now, 0); !ok || step != cur {
		t.Fatalf("the current code must work: %d %v", step, ok)
	}
	for _, d := range []int64{-1, 1} {
		if _, ok := VerifyTOTP(secret, totpCode(secret, cur+d), now, 0); !ok {
			t.Errorf("one step of drift (%d) must work", d)
		}
	}
	for _, d := range []int64{-2, 2, 40} {
		if _, ok := VerifyTOTP(secret, totpCode(secret, cur+d), now, 0); ok {
			t.Errorf("%d steps away must not work", d)
		}
	}
	// A code already used (its step at or before lastStep) is refused, a newer one is not.
	if _, ok := VerifyTOTP(secret, totpCode(secret, cur), now, cur); ok {
		t.Fatal("a used code worked twice")
	}
	if _, ok := VerifyTOTP(secret, totpCode(secret, cur-1), now, cur); ok {
		t.Fatal("an older code worked after a newer one")
	}
	if _, ok := VerifyTOTP(secret, totpCode(secret, cur+1), now, cur); !ok {
		t.Fatal("the next code must work")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "12 456"} {
		if _, ok := VerifyTOTP(secret, bad, now, 0); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRecoveryCodesAreDistinctAndNormalise(t *testing.T) {
	codes, err := NewRecoveryCodes(10)
	if err != nil || len(codes) != 10 {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 11 || c[5] != '-' || seen[c] {
			t.Fatalf("bad or repeated code %q", c)
		}
		seen[c] = true
		if NormaliseRecoveryCode(strings.ToLower(c)+" ") != NormaliseRecoveryCode(c) {
			t.Fatal("a code typed in lower case with a space must match")
		}
		if LooksLikeTOTP(c) {
			t.Fatal("a recovery code must not look like a TOTP code")
		}
	}
	if !LooksLikeTOTP("123456") || LooksLikeTOTP("12345a") {
		t.Fatal("LooksLikeTOTP")
	}
}

func TestTOTPURI(t *testing.T) {
	u := TOTPURI("Owlery", "owner", []byte("12345678901234567890"))
	for _, want := range []string{"otpauth://totp/Owlery:owner?", "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "issuer=Owlery", "digits=6", "period=30"} {
		if !strings.Contains(u, want) {
			t.Errorf("%q missing from %s", want, u)
		}
	}
}
