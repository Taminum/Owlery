package secrets

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func testRing(t *testing.T, versions ...int) *Keyring {
	t.Helper()
	keys := map[int][]byte{}
	for _, v := range versions {
		keys[v] = bytes.Repeat([]byte{byte(v)}, 32)
	}
	r, err := NewKeyring(keys, versions[len(versions)-1])
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const panelA = "aaaaaaaa-0000-4000-8000-000000000001"
const panelB = "bbbbbbbb-0000-4000-8000-000000000002"

func TestRoundTrip(t *testing.T) {
	r := testRing(t, 1)
	s, err := r.Seal(panelA, []byte("token-value"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(s.Ciphertext, []byte("token-value")) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := r.Open(panelA, s)
	if err != nil || string(got) != "token-value" {
		t.Fatalf("round trip: %q %v", got, err)
	}
}

func TestNonceIsFreshEveryTime(t *testing.T) {
	r := testRing(t, 1)
	a, _ := r.Seal(panelA, []byte("same"))
	b, _ := r.Seal(panelA, []byte("same"))
	if bytes.Equal(a.Nonce, b.Nonce) || bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("nonce reuse")
	}
	if len(a.Nonce) != 12 {
		t.Fatalf("nonce must be 96 bits, got %d bytes", len(a.Nonce))
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	r := testRing(t, 1)
	s, _ := r.Seal(panelA, []byte("token"))
	s.Ciphertext[0] ^= 0xff
	if _, err := r.Open(panelA, s); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

func TestCiphertextBoundToPanel(t *testing.T) {
	r := testRing(t, 1)
	s, _ := r.Seal(panelA, []byte("token"))
	if _, err := r.Open(panelB, s); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("copying a secret to another panel must fail, got %v", err)
	}
}

func TestCiphertextBoundToKeyVersion(t *testing.T) {
	r := testRing(t, 1, 2)
	s, _ := r.Seal(panelA, []byte("token")) // sealed with v2
	s.KeyVersion = 1                        // attacker edits the column
	if _, err := r.Open(panelA, s); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("version downgrade must fail, got %v", err)
	}
}

func TestUnknownKeyVersion(t *testing.T) {
	r := testRing(t, 1)
	if _, err := r.Open(panelA, Sealed{Ciphertext: []byte("x"), Nonce: make([]byte, 12), KeyVersion: 9}); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("got %v", err)
	}
}

func TestRotationReencryptsWithoutExposure(t *testing.T) {
	old := testRing(t, 1)
	s1, _ := old.Seal(panelA, []byte("token"))

	both := testRing(t, 1, 2) // v2 active, v1 still present for decrypt
	s2, changed, err := both.Reseal(panelA, s1)
	if err != nil || !changed || s2.KeyVersion != 2 {
		t.Fatalf("reseal: %+v changed=%v err=%v", s2, changed, err)
	}
	pt, err := both.Open(panelA, s2)
	if err != nil || string(pt) != "token" {
		t.Fatalf("after rotation: %q %v", pt, err)
	}
	if _, changed, _ := both.Reseal(panelA, s2); changed {
		t.Fatal("already-current secret must not be re-encrypted")
	}
	only2 := testRing(t, 2)
	if _, err := only2.Open(panelA, s2); err != nil {
		t.Fatalf("v1 can be retired after rotation: %v", err)
	}
}

func TestParseKeyring(t *testing.T) {
	l1, _ := GenerateKeyLine(1)
	l2, _ := GenerateKeyLine(2)
	r, err := ParseKeyring("# comment\n"+l1+"\n\n"+l2+"\n", 0)
	if err != nil || r.ActiveVersion() != 2 {
		t.Fatalf("highest version must be active: %v %v", r, err)
	}
	r, err = ParseKeyring(l1+"\n"+l2, 1)
	if err != nil || r.ActiveVersion() != 1 {
		t.Fatalf("override: %v", err)
	}
	for _, bad := range []string{"", "nonsense", "1:not-base64!!", "1:" + "QUJD", "x:QUJD"} {
		if _, err := ParseKeyring(bad, 0); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestGeneratedKeysAreDistinct(t *testing.T) {
	a, _ := GenerateKeyLine(1)
	b, _ := GenerateKeyLine(1)
	if a == b || !strings.HasPrefix(a, "1:") {
		t.Fatal("keys must be random")
	}
}

func TestDerivedKeysArePurposeBound(t *testing.T) {
	r := testRing(t, 1)
	if bytes.Equal(r.DeriveKey("csrf"), r.DeriveKey("other")) {
		t.Fatal("different purposes must give different keys")
	}
	if bytes.Equal(r.DeriveKey("csrf"), bytes.Repeat([]byte{1}, 32)) {
		t.Fatal("derived key must not equal the master key")
	}
}
