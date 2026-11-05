package relsign

import (
	"errors"
	"strings"
	"testing"
)

const sums = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  remnascope-secagent-linux-amd64\n" +
	"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB  remnascope-secagent-windows-amd64.exe\n"

func TestASignedListIsAcceptedAndAnyChangeIsNot(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(priv, []byte(sums))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, []byte(sums), sig); err != nil {
		t.Fatalf("a good signature: %v", err)
	}
	tampered := strings.Replace(sums, "aaaa", "cccc", 1)
	if err := Verify(pub, []byte(tampered), sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a changed list must not pass: %v", err)
	}
	otherPub, _, _ := GenerateKey()
	if err := Verify(otherPub, []byte(sums), sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("another key must not pass: %v", err)
	}
	if err := Verify(pub, []byte(sums), "not base64!"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("garbage must not pass: %v", err)
	}
	if err := Verify("short", []byte(sums), sig); err == nil {
		t.Fatal("a bad public key must be refused")
	}
	if _, err := Sign("short", []byte(sums)); err == nil {
		t.Fatal("a bad private key must be refused")
	}
}

func TestHashFor(t *testing.T) {
	h, err := HashFor([]byte(sums), "remnascope-secagent-windows-amd64.exe")
	if err != nil || h != strings.Repeat("b", 64) {
		t.Fatalf("%q %v", h, err)
	}
	if _, err := HashFor([]byte(sums), "remnascope-secagent-linux-arm64"); err == nil {
		t.Fatal("a file that is not in the list has no hash")
	}
	if _, err := HashFor([]byte("short  x\n"), "x"); err == nil {
		t.Fatal("a hash of the wrong length is not a hash")
	}
}
