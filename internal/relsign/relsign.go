// Package relsign signs and checks a release. A release is the file SHA256SUMS (the hash of every program in it); the
// signature is made over that file, so one signature covers every program. The agent holds the public half and installs
// nothing the private half did not sign.
package relsign

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
)

// GenerateKey makes a key pair. Both halves are returned in base64; the private one is the seed, which is all that is
// needed to sign.
func GenerateKey() (public, private string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv.Seed()), nil
}

func privateFrom(seedB64 string) (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(seedB64))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("relsign: the private key is not a key of this tool")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Sign signs msg with the private key and returns the signature in base64.
func Sign(seedB64 string, msg []byte) (string, error) {
	priv, err := privateFrom(seedB64)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)), nil
}

// ErrBadSignature means the file was not signed by the key, or was changed after.
var ErrBadSignature = errors.New("relsign: the signature does not match")

// Verify checks sigB64 over msg against the public key in base64.
func Verify(pubB64 string, msg []byte, sigB64 string) error {
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("relsign: the public key is not a key of this tool")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return ErrBadSignature
	}
	return nil
}

// HashFor finds the hash of the named file in the text of SHA256SUMS ("<hash>  <name>" per line).
func HashFor(sums []byte, name string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", errors.New("relsign: the file is not in the list of the release")
}

// ReleaseKey is the public half of the key Owlery releases are signed with. The private half lives only in the secrets
// of the repository's GitHub account (OWL_SIGN_KEY) and is never in this tree.
const ReleaseKey = "nvZn9o2pnogEHvEog3unuB8YBrIEmVoRdqqR91RdhXA="
