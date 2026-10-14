// Package secrets encrypts panel API tokens at rest.
//
// AES-256-GCM, a fresh random 96-bit nonce per encryption, and AAD that binds the
// ciphertext to the panel UUID and the key version. A ciphertext copied to another
// panel row, or one whose key_version column is edited, fails authentication.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

const (
	keyLen   = 32
	nonceLen = 12
	aadLabel = "remnascope/panel-token/v1"
)

var (
	ErrNoKey      = errors.New("secrets: no key configured")
	ErrUnknownKey = errors.New("secrets: unknown key version")
	ErrDecrypt    = errors.New("secrets: decryption failed")
)

type Sealed struct {
	Ciphertext []byte
	Nonce      []byte
	KeyVersion int
}

// Keyring holds every key version still needed to decrypt, and the one used to encrypt.
type Keyring struct {
	keys   map[int][]byte
	active int
}

// NewKeyring builds a keyring from version->32-byte key. active must be present.
func NewKeyring(keys map[int][]byte, active int) (*Keyring, error) {
	if len(keys) == 0 {
		return nil, ErrNoKey
	}
	cp := make(map[int][]byte, len(keys))
	for v, k := range keys {
		if len(k) != keyLen {
			return nil, fmt.Errorf("secrets: key v%d must be %d bytes, got %d", v, keyLen, len(k))
		}
		cp[v] = append([]byte(nil), k...)
	}
	if _, ok := cp[active]; !ok {
		return nil, fmt.Errorf("secrets: active key v%d not in keyring", active)
	}
	return &Keyring{keys: cp, active: active}, nil
}

// ParseKeyring reads lines of the form "<version>:<base64 key>". Blank lines and
// lines starting with # are ignored. The highest version is active unless activeOverride > 0.
func ParseKeyring(text string, activeOverride int) (*Keyring, error) {
	keys := map[int][]byte{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ver, b64, ok := strings.Cut(line, ":")
		if !ok {
			return nil, errors.New("secrets: key line must look like <version>:<base64>")
		}
		v, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(ver), "v"))
		if err != nil || v <= 0 {
			return nil, errors.New("secrets: bad key version")
		}
		k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil {
			return nil, errors.New("secrets: key is not valid base64")
		}
		keys[v] = k
	}
	if len(keys) == 0 {
		return nil, ErrNoKey
	}
	active := activeOverride
	if active == 0 {
		vs := make([]int, 0, len(keys))
		for v := range keys {
			vs = append(vs, v)
		}
		sort.Ints(vs)
		active = vs[len(vs)-1]
	}
	return NewKeyring(keys, active)
}

// LoadKeyringFile reads a keyring from a file (a Docker/host secret).
func LoadKeyringFile(path string, activeOverride int) (*Keyring, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secrets: read key file: %w", err)
	}
	return ParseKeyring(string(b), activeOverride)
}

// GenerateKeyLine returns a fresh "<version>:<base64>" line. Callers write it to a
// secret file; it is never logged.
func GenerateKeyLine(version int) (string, error) {
	k := make([]byte, keyLen)
	if _, err := rand.Read(k); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%s", version, base64.StdEncoding.EncodeToString(k)), nil
}

func (k *Keyring) ActiveVersion() int { return k.active }

func aad(panelID string, version int) []byte {
	return []byte(aadLabel + "|" + panelID + "|" + strconv.Itoa(version))
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// Seal encrypts plaintext for the given panel with the active key.
func (k *Keyring) Seal(panelID string, plaintext []byte) (Sealed, error) {
	g, err := gcm(k.keys[k.active])
	if err != nil {
		return Sealed{}, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return Sealed{}, err
	}
	ct := g.Seal(nil, nonce, plaintext, aad(panelID, k.active))
	return Sealed{Ciphertext: ct, Nonce: nonce, KeyVersion: k.active}, nil
}

// Open decrypts a stored secret. Any tampering, wrong panel or wrong version
// yields ErrDecrypt with no further detail.
func (k *Keyring) Open(panelID string, s Sealed) ([]byte, error) {
	key, ok := k.keys[s.KeyVersion]
	if !ok {
		return nil, ErrUnknownKey
	}
	if len(s.Nonce) != nonceLen {
		return nil, ErrDecrypt
	}
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	pt, err := g.Open(nil, s.Nonce, s.Ciphertext, aad(panelID, s.KeyVersion))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// Reseal re-encrypts under the active key. It returns the new Sealed and whether anything changed.
func (k *Keyring) Reseal(panelID string, s Sealed) (Sealed, bool, error) {
	if s.KeyVersion == k.active {
		return s, false, nil
	}
	pt, err := k.Open(panelID, s)
	if err != nil {
		return Sealed{}, false, err
	}
	defer wipe(pt)
	n, err := k.Seal(panelID, pt)
	return n, true, err
}

// DeriveKey returns a purpose-bound subkey (e.g. for CSRF tokens) from the active key,
// so the master key itself is never used outside encryption.
func (k *Keyring) DeriveKey(purpose string) []byte {
	m := hmac.New(sha256.New, k.keys[k.active])
	m.Write([]byte("remnascope/derive/" + purpose))
	return m.Sum(nil)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
