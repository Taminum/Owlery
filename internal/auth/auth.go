// Package auth holds password hashing, session tokens, CSRF tokens and the role model.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/Taminum/RemnaScope/internal/store"
)

// --- passwords -----------------------------------------------------------

type Argon2Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
	KeyLen    uint32
	SaltLen   uint32
}

// DefaultParams follows the RFC 9106 "second recommended option" scale.
var DefaultParams = Argon2Params{MemoryKiB: 64 * 1024, Time: 3, Threads: 2, KeyLen: 32, SaltLen: 16}

const (
	MinPasswordLen = 12
	MaxPasswordLen = 256 // bounds hashing cost for hostile input
)

var ErrWeakPassword = errors.New("password must be at least 12 characters, at most 256, and not contain the username")

func ValidatePassword(username, password string) error {
	n := utf8.RuneCountInString(password)
	if n < MinPasswordLen || len(password) > MaxPasswordLen {
		return ErrWeakPassword
	}
	if u := strings.ToLower(strings.TrimSpace(username)); u != "" && strings.Contains(strings.ToLower(password), u) {
		return ErrWeakPassword
	}
	if strings.TrimSpace(password) == "" {
		return ErrWeakPassword
	}
	return nil
}

func HashPassword(password string, p Argon2Params) (string, error) {
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

type parsedHash struct {
	p    Argon2Params
	salt []byte
	key  []byte
}

func parseHash(h string) (parsedHash, error) {
	parts := strings.Split(h, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return parsedHash{}, errors.New("auth: unsupported hash format")
	}
	var ver int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &ver); err != nil || ver != argon2.Version {
		return parsedHash{}, errors.New("auth: unsupported argon2 version")
	}
	var ph parsedHash
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &ph.p.MemoryKiB, &ph.p.Time, &ph.p.Threads); err != nil {
		return parsedHash{}, errors.New("auth: bad argon2 parameters")
	}
	var err error
	if ph.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return parsedHash{}, err
	}
	if ph.key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return parsedHash{}, err
	}
	ph.p.KeyLen, ph.p.SaltLen = uint32(len(ph.key)), uint32(len(ph.salt))
	return ph, nil
}

// VerifyPassword compares in constant time. needsRehash is true when the stored
// parameters are weaker than the current defaults.
func VerifyPassword(password, hash string) (ok, needsRehash bool) {
	ph, err := parseHash(hash)
	if err != nil || len(password) > MaxPasswordLen || ph.p.MemoryKiB > 1<<20 || ph.p.Time > 10 {
		return false, false
	}
	key := argon2.IDKey([]byte(password), ph.salt, ph.p.Time, ph.p.MemoryKiB, ph.p.Threads, ph.p.KeyLen)
	if subtle.ConstantTimeCompare(key, ph.key) != 1 {
		return false, false
	}
	d := DefaultParams
	return true, ph.p.MemoryKiB < d.MemoryKiB || ph.p.Time < d.Time || ph.p.Threads < d.Threads
}

// DummyHash is verified when the username does not exist, so "no such user" and
// "wrong password" take the same time.
func DummyHash() string {
	h, _ := HashPassword("remnascope-dummy-password", DefaultParams)
	return h
}

// --- sessions and CSRF -------------------------------------------------------

// NewToken returns a 256-bit URL-safe random token.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken is what the database stores; the raw token only ever lives in the cookie.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// CSRFToken is derived from the session and a server-side key, so nothing extra is
// stored and a token from one session is useless in another.
func CSRFToken(key []byte, sessionID string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("csrf|" + sessionID))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func CSRFValid(key []byte, sessionID, presented string) bool {
	want := CSRFToken(key, sessionID)
	return subtle.ConstantTimeCompare([]byte(want), []byte(presented)) == 1
}

// --- roles ---------------------------------------------------------------------

type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
	RoleOwner    Role = "owner" // global; only ever derived from accounts.is_owner
)

func ValidRole(r string) bool {
	return r == string(RoleViewer) || r == string(RoleOperator) || r == string(RoleAdmin)
}

func rank(r Role) int {
	switch r {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 3
	case RoleOwner:
		return 4
	}
	return 0
}

// Perm is the minimum role an action needs on a panel.
type Perm int

const (
	PermView    Perm = iota + 1 // see panel data
	PermOperate                 // test a connection, run a manual sync
	PermAdmin                   // edit, rotate token, disable
	PermOwner                   // create/delete panels, manage accounts
)

func (p Perm) need() int { return int(p) }

type Actor struct {
	AccountID string
	Username  string
	IsOwner   bool
	Roles     map[string]Role // panelID -> role
}

func NewActor(a store.Account, ms []store.Membership) Actor {
	act := Actor{AccountID: a.ID, Username: a.Username, IsOwner: a.IsOwner, Roles: map[string]Role{}}
	for _, m := range ms {
		act.Roles[m.PanelID] = Role(m.Role)
	}
	return act
}

func (a Actor) roleOn(panelID string) Role {
	if a.IsOwner {
		return RoleOwner
	}
	return a.Roles[panelID]
}

// Can reports whether the actor holds at least perm on the panel. Unknown panels give false.
func (a Actor) Can(panelID string, p Perm) bool {
	return rank(a.roleOn(panelID)) >= p.need()
}

// CanGlobal covers actions not tied to a panel (create panel, manage accounts).
func (a Actor) CanGlobal() bool { return a.IsOwner }

// Scope is the set of panels the actor can see at all.
func (a Actor) Scope() store.Scope {
	if a.IsOwner {
		return store.Scope{All: true}
	}
	ids := make([]string, 0, len(a.Roles))
	for id := range a.Roles {
		ids = append(ids, id)
	}
	return store.Scope{IDs: ids}
}

// ScopeAt narrows the scope to panels where the actor holds at least perm.
func (a Actor) ScopeAt(p Perm) store.Scope {
	if a.IsOwner {
		return store.Scope{All: true}
	}
	var ids []string
	for id, r := range a.Roles {
		if rank(r) >= p.need() {
			ids = append(ids, id)
		}
	}
	return store.Scope{IDs: ids}
}

func (a Actor) RoleOn(panelID string) string { return string(a.roleOn(panelID)) }

// MaskUsername keeps the first two characters; viewers never see full account names.
func MaskUsername(s string) string {
	r := []rune(s)
	if len(r) <= 2 {
		return strings.Repeat("•", len(r))
	}
	return string(r[:2]) + strings.Repeat("•", min(len(r)-2, 6))
}
