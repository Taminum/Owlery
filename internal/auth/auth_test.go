package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/store"
)

var fast = Argon2Params{MemoryKiB: 8, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}

func TestPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery", fast)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") || strings.Contains(h, "correct") {
		t.Fatalf("bad hash %q", h)
	}
	if ok, _ := VerifyPassword("correct horse battery", h); !ok {
		t.Fatal("right password rejected")
	}
	if ok, _ := VerifyPassword("correct horse batterz", h); ok {
		t.Fatal("wrong password accepted")
	}
	h2, _ := HashPassword("correct horse battery", fast)
	if h == h2 {
		t.Fatal("salts must differ")
	}
}

func TestWeakHashParametersAreFlaggedForRehash(t *testing.T) {
	h, _ := HashPassword("correct horse battery", fast)
	ok, rehash := VerifyPassword("correct horse battery", h)
	if !ok || !rehash {
		t.Fatalf("ok=%v rehash=%v", ok, rehash)
	}
	strong, _ := HashPassword("correct horse battery", DefaultParams)
	if _, rehash := VerifyPassword("correct horse battery", strong); rehash {
		t.Fatal("current parameters must not trigger a rehash")
	}
}

func TestVerifyRejectsMalformedAndHostileHashes(t *testing.T) {
	for _, h := range []string{"", "plain", "$argon2id$v=19$m=1,t=1,p=1$AAAA", "$bcrypt$v=19$m=8,t=1,p=1$AAAA$AAAA",
		"$argon2id$v=19$m=4294967295,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		if ok, _ := VerifyPassword("whatever-password", h); ok {
			t.Errorf("%q must not verify", h)
		}
	}
	h, _ := HashPassword("correct horse battery", fast)
	if ok, _ := VerifyPassword(strings.Repeat("a", MaxPasswordLen+1), h); ok {
		t.Fatal("oversized passwords are refused before hashing")
	}
}

func TestPasswordPolicy(t *testing.T) {
	for _, bad := range []string{"short", "elevenchars", "            ", strings.Repeat("a", 300), "my-alice-password-1"} {
		if ValidatePassword("alice", bad) == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	for _, good := range []string{"twelve chars!", "a long passphrase with spaces", "пароль-на-русском-языке"} {
		if err := ValidatePassword("alice", good); err != nil {
			t.Errorf("%q should pass: %v", good, err)
		}
	}
}

func TestTokens(t *testing.T) {
	a, _ := NewToken()
	b, _ := NewToken()
	if a == b || len(a) < 40 {
		t.Fatalf("tokens must be long and unique: %q %q", a, b)
	}
	if string(HashToken(a)) == a || len(HashToken(a)) != 32 {
		t.Fatal("hash shape")
	}
	if string(HashToken(a)) == string(HashToken(b)) {
		t.Fatal("different tokens must hash differently")
	}
}

func TestCSRFIsSessionBoundAndKeyBound(t *testing.T) {
	k1, k2 := []byte("0123456789abcdef0123456789abcdef"), []byte("fedcba9876543210fedcba9876543210")
	tok := CSRFToken(k1, "session-1")
	if !CSRFValid(k1, "session-1", tok) {
		t.Fatal("valid token rejected")
	}
	if CSRFValid(k1, "session-2", tok) {
		t.Fatal("token from another session accepted")
	}
	if CSRFValid(k2, "session-1", tok) {
		t.Fatal("token under another key accepted")
	}
	if CSRFValid(k1, "session-1", "") || CSRFValid(k1, "session-1", tok+"x") {
		t.Fatal("empty or altered token accepted")
	}
}

func TestRoleMatrix(t *testing.T) {
	const home, work, other = "home", "work", "other"
	owner := Actor{IsOwner: true}
	opHome := Actor{Roles: map[string]Role{home: RoleOperator}}
	viewWork := Actor{Roles: map[string]Role{work: RoleViewer}}
	adminBoth := Actor{Roles: map[string]Role{home: RoleAdmin, work: RoleAdmin}}

	type c struct {
		who   Actor
		panel string
		perm  Perm
		want  bool
	}
	for i, tc := range []c{
		{owner, other, PermOwner, true}, {owner, home, PermAdmin, true},
		{viewWork, work, PermView, true}, {viewWork, work, PermOperate, false}, {viewWork, work, PermAdmin, false},
		{viewWork, home, PermView, false}, // Work-only viewer cannot see Home
		{opHome, home, PermView, true}, {opHome, home, PermOperate, true}, {opHome, home, PermAdmin, false}, {opHome, work, PermView, false},
		{adminBoth, home, PermAdmin, true}, {adminBoth, work, PermOwner, false}, {adminBoth, other, PermView, false},
		{Actor{}, home, PermView, false},
	} {
		if got := tc.who.Can(tc.panel, tc.perm); got != tc.want {
			t.Errorf("case %d: Can(%s, %d) = %v, want %v", i, tc.panel, tc.perm, got, tc.want)
		}
	}
	if adminBoth.CanGlobal() || !owner.CanGlobal() {
		t.Fatal("only owners have global rights; a panel admin must not create panels or manage accounts")
	}
}

func TestScopes(t *testing.T) {
	a := Actor{Roles: map[string]Role{"p1": RoleViewer, "p2": RoleOperator, "p3": RoleAdmin}}
	if !a.Scope().Allows("p1") || a.Scope().Allows("p9") || a.Scope().All {
		t.Fatalf("scope: %+v", a.Scope())
	}
	op := a.ScopeAt(PermOperate)
	if op.Allows("p1") || !op.Allows("p2") || !op.Allows("p3") {
		t.Fatalf("operate scope: %+v", op)
	}
	if !(Actor{IsOwner: true}).Scope().All {
		t.Fatal("owner sees all")
	}
}

func TestNewActorFromStore(t *testing.T) {
	a := NewActor(store.Account{ID: "a1", Username: "u", IsOwner: false}, []store.Membership{{PanelID: "p", Role: "viewer"}})
	if a.RoleOn("p") != "viewer" || a.RoleOn("q") != "" {
		t.Fatalf("%+v", a)
	}
	if (Actor{IsOwner: true}).RoleOn("anything") != "owner" {
		t.Fatal("owner role")
	}
}

func TestMaskUsername(t *testing.T) {
	for in, want := range map[string]string{"alice": "al•••", "ab": "••", "": "", "verylongusername": "ve••••••", "юзер": "юз••"} {
		if got := MaskUsername(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(0.001, 3)
	now := time.Now()
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !l.Allow("ip1") {
			t.Fatalf("burst call %d denied", i)
		}
	}
	if l.Allow("ip1") {
		t.Fatal("over burst must be denied")
	}
	if !l.Allow("ip2") {
		t.Fatal("keys are independent")
	}
	l.now = func() time.Time { return now.Add(2000 * time.Second) }
	if !l.Allow("ip1") {
		t.Fatal("bucket must refill")
	}
}

func TestLimiterMemoryIsBounded(t *testing.T) {
	l := NewLimiter(1, 1)
	l.max = 100
	for i := 0; i < 1000; i++ {
		l.Allow(string(rune('a'+i%26)) + time.Duration(i).String())
	}
	if len(l.buckets) > 100 {
		t.Fatalf("buckets grew to %d", len(l.buckets))
	}
}
