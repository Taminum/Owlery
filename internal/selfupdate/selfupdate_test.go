package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Taminum/Owlery/internal/relsign"
)

func TestVersions(t *testing.T) {
	for _, v := range []string{"v0.5.14", "v1.0.0", "v10.20.30"} {
		if !ValidVersion(v) {
			t.Errorf("%s is a release", v)
		}
	}
	for _, v := range []string{"dev", "0.5.14", "v0.5", "v0.5.14-rc1", "v1.2.3/../x", "", "v0.5.14 "} {
		if ValidVersion(v) {
			t.Errorf("%q is not a release", v)
		}
	}
	cases := []struct {
		cand, cur string
		want      bool
	}{
		{"v0.5.15", "v0.5.14", true}, {"v0.6.0", "v0.5.14", true}, {"v1.0.0", "v0.9.9", true},
		{"v0.5.14", "v0.5.14", false}, {"v0.5.13", "v0.5.14", false}, {"v0.5.15", "dev", false}, {"dev", "v0.5.14", false},
		{"v0.10.0", "v0.9.0", true},
	}
	for _, c := range cases {
		if got := Newer(c.cand, c.cur); got != c.want {
			t.Errorf("Newer(%s, %s) = %v", c.cand, c.cur, got)
		}
	}
}

func TestAssetName(t *testing.T) {
	if n, _ := AssetName("linux", "amd64"); n != "remnascope-secagent-linux-amd64" {
		t.Error(n)
	}
	if n, _ := AssetName("windows", "arm64"); n != "remnascope-secagent-windows-arm64.exe" {
		t.Error(n)
	}
	if _, err := AssetName("plan9", "amd64"); err == nil {
		t.Error("an unknown system has no program")
	}
	if _, err := AssetName("linux", "386"); err == nil {
		t.Error("an unknown processor has no program")
	}
}

// release serves a release the way GitHub does: /<version>/<file>.
func release(t *testing.T, priv string, program []byte, tamper func(sums *string)) *httptest.Server {
	t.Helper()
	h := sha256.Sum256(program)
	sums := hex.EncodeToString(h[:]) + "  remnascope-secagent-linux-amd64\n"
	sig, err := relsign.Sign(priv, []byte(sums))
	if err != nil {
		t.Fatal(err)
	}
	if tamper != nil {
		tamper(&sums)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v0.5.15/SHA256SUMS", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(sums)) })
	mux.HandleFunc("/v0.5.15/SHA256SUMS.sig", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(sig)) })
	mux.HandleFunc("/v0.5.15/remnascope-secagent-linux-amd64", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(program) })
	return httptest.NewServer(mux)
}

func TestAGoodSignedReleaseIsFetchedAndVerified(t *testing.T) {
	pub, priv, _ := relsign.GenerateKey()
	srv := release(t, priv, []byte("the new program"), nil)
	defer srv.Close()
	dir := filepath.Join(t.TempDir(), "update")
	f := &Fetcher{Base: srv.URL, PublicKey: pub}
	if err := f.Fetch(context.Background(), "v0.5.15", "linux", "amd64", dir); err != nil {
		t.Fatal(err)
	}
	said := func(string) (string, error) { return "v0.5.15\n", nil }
	if v, err := VerifyStaged(dir, pub, "v0.5.14", "linux", "amd64", said); err != nil || v != "v0.5.15" {
		t.Fatalf("%q %v", v, err)
	}
	if _, err := VerifyStaged(dir, pub, "v0.5.15", "linux", "amd64", said); err == nil {
		t.Error("the same version is not an update")
	}
	if _, err := VerifyStaged(dir, pub, "v0.6.0", "linux", "amd64", said); err == nil {
		t.Error("an older version is not an update")
	}
	if _, err := VerifyStaged(dir, pub, "dev", "linux", "amd64", said); err == nil {
		t.Error("a build that is not a release is left alone")
	}
	lie := func(string) (string, error) { return "v0.4.0", nil }
	if _, err := VerifyStaged(dir, pub, "v0.5.14", "linux", "amd64", lie); err == nil || !strings.Contains(err.Error(), "says it is") {
		t.Errorf("a program that is older than its label must not pass: %v", err)
	}
	other, _, _ := relsign.GenerateKey()
	if _, err := VerifyStaged(dir, other, "v0.5.14", "linux", "amd64", said); err == nil {
		t.Error("another key must not pass")
	}
	// Somebody swaps the staged program for another one.
	if err := os.WriteFile(filepath.Join(dir, FileProgram), []byte("another program"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyStaged(dir, pub, "v0.5.14", "linux", "amd64", said); err == nil {
		t.Error("a swapped program must not pass")
	}
}

func TestAReleaseThatIsNotWhatWasSignedLeavesNothing(t *testing.T) {
	pub, priv, _ := relsign.GenerateKey()
	ctx := context.Background()
	// The list was changed after it was signed.
	srv := release(t, priv, []byte("p"), func(s *string) { *s = strings.Replace(*s, "  remnascope", "  remnascopf", 1) })
	dir := filepath.Join(t.TempDir(), "update")
	if err := (&Fetcher{Base: srv.URL, PublicKey: pub}).Fetch(ctx, "v0.5.15", "linux", "amd64", dir); err == nil {
		t.Error("a changed list must not pass")
	}
	srv.Close()
	if _, err := os.Stat(dir); err == nil {
		t.Error("nothing is staged when a check fails")
	}
	// Signed by somebody else.
	_, otherPriv, _ := relsign.GenerateKey()
	srv2 := release(t, otherPriv, []byte("p"), nil)
	defer srv2.Close()
	if err := (&Fetcher{Base: srv2.URL, PublicKey: pub}).Fetch(ctx, "v0.5.15", "linux", "amd64", dir); err == nil {
		t.Error("another signer must not pass")
	}
	// A bad version is not even asked for.
	if err := (&Fetcher{Base: srv2.URL, PublicKey: pub}).Fetch(ctx, "../etc", "linux", "amd64", dir); err == nil {
		t.Error("a bad version is refused")
	}
}
