package secagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/Taminum/Owlery/internal/relsign"
	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/selfupdate"
)

func updAgent(t *testing.T, allow bool, version string) (*agent, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "update")
	return &agent{cfg: Config{AllowUpdate: allow, UpdateDir: dir, Version: version, Log: slog.Default()}}, dir
}

func signedRelease(t *testing.T, pub, priv string, program []byte) *httptest.Server {
	t.Helper()
	asset, err := selfupdate.AssetName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skip("no release program for this system")
	}
	h := sha256.Sum256(program)
	sums := hex.EncodeToString(h[:]) + "  " + asset + "\n"
	sig, err := relsign.Sign(priv, []byte(sums))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v0.5.15/SHA256SUMS", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(sums)) })
	mux.HandleFunc("/v0.5.15/SHA256SUMS.sig", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(sig)) })
	mux.HandleFunc("/v0.5.15/"+asset, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(program) })
	return httptest.NewServer(mux)
}

func TestAnAgentIsUpdatedOnlyWhenTheMachineAllowedItAndItIsARelease(t *testing.T) {
	cases := []struct {
		name    string
		allow   bool
		version string
		offered bool
	}{
		{"allowed release", true, "v0.5.14", true},
		{"not allowed", false, "v0.5.14", false},
		{"a development build", true, "dev", false},
	}
	for _, c := range cases {
		a, _ := updAgent(t, c.allow, c.version)
		if got := slices.Contains(a.capabilities(false), secproto.CapSelfUpdate); got != c.offered {
			t.Errorf("%s: capability offered = %v", c.name, got)
		}
	}
	a, _ := updAgent(t, false, "v0.5.14")
	if res := a.update(context.Background(), secproto.UpdateReq{ID: "1", Version: "v0.5.15"}); res.OK || res.Error != "not_allowed" {
		t.Errorf("a machine that did not allow it refuses: %+v", res)
	}
}

func TestUpdateRefusesWhatIsNotNewerOrNotAVersion(t *testing.T) {
	a, dir := updAgent(t, true, "v0.5.14")
	for version, want := range map[string]string{"v0.5.14": "up_to_date", "v0.5.13": "up_to_date", "latest": "bad_version", "../x": "bad_version", "": "bad_version"} {
		res := a.update(context.Background(), secproto.UpdateReq{ID: "1", Version: version})
		if res.OK || res.Error != want {
			t.Errorf("%q: %+v, want %s", version, res, want)
		}
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("nothing is fetched or kept for a request that is refused")
	}
}

func TestUpdateFetchesChecksAndHandsOnARelease(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the hand-over to the root helper is Linux")
	}
	pub, priv, _ := relsign.GenerateKey()
	srv := signedRelease(t, pub, priv, []byte("v0.5.15\nnew"))
	defer srv.Close()
	a, dir := updAgent(t, true, "v0.5.14")
	a.cfg.UpdateFetcher = &selfupdate.Fetcher{Base: srv.URL, PublicKey: pub}
	res := a.update(context.Background(), secproto.UpdateReq{ID: "1", Version: "v0.5.15"})
	if !res.OK {
		t.Fatalf("%+v", res)
	}
	if _, err := os.Stat(filepath.Join(dir, selfupdate.FileReady)); err != nil {
		t.Error("the root helper is called by the file 'ready'")
	}
	if _, err := os.Stat(filepath.Join(dir, selfupdate.DirStaged, selfupdate.FileProgram)); err != nil {
		t.Error("the program is staged")
	}
	// Signed by another key: nothing is handed on.
	other, _, _ := relsign.GenerateKey()
	a2, dir2 := updAgent(t, true, "v0.5.14")
	a2.cfg.UpdateFetcher = &selfupdate.Fetcher{Base: srv.URL, PublicKey: other}
	if res := a2.update(context.Background(), secproto.UpdateReq{ID: "2", Version: "v0.5.15"}); res.OK {
		t.Fatal("a release signed by somebody else must be refused")
	}
	if _, err := os.Stat(filepath.Join(dir2, selfupdate.FileReady)); err == nil {
		t.Error("nothing is handed on")
	}
}

func TestAConnectedAgentTellsItsVersion(t *testing.T) {
	a, dir := updAgent(t, true, "v0.5.15")
	a.onConnected()
	b, err := os.ReadFile(filepath.Join(dir, selfupdate.FileHealthy))
	if err != nil || string(b) != "v0.5.15\n" {
		t.Fatalf("%q %v", b, err)
	}
	(&agent{cfg: Config{Version: "v0.5.15"}}).onConnected() // no place to keep it: nothing happens
}
