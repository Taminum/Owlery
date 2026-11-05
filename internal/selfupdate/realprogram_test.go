package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Taminum/Owlery/internal/relsign"
)

// A release made of the real agent: it is built here, served the way GitHub serves a release, fetched, and the staged program is
// run for real. A fake program cannot catch what only the system's own way of running a file shows (on Windows, a name without
// .exe is not a program), and this is the step that failed on a machine once.
func TestARealAgentIsFetchedStagedAndRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the agent")
	}
	asset, err := AssetName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skip("no release program for this system")
	}
	bin := filepath.Join(t.TempDir(), "agent-"+asset)
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-X main.version=v0.5.99", "-o", bin, "github.com/Taminum/Owlery/cmd/secagent")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	prog, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := relsign.GenerateKey()
	h := sha256.Sum256(prog)
	sums := hex.EncodeToString(h[:]) + "  " + asset + "\n"
	sig, err := relsign.Sign(priv, []byte(sums))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v0.5.99/SHA256SUMS", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(sums)) })
	mux.HandleFunc("/v0.5.99/SHA256SUMS.sig", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(sig)) })
	mux.HandleFunc("/v0.5.99/"+asset, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(prog) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := filepath.Join(t.TempDir(), "update", DirStaged)
	if err := (&Fetcher{Base: srv.URL, PublicKey: pub}).Fetch(context.Background(), "v0.5.99", runtime.GOOS, runtime.GOARCH, dir); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(FileProgram, ".exe") {
		t.Errorf("a program Windows can run has .exe in its name: %q", FileProgram)
	}
	got, err := VerifyStaged(dir, pub, "v0.5.15", runtime.GOOS, runtime.GOARCH, nil) // nil: the staged program is really run
	if err != nil || got != "v0.5.99" {
		t.Fatalf("%q %v", got, err)
	}
}
