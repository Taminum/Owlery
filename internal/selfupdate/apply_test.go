package selfupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/relsign"
)

// A world with an installed program, a signed release staged by Fetch, and a restart that is a function.
type world struct {
	dir, install, pub string
	restarts          int
	onRestart         func(w *world) // what the "new agent" does when it is started
	a                 *Applier
}

// versionOf says what a program file claims to be: the first line of the file.
func versionOf(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return line, nil
}

func newWorld(t *testing.T, newVersion string) *world {
	t.Helper()
	pub, priv, _ := relsign.GenerateKey()
	w := &world{dir: filepath.Join(t.TempDir(), "update"), install: filepath.Join(t.TempDir(), "secagent"), pub: pub}
	if err := os.WriteFile(w.install, []byte("v0.5.14\nold"), 0o755); err != nil {
		t.Fatal(err)
	}
	srv := release(t, priv, []byte(newVersion+"\nnew"), nil)
	t.Cleanup(srv.Close)
	if err := (&Fetcher{Base: srv.URL, PublicKey: pub}).Fetch(context.Background(), "v0.5.15", "linux", "amd64", filepath.Join(w.dir, DirStaged)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.dir, FileReady), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w.a = &Applier{UpdateDir: w.dir, Install: w.install, Wait: 300 * time.Millisecond, Poll: 10 * time.Millisecond, GOOS: "linux", GOARCH: "amd64", PublicKey: pub, Version: versionOf,
		Restart: func() error {
			w.restarts++
			if w.onRestart != nil {
				w.onRestart(w)
			}
			return nil
		}}
	return w
}

func (w *world) installed(t *testing.T) string {
	t.Helper()
	v, err := versionOf(w.install)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestTheNewAgentThatConnectsStays(t *testing.T) {
	w := newWorld(t, "v0.5.15")
	w.onRestart = func(w *world) { // the new agent writes its version once it is connected
		if w.restarts == 1 {
			_ = os.WriteFile(filepath.Join(w.dir, FileHealthy), []byte("v0.5.15\n"), 0o600)
		}
	}
	if err := w.a.Apply(); err != nil {
		t.Fatal(err)
	}
	if got := w.installed(t); got != "v0.5.15" {
		t.Errorf("installed: %s", got)
	}
	if w.restarts != 1 {
		t.Errorf("restarts: %d", w.restarts)
	}
	if _, err := os.Stat(filepath.Join(w.dir, FileReady)); err == nil {
		t.Error("the request is taken off so that it is not run twice")
	}
	if _, err := os.Stat(filepath.Join(w.dir, DirStaged)); err == nil {
		t.Error("what was installed is cleared away")
	}
	if got, _ := versionOf(w.install + ".prev"); got != "v0.5.14" {
		t.Errorf("the old program is kept: %q", got)
	}
}

func TestANewAgentThatNeverConnectsIsRolledBack(t *testing.T) {
	w := newWorld(t, "v0.5.15")
	if err := w.a.Apply(); err == nil || !strings.Contains(err.Error(), "did not connect") {
		t.Fatalf("it must say the new agent did not connect: %v", err)
	}
	if got := w.installed(t); got != "v0.5.14" {
		t.Errorf("the old one is back: %s", got)
	}
	if w.restarts != 2 {
		t.Errorf("the new one was started, then the old one: %d restarts", w.restarts)
	}
}

func TestAnAgentThatReportsAnotherVersionIsNotTaken(t *testing.T) {
	w := newWorld(t, "v0.5.15")
	w.onRestart = func(w *world) { _ = os.WriteFile(filepath.Join(w.dir, FileHealthy), []byte("v0.5.14\n"), 0o600) } // the old one still running
	if err := w.a.Apply(); err == nil {
		t.Fatal("the old agent still running is not the new one")
	}
	if got := w.installed(t); got != "v0.5.14" {
		t.Errorf("rolled back: %s", got)
	}
}

func TestARestartThatFailsPutsTheOldProgramBack(t *testing.T) {
	w := newWorld(t, "v0.5.15")
	n := 0
	w.a.Restart = func() error {
		n++
		if n == 1 {
			return errors.New("systemctl failed")
		}
		return nil
	}
	if err := w.a.Apply(); err == nil {
		t.Fatal("a failed restart is an error")
	}
	if got := w.installed(t); got != "v0.5.14" {
		t.Errorf("rolled back: %s", got)
	}
}

func TestNothingIsInstalledThatIsNotSignedNewerAndWhatItSays(t *testing.T) {
	// A program that says it is older than its label: a replay of an old signed release.
	w := newWorld(t, "v0.4.0")
	if err := w.a.Apply(); err == nil || !strings.Contains(err.Error(), "says it is") {
		t.Fatalf("%v", err)
	}
	if w.installed(t) != "v0.5.14" || w.restarts != 0 {
		t.Error("nothing is changed and nothing is restarted")
	}
	// Staged files from somebody else's key.
	w2 := newWorld(t, "v0.5.15")
	other, _, _ := relsign.GenerateKey()
	w2.a.PublicKey = other
	if err := w2.a.Apply(); err == nil {
		t.Fatal("another key must not pass")
	}
	if w2.installed(t) != "v0.5.14" || w2.restarts != 0 {
		t.Error("nothing is changed and nothing is restarted")
	}
	// Nothing staged at all.
	w3 := newWorld(t, "v0.5.15")
	_ = os.RemoveAll(filepath.Join(w3.dir, DirStaged))
	if err := w3.a.Apply(); err == nil {
		t.Fatal("nothing staged is not an update")
	}
}
