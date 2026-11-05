package selfupdate

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Files the agent and the root helper pass each other in the update directory.
const (
	DirStaged   = "staged"  // what Fetch left
	FileReady   = "ready"   // the agent writes it when the staged release is checked and waits to be installed
	FileHealthy = "healthy" // the agent writes its own version into it once it is connected to the server
)

// Applier installs a staged release as root and watches that the new agent comes up. On Linux the agent cannot write the
// directory its program is in, so a small root unit runs this, started by a path unit when "ready" appears. It trusts
// nothing in the update directory: the agent that wrote it may be the thing that was broken into, so the release is checked
// again here, against the release key, before anything is replaced.
type Applier struct {
	UpdateDir string // the agent's own update directory
	Install   string // the installed program
	Restart   func() error
	Wait      time.Duration // how long the new agent has to report that it is connected
	Poll      time.Duration
	GOOS      string
	GOARCH    string
	PublicKey string // "" is the release key
	Version   func(path string) (string, error)
	Log       *slog.Logger
}

func (a *Applier) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// Apply installs what is staged, or does nothing and says why. It returns once the new agent has reported in or the old one
// is back.
func (a *Applier) Apply() error {
	_ = os.Remove(filepath.Join(a.UpdateDir, FileReady)) // so the path unit does not start this again for the same request
	staged := filepath.Join(a.UpdateDir, DirStaged)
	current, err := a.Version(a.Install)
	if err != nil {
		return fmt.Errorf("selfupdate: the installed program: %w", err)
	}
	current = strings.TrimSpace(current)
	version, err := VerifyStaged(staged, a.PublicKey, current, a.GOOS, a.GOARCH, a.Version)
	if err != nil {
		return err
	}
	prev := a.Install + ".prev"
	if err := copyFile(a.Install, prev, 0o755); err != nil {
		return fmt.Errorf("selfupdate: keeping the old program: %w", err)
	}
	_ = os.Remove(filepath.Join(a.UpdateDir, FileHealthy))
	if err := copyFile(filepath.Join(staged, FileProgram), a.Install, 0o755); err != nil {
		return fmt.Errorf("selfupdate: installing: %w", err)
	}
	a.log().Info("installed", "from", current, "to", version)
	if err := a.Restart(); err != nil {
		a.log().Error("the restart failed, putting the old program back", "err", err)
		return a.rollback(prev, fmt.Errorf("selfupdate: restart: %w", err))
	}
	deadline := time.Now().Add(a.Wait)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(filepath.Join(a.UpdateDir, FileHealthy)); err == nil && strings.TrimSpace(string(b)) == version {
			a.log().Info("the new agent is connected", "version", version)
			_ = os.RemoveAll(staged)
			return nil
		}
		time.Sleep(a.Poll)
	}
	a.log().Error("the new agent did not report in, putting the old program back", "version", version)
	return a.rollback(prev, errors.New("selfupdate: the new agent did not connect in time"))
}

func (a *Applier) rollback(prev string, cause error) error {
	if err := copyFile(prev, a.Install, 0o755); err != nil {
		return fmt.Errorf("%w; and the old program could not be put back: %v", cause, err)
	}
	if err := a.Restart(); err != nil {
		return fmt.Errorf("%w; the old program is back but did not restart: %v", cause, err)
	}
	_ = os.RemoveAll(filepath.Join(a.UpdateDir, DirStaged))
	return cause
}
