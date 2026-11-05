//go:build !windows

package secagent

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Taminum/Owlery/internal/selfupdate"
)

// applyStaged hands the checked release on to the root helper: a file appears, a path unit notices it and a root service
// installs the release, after checking it once more against the release key. The agent cannot write where its program is,
// and nothing it writes is trusted.
func (a *agent) applyStaged(string) error {
	if runtime.GOOS != "linux" {
		return errors.New("updates from the server card are for Linux and Windows")
	}
	return os.WriteFile(filepath.Join(a.cfg.UpdateDir, selfupdate.FileReady), nil, 0o600)
}

func (a *agent) updateConnected() {}

// checkUpdateTrial is only for Windows: a Linux update is watched by the root helper that made it.
func (a *agent) checkUpdateTrial() {}
