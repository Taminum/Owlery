//go:build windows

package secagent

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Taminum/Owlery/internal/selfupdate"
)

// On Windows the agent is the system account, so it installs the release itself: the running program can be renamed, the new one
// is put in its place, and the service manager restarts the service when it ends with an error. The old program is kept. A new
// program that starts but never gets connected is taken off again after a few starts.

type trial struct {
	Prev  string `json:"prev"`
	Tries int    `json:"tries"`
}

func (a *agent) trialFile() string { return filepath.Join(a.cfg.UpdateDir, "trial.json") }

func copyOver(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func (a *agent) applyStaged(version string) error {
	staged := filepath.Join(a.cfg.UpdateDir, selfupdate.DirStaged)
	if _, err := selfupdate.VerifyStaged(staged, "", a.cfg.Version, runtime.GOOS, runtime.GOARCH, nil); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := copyOver(filepath.Join(staged, selfupdate.FileProgram), exe); err != nil {
		_ = os.Remove(exe)
		_ = os.Rename(old, exe)
		return err
	}
	b, _ := json.Marshal(trial{Prev: a.cfg.Version})
	if err := os.WriteFile(a.trialFile(), b, 0o600); err != nil {
		_ = os.Remove(exe)
		_ = os.Rename(old, exe)
		return err
	}
	// The service ends with an error a moment from now, after this answer has gone out, and the service manager starts the new program.
	go func() {
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}()
	return nil
}

// updateConnected ends the trial of a new program: it is connected, so it stays.
func (a *agent) updateConnected() { _ = os.Remove(a.trialFile()) }

// checkUpdateTrial counts the starts of a program that is on trial, and puts the old one back when the new one has started
// three times without getting connected.
func (a *agent) checkUpdateTrial() {
	if a.cfg.UpdateDir == "" {
		return
	}
	b, err := os.ReadFile(a.trialFile())
	if err != nil {
		return
	}
	var t trial
	if json.Unmarshal(b, &t) != nil {
		_ = os.Remove(a.trialFile())
		return
	}
	t.Tries++
	if t.Tries <= 3 {
		nb, _ := json.Marshal(t)
		_ = os.WriteFile(a.trialFile(), nb, 0o600)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	old := exe + ".old"
	if _, err := os.Stat(old); err != nil {
		_ = os.Remove(a.trialFile())
		return
	}
	a.cfg.Log.Error("the new program did not get connected, putting the old one back", "old", t.Prev)
	bad := exe + ".bad"
	_ = os.Remove(bad)
	if err := os.Rename(exe, bad); err != nil {
		return
	}
	if err := os.Rename(old, exe); err != nil {
		_ = os.Rename(bad, exe)
		return
	}
	_ = os.Remove(a.trialFile())
	go func() {
		time.Sleep(time.Second)
		os.Exit(1)
	}()
}
