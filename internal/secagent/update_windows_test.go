//go:build windows

package secagent

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestClearOldWhenThePreviousProgramIsStillRunning(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "secagent.exe.old")

	if err := clearOld(old); err != nil { // nothing there
		t.Fatal(err)
	}

	// A program that is running from the old file: Windows lets it be renamed but not deleted, which is what made the next update
	// fail with "Access denied".
	src := filepath.Join(os.Getenv("SystemRoot"), "System32", "ping.exe")
	if err := copyOver(src, old); err != nil {
		t.Skip("cannot copy a test program:", err)
	}
	cmd := exec.Command(old, "-n", "30", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start the test program:", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	if err := os.Remove(old); err == nil {
		t.Skip("this Windows lets a running program be deleted; nothing to prove")
	}
	if err := clearOld(old); err != nil {
		t.Fatalf("a busy old program must be moved aside: %v", err)
	}
	if _, err := os.Stat(old); err == nil {
		t.Fatal("the old name is still taken")
	}
	// The way is clear for the rename of the current program.
	cur := filepath.Join(dir, "secagent.exe")
	if err := os.WriteFile(cur, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(cur, old); err != nil {
		t.Fatal(err)
	}
}
