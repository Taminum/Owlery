//go:build windows

// Command owlery-remote is the screen-sharing helper. It shows the screen of the person at the machine, with mouse and
// keyboard, to Owlery through the agent's tunnel. It is a separate program from secagent because of how Windows works:
// the agent is a system service in session 0 and cannot see any desktop, so it launches this helper into the signed-in
// person's own session (as the system account) when a session is asked for. Running as the system account, and moving
// each capture and each click onto whichever desktop is receiving input, is what lets it reach the secure desktop too —
// UAC prompts and the lock screen — which a tool running with the person's ordinary rights cannot.
//
//	owlery-remote install     writes the shared secret the agent uses to reach it (run as an administrator)
//	owlery-remote uninstall   removes that secret (run as an administrator)
//	owlery-remote run         runs the helper; the agent starts this itself, there is no need to run it by hand
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/Taminum/Owlery/internal/remotehelper"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			if err := install(); err != nil {
				fmt.Fprintln(os.Stderr, "owlery-remote install:", err)
				os.Exit(1)
			}
			fmt.Println("screen sharing is set up on this machine")
			return
		case "uninstall":
			if err := uninstall(); err != nil {
				fmt.Fprintln(os.Stderr, "owlery-remote uninstall:", err)
				os.Exit(1)
			}
			fmt.Println("screen sharing is removed")
			return
		}
	}
	run()
}

func ownDir() (string, error) {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		return "", fmt.Errorf("%%ProgramData%% is not set")
	}
	return filepath.Join(pd, "Owlery"), nil
}

func run() {
	d, err := ownDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "owlery-remote:", err)
		os.Exit(1)
	}
	out := os.Stderr
	if f, err := os.OpenFile(filepath.Join(d, "remote.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		defer f.Close()
		out = f
	}
	log := slog.New(slog.NewTextHandler(out, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := remotehelper.Run(ctx, filepath.Join(d, "remote.secret"), log); err != nil {
		log.Error("stopped", "err", err)
		os.Exit(1)
	}
}

// install makes sure the helper program sits where the agent expects it, writes a fresh secret that only the system
// account and administrators can read — the boundary that stops any other local process from driving the screen through
// the loopback port the secret guards — and does nothing else. The agent launches the helper itself; there is no
// service or logon task. It replaces an earlier install, so the secret rotates each time this is run.
func install() error {
	d, err := ownDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d, 0o755); err != nil {
		return err
	}
	// Put the program at the canonical path the agent launches (copy it only when it is run from somewhere else).
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	want := filepath.Join(d, "owlery-remote.exe")
	if !sameFile(exe, want) {
		if err := copyFile(exe, want); err != nil {
			return fmt.Errorf("placing the helper at %s: %w", want, err)
		}
	}
	secretPath := filepath.Join(d, "remote.secret")
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	if err := os.WriteFile(secretPath, []byte(hex.EncodeToString(b)), 0o600); err != nil {
		return err
	}
	if out, err := exec.Command("icacls", secretPath, "/inheritance:r", "/grant:r", "SYSTEM:F", "*S-1-5-32-544:F").CombinedOutput(); err != nil {
		return fmt.Errorf("icacls: %w: %s", err, out)
	}
	return nil
}

func uninstall() error {
	if d, err := ownDir(); err == nil {
		_ = os.Remove(filepath.Join(d, "remote.secret"))
	}
	return nil
}

func sameFile(a, b string) bool {
	ai, err1 := os.Stat(a)
	bi, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(ai, bi)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
