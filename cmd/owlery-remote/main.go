//go:build windows

// Command owlery-remote is the remote-control helper: it runs in the signed-in person's own Windows session (the
// security agent is a system service and cannot see a desktop at all), and shows that screen, mouse and keyboard to
// Owlery through the agent's tunnel. It is a separate program from secagent for exactly that reason: a service and a
// session-bound program cannot be the same process on Windows.
//
// Known limit of this first version: it runs with the signed-in person's own standard rights, not elevated, so like
// most such tools it cannot click into a window that was itself opened "as administrator" (Windows keeps those apart
// on purpose). Running the helper elevated too would lift that, at the cost of needing elevation to install it.
//
//	owlery-remote install     registers itself to start at logon and starts it now (run as an administrator)
//	owlery-remote uninstall   removes that and the shared secret (run as an administrator)
//	owlery-remote run         runs the helper itself; this is what the logon task calls (no need to run this by hand)
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/Taminum/Owlery/internal/remotehelper"
)

const taskName = "OwleryRemoteHelper"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			if err := install(); err != nil {
				fmt.Fprintln(os.Stderr, "owlery-remote install:", err)
				os.Exit(1)
			}
			fmt.Println("installed and started", taskName)
			return
		case "uninstall":
			if err := uninstall(); err != nil {
				fmt.Fprintln(os.Stderr, "owlery-remote uninstall:", err)
				os.Exit(1)
			}
			fmt.Println("removed", taskName)
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

// install writes a fresh secret, lets only SYSTEM, administrators and the one user the helper runs as read it (no other
// account on the machine can, and nobody off the machine ever sees it — that boundary is what stops any other local process from driving the screen through the
// loopback port it guards), and registers the scheduled task that starts this program, unelevated, each time
// somebody signs in. It replaces a previous install, so the secret rotates each time this is run.
func install() error {
	d, err := ownDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d, 0o755); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	secretPath := filepath.Join(d, "remote.secret")
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	if err := os.WriteFile(secretPath, []byte(hex.EncodeToString(b)), 0o600); err != nil {
		return err
	}
	if out, err := exec.Command("icacls", secretPath, "/inheritance:r", "/grant:r", "SYSTEM:F", "*S-1-5-32-544:F", os.Getenv("USERNAME")+":R").CombinedOutput(); err != nil {
		return fmt.Errorf("icacls: %w: %s", err, out)
	}
	user := os.Getenv("USERNAME")
	if user == "" {
		return fmt.Errorf("USERNAME is not set")
	}
	_ = exec.Command("schtasks", "/delete", "/tn", taskName, "/f").Run() // fine if there was no earlier install
	create := exec.Command("schtasks", "/create", "/tn", taskName, "/tr", fmt.Sprintf("\"%s\" run", exe),
		"/sc", "onlogon", "/ru", user, "/rl", "limited", "/f")
	if out, err := create.CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks /create: %w: %s", err, out)
	}
	if out, err := exec.Command("schtasks", "/run", "/tn", taskName).CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks /run: %w: %s", err, out)
	}
	return nil
}

func uninstall() error {
	_ = exec.Command("schtasks", "/end", "/tn", taskName).Run()
	if out, err := exec.Command("schtasks", "/delete", "/tn", taskName, "/f").CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks /delete: %w: %s", err, out)
	}
	if d, err := ownDir(); err == nil {
		_ = os.Remove(filepath.Join(d, "remote.secret"))
	}
	return nil
}
