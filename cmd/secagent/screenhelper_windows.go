//go:build windows

package main

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Taminum/Owlery/internal/remotehelper"
	"github.com/Taminum/Owlery/internal/secproto"
)

// The screen-sharing helper is not a program of its own: it is this same secagent binary, run with the "screen-helper"
// argument. The agent (a system service) launches it into the signed-in person's session as the system account when a
// screen session is asked for, the same way the Linux terminal helper is this binary run as "shell-helper". Keeping it
// one binary means one file to ship and download.

const ffmpegURL = "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-win64-gpl.zip"

// screenDir is where the secret and ffmpeg live: %ProgramData%\Owlery.
func screenDir() string {
	return filepath.Join(os.Getenv("ProgramData"), "Owlery")
}

// runScreenHelper runs the helper that shows the screen. The agent starts it; it is not meant to be run by hand.
func runScreenHelper(args []string) {
	fs := flag.NewFlagSet("screen-helper", flag.ExitOnError)
	secret := fs.String("secret-file", filepath.Join(screenDir(), "remote.secret"), "the shared secret the agent authenticates with")
	port := fs.Int("port", secproto.RemoteHelperPort, "the loopback port to serve on (one per Windows session)")
	_ = fs.Parse(args)
	out := io.Writer(os.Stderr)
	if f, err := os.OpenFile(filepath.Join(screenDir(), "remote.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		defer f.Close()
		out = f
	}
	log := slog.New(slog.NewTextHandler(out, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := remotehelper.Run(ctx, *secret, *port, log); err != nil {
		log.Error("screen helper stopped", "err", err)
		os.Exit(1)
	}
}

// setupScreen prepares a machine for screen sharing during installation: a fresh secret that only the system account and
// administrators can read (the boundary that stops any other local process from driving the screen through the loopback
// port it guards), and ffmpeg for the H.264 encoder, downloaded if it is not already there. A missing ffmpeg is not
// fatal — the helper then falls back to still pictures — but the secret is required.
func setupScreen() error {
	d := screenDir()
	if err := os.MkdirAll(d, 0o755); err != nil {
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
	if out, err := exec.Command("icacls", secretPath, "/inheritance:r", "/grant:r", "SYSTEM:F", "*S-1-5-32-544:F").CombinedOutput(); err != nil {
		return fmt.Errorf("icacls: %w: %s", err, out)
	}
	ffmpeg := filepath.Join(d, "ffmpeg.exe")
	if _, err := os.Stat(ffmpeg); err == nil {
		return nil // already there from an earlier install
	}
	if err := downloadFFmpeg(ffmpeg); err != nil {
		fmt.Fprintln(os.Stderr, "secagent install: ffmpeg could not be downloaded, the screen will go as still pictures until it is:", err)
	}
	return nil
}

// downloadFFmpeg fetches a static ffmpeg build and writes just its ffmpeg.exe to dst.
func downloadFFmpeg(dst string) error {
	resp, err := http.Get(ffmpegURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the download answered %s", resp.Status)
	}
	tmp, err := os.CreateTemp("", "ffmpeg-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		return err
	}
	zr, err := zip.OpenReader(tmp.Name())
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), "/bin/ffmpeg.exe") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}
	return fmt.Errorf("no ffmpeg.exe inside the archive")
}
