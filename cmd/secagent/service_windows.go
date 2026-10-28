//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "OwlerySecAgent"

// platformCommand handles "install" and "uninstall": the agent registers itself as a Windows service that starts with
// the machine and is restarted if it stops. It must run as an administrator.
func platformCommand(cmd string, args []string) bool {
	switch cmd {
	case "install":
		fs := flag.NewFlagSet("install", flag.ExitOnError)
		server := fs.String("server", "", "wss:// URL of Owlery")
		tokenFile := fs.String("token-file", "", "file holding the agent credential")
		probe := fs.Bool("probe", false, "act as a checker for the other servers")
		shell := fs.Bool("allow-shell", false, "let Owlery open a terminal on this machine")
		desktop := fs.Bool("allow-desktop", false, "let Owlery reach this machine's remote desktop through the agent")
		screen := fs.Bool("allow-screen", false, "let Owlery show this machine's screen to an administrator")
		_ = fs.Parse(args)
		if *server == "" || *tokenFile == "" {
			fmt.Fprintln(os.Stderr, "secagent install: -server and -token-file are required")
			os.Exit(2)
		}
		if err := install(*server, *tokenFile, *probe, *shell, *desktop, *screen); err != nil {
			fmt.Fprintln(os.Stderr, "secagent install:", err)
			os.Exit(1)
		}
		fmt.Println("installed and started the service", serviceName)
	case "uninstall":
		if err := uninstall(); err != nil {
			fmt.Fprintln(os.Stderr, "secagent uninstall:", err)
			os.Exit(1)
		}
		fmt.Println("removed the service", serviceName)
	default:
		return false
	}
	return true
}

func install(server, tokenFile string, probe, shell, desktop, screen bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	tokenFile, err = filepath.Abs(tokenFile)
	if err != nil {
		return err
	}
	if _, err := os.Stat(tokenFile); err != nil {
		return fmt.Errorf("the token file: %w", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("the service manager (run as an administrator): %w", err)
	}
	defer m.Disconnect()
	// A second install replaces the first: the address or the token may have changed.
	if s, err := m.OpenService(serviceName); err == nil {
		stopService(s)
		_ = s.Delete()
		s.Close()
		time.Sleep(2 * time.Second)
	}
	args := []string{"-server", server, "-token-file", tokenFile, "-log-file", filepath.Join(filepath.Dir(tokenFile), "secagent.log")}
	if probe {
		args = append(args, "-probe")
	}
	if shell {
		args = append(args, "-allow-shell")
	}
	if desktop {
		args = append(args, "-allow-desktop")
	}
	if screen {
		args = append(args, "-allow-screen")
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: "Owlery security agent",
		Description: "Reports this machine's resources to Owlery. Listens on nothing.",
		StartType:   mgr.StartAutomatic,
	}, args...)
	if err != nil {
		return err
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second}, {Type: mgr.ServiceRestart, Delay: 30 * time.Second}, {Type: mgr.ServiceRestart, Delay: time.Minute}}, 86400)
	return s.Start()
}

func uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("the service manager (run as an administrator): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return errors.New("the service is not installed")
	}
	defer s.Close()
	stopService(s)
	return s.Delete()
}

func stopService(s *mgr.Service) {
	if _, err := s.Control(svc.Stop); err != nil {
		return
	}
	for i := 0; i < 20; i++ {
		if st, err := s.Query(); err != nil || st.State == svc.Stopped {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// runAsService runs the agent under the service manager when Windows started it as a service.
func runAsService(run func(context.Context) error) (bool, error) {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return false, nil
	}
	return true, svc.Run(serviceName, &handler{run: run})
}

type handler struct{ run func(context.Context) error }

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			cancel()
			if err != nil {
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
				}
				return false, 0
			}
		}
	}
}
