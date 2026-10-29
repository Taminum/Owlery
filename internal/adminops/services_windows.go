//go:build windows

package adminops

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type svcInfo struct {
	Name    string `json:"name"`
	Display string `json:"display,omitempty"`
	State   string `json:"state"`
	Start   string `json:"start"`
	PID     uint32 `json:"pid,omitempty"`
}

var stateNames = map[svc.State]string{
	svc.Stopped: "stopped", svc.StartPending: "starting", svc.StopPending: "stopping", svc.Running: "running",
	svc.ContinuePending: "resuming", svc.PausePending: "pausing", svc.Paused: "paused",
}

func startName(t uint32, delayed bool) string {
	switch t {
	case mgr.StartAutomatic:
		if delayed {
			return "auto-delayed"
		}
		return "auto"
	case mgr.StartManual:
		return "manual"
	case mgr.StartDisabled:
		return "disabled"
	case windows.SERVICE_BOOT_START:
		return "boot"
	case windows.SERVICE_SYSTEM_START:
		return "system"
	}
	return "?"
}

// connectRead opens the service manager with only the right to look, so a list needs no more than reading.
func connectRead() (*mgr.Mgr, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, err
	}
	return &mgr.Mgr{Handle: h}, nil
}

// openRead opens one service with only the right to query it.
func openRead(m *mgr.Mgr, name string) (*mgr.Service, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.OpenService(m.Handle, n, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: name, Handle: h}, nil
}

func listServices() (any, error) {
	m, err := connectRead()
	if err != nil {
		return nil, fmt.Errorf("менеджер служб: %w", err)
	}
	defer m.Disconnect()
	names, err := m.ListServices()
	if err != nil {
		return nil, err
	}
	out := make([]svcInfo, 0, len(names))
	for _, n := range names {
		if len(out) >= maxServices {
			break
		}
		s, err := openRead(m, n)
		if err != nil {
			continue
		}
		info := svcInfo{Name: n}
		if st, err := s.Query(); err == nil {
			info.State = stateNames[st.State]
			info.PID = st.ProcessId
		}
		if cfg, err := s.Config(); err == nil {
			info.Display = cfg.DisplayName
			info.Start = startName(cfg.StartType, cfg.DelayedAutoStart)
		}
		s.Close()
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

func guardOwn(name string) error {
	if strings.EqualFold(name, ownService) {
		return errors.New("эту службу остановить нельзя: это сам агент, он оборвёт связь с Owlery")
	}
	return nil
}

func controlService(ctx context.Context, op, name string) error {
	if err := guardOwn(name); op != "svc_start" && err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("менеджер служб: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return errors.New("такой службы нет")
	}
	defer s.Close()
	switch op {
	case "svc_start":
		return startService(s)
	case "svc_stop":
		return stopService(ctx, s)
	}
	if err := stopService(ctx, s); err != nil {
		return err
	}
	return startService(s)
}

func startService(s *mgr.Service) error {
	if st, err := s.Query(); err == nil && st.State == svc.Running {
		return nil
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("не удалось запустить: %w", err)
	}
	return nil
}

// stopService asks the service to stop and waits for it, up to half a minute.
func stopService(ctx context.Context, s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("не удалось остановить: %w", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := s.Query(); err == nil && st.State == svc.Stopped {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	return errors.New("служба не остановилась за 30 секунд")
}

// setServiceStartup changes only how the service starts, leaving everything else about it as it is.
func setServiceStartup(name, start string) error {
	var t uint32
	switch start {
	case "auto":
		t = mgr.StartAutomatic
	case "manual":
		t = mgr.StartManual
	case "disabled":
		t = mgr.StartDisabled
		if err := guardOwn(name); err != nil {
			return err
		}
	default:
		return errors.New("запуск: auto, manual или disabled")
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("менеджер служб: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return errors.New("такой службы нет")
	}
	defer s.Close()
	if err := windows.ChangeServiceConfig(s.Handle, windows.SERVICE_NO_CHANGE, t, windows.SERVICE_NO_CHANGE, nil, nil, nil, nil, nil, nil, nil); err != nil {
		return fmt.Errorf("не удалось изменить: %w", err)
	}
	return nil
}
