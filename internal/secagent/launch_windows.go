//go:build windows

package secagent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// launchConsole opens PowerShell or cmd on the interactive desktop of a Windows session, as the system account, and leaves it
// there for the administrator to use through the screen view. The program is one of two fixed paths; nothing the page sends
// becomes a command line.
func launchConsole(args json.RawMessage) error {
	var in struct {
		Shell   string `json:"shell"`
		Session uint32 `json:"session"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &in); err != nil {
			return errors.New("не разобрать запрос")
		}
	}
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32")
	var exe string
	var extra []string
	switch in.Shell {
	case "powershell":
		exe = filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")
		extra = []string{"-NoLogo"}
	case "cmd":
		exe = filepath.Join(sys, "cmd.exe")
	default:
		return errors.New("оболочка: powershell или cmd")
	}
	if _, err := os.Stat(exe); err != nil {
		return fmt.Errorf("на машине нет %s", filepath.Base(exe))
	}
	sid, _ := pickSession(in.Session)
	// CREATE_NEW_CONSOLE: the window must be seen.
	if err := startInSessionWith(exe, sid, 0x10, extra...); err != nil {
		return fmt.Errorf("не удалось открыть окно в сеансе %d: %w", sid, err)
	}
	return nil
}
