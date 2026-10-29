//go:build windows

package adminops

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Startup entries are what Windows starts at sign-in: the Run keys of the machine and of each loaded user, and the
// Startup folders. Scheduled tasks and services that start at boot are not here (services have their own tab).
type startupEntry struct {
	Kind    string `json:"kind"`  // reg | file
	Where   string `json:"where"` // the registry key (with its root) or the folder
	Name    string `json:"name"`
	Command string `json:"command,omitempty"`
	User    string `json:"user,omitempty"`
}

// startupRef names an entry to remove: the same three fields the list gave.
type startupRef struct {
	Kind  string `json:"kind"`
	Where string `json:"where"`
	Name  string `json:"name"`
}

var runKeys = []string{
	`Software\Microsoft\Windows\CurrentVersion\Run`,
	`Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	`Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
}

func listStartup() (any, error) {
	var out []startupEntry
	readKey := func(root registry.Key, rootName, sub, user string) {
		k, err := registry.OpenKey(root, sub, registry.QUERY_VALUE)
		if err != nil {
			return
		}
		defer k.Close()
		names, err := k.ReadValueNames(0)
		if err != nil {
			return
		}
		for _, n := range names {
			if len(out) >= maxStartup {
				return
			}
			v, _, err := k.GetStringValue(n)
			if err != nil {
				continue
			}
			out = append(out, startupEntry{Kind: "reg", Where: rootName + `\` + sub, Name: n, Command: v, User: user})
		}
	}
	for _, sub := range runKeys {
		readKey(registry.LOCAL_MACHINE, "HKLM", sub, "")
	}
	// Each signed-in person's own keys live in their loaded hive under HKEY_USERS.
	if k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS); err == nil {
		sids, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, sid := range sids {
			if !strings.HasPrefix(sid, "S-1-5-21-") || strings.HasSuffix(sid, "_Classes") {
				continue
			}
			readKey(registry.USERS, "HKU", sid+`\`+runKeys[0], sid)
		}
	}
	for _, dir := range startupFolders() {
		des, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, de := range des {
			if de.IsDir() || strings.EqualFold(de.Name(), "desktop.ini") || len(out) >= maxStartup {
				continue
			}
			out = append(out, startupEntry{Kind: "file", Where: dir, Name: de.Name(), Command: filepath.Join(dir, de.Name())})
		}
	}
	return out, nil
}

// startupFolders are the common Startup folder and the one of each person with a profile.
func startupFolders() []string {
	var dirs []string
	if pd := os.Getenv("ProgramData"); pd != "" {
		dirs = append(dirs, filepath.Join(pd, `Microsoft\Windows\Start Menu\Programs\Startup`))
	}
	users := filepath.Join(os.Getenv("SystemDrive")+`\`, "Users")
	if des, err := os.ReadDir(users); err == nil {
		for _, de := range des {
			if de.IsDir() {
				dirs = append(dirs, filepath.Join(users, de.Name(), `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`))
			}
		}
	}
	return dirs
}

func splitRoot(where string) (registry.Key, string, error) {
	root, sub, ok := strings.Cut(where, `\`)
	if !ok {
		return 0, "", errors.New("неверный раздел реестра")
	}
	switch root {
	case "HKLM":
		return registry.LOCAL_MACHINE, sub, nil
	case "HKU":
		return registry.USERS, sub, nil
	}
	return 0, "", errors.New("неверный раздел реестра")
}

// removeStartup deletes one entry that the list could have shown: a value under a Run key, or a file in a Startup
// folder. Anything else is refused, so a crafted request cannot delete an arbitrary value or file.
func removeStartup(r startupRef) error {
	switch r.Kind {
	case "reg":
		root, sub, err := splitRoot(r.Where)
		if err != nil {
			return err
		}
		okKey := false
		for _, rk := range runKeys {
			if strings.EqualFold(sub, rk) || (root == registry.USERS && strings.HasSuffix(strings.ToLower(sub), strings.ToLower(`\`+runKeys[0]))) {
				okKey = true
			}
		}
		if !okKey {
			return errors.New("это не запись автозагрузки")
		}
		k, err := registry.OpenKey(root, sub, registry.SET_VALUE)
		if err != nil {
			return fmt.Errorf("не открыть раздел: %w", err)
		}
		defer k.Close()
		if err := k.DeleteValue(r.Name); err != nil {
			return fmt.Errorf("не удалить: %w", err)
		}
		return nil
	case "file":
		clean := filepath.Clean(r.Where)
		for _, dir := range startupFolders() {
			if strings.EqualFold(clean, dir) && r.Name == filepath.Base(r.Name) {
				if err := os.Remove(filepath.Join(dir, r.Name)); err != nil {
					return fmt.Errorf("не удалить: %w", err)
				}
				return nil
			}
		}
		return errors.New("это не папка автозагрузки")
	}
	return errors.New("неизвестный вид записи")
}

// addStartup puts a program into the machine's Run key, so it starts for everyone who signs in.
func addStartup(name, command string) error {
	name, command = strings.TrimSpace(name), strings.TrimSpace(command)
	if name == "" || command == "" || len(name) > 200 || len(command) > 2000 || strings.ContainsAny(name, `\/`) {
		return errors.New("нужны имя (без слэшей) и команда")
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, runKeys[0], registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("не открыть раздел: %w", err)
	}
	defer k.Close()
	return k.SetStringValue(name, command)
}
