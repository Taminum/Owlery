//go:build !windows

package secagent

import (
	"encoding/json"
	"errors"
)

// launchConsole is for Windows: a console on somebody's desktop only makes sense where the agent can put a window there.
func launchConsole(json.RawMessage) error {
	return errors.New("окно консоли на экране есть только на Windows")
}
