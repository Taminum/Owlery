// Package adminops carries out the management operations an administrator asks for from the server card: look at
// processes, services, startup entries, sessions, the event log and network connections, and change them. It runs inside
// the agent, which on Windows is the system account, so it is only compiled to do anything there; the agent offers it
// only when the machine was installed with -allow-admin.
package adminops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrUnsupported means this operating system has no management operations.
var ErrUnsupported = errors.New("management is only available on Windows")

// Do runs one operation and returns its result as JSON. A refusal or failure is an error whose text is shown to the
// administrator as it is, so it is written for them.
func Do(ctx context.Context, op string, args json.RawMessage) (json.RawMessage, error) {
	v, err := run(ctx, op, args)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// need decodes the arguments of an operation into dst.
func need(args json.RawMessage, dst any) error {
	if len(args) == 0 {
		return errors.New("нет параметров")
	}
	if err := json.Unmarshal(args, dst); err != nil {
		return fmt.Errorf("параметры не разобрать: %w", err)
	}
	return nil
}

// Caps on what one answer holds, so that it fits the agent's message limit.
const (
	maxProcs    = 2500
	maxServices = 1500
	maxStartup  = 500
	maxEvents   = 300
	maxConns    = 3000
)
