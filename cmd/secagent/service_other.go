//go:build !windows

package main

import (
	"context"
	"log/slog"
)

// On Linux the agent is a systemd unit: there are no service commands and no service mode.
func platformCommand(string, []string) bool { return false }

func runAsService(func(context.Context) error, *slog.Logger) (bool, error) { return false, nil }
