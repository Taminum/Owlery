//go:build !linux && !windows

package seccollect

import (
	"errors"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

func (h *HostReader) readOS(now time.Time) secproto.Host { return h.readProcfs(now) }

func diskUsage(string) (int64, int64, error) { return 0, 0, errors.New("not supported on this system") }
