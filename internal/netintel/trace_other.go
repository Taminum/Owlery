//go:build !linux

package netintel

import (
	"context"
	"net/netip"
	"time"
)

const traceSupported = false

// probeTTL has no unprivileged implementation here; the server runs on Linux.
func probeTTL(context.Context, netip.Addr, int, int) (netip.Addr, time.Duration, bool, bool) {
	return netip.Addr{}, 0, false, false
}
