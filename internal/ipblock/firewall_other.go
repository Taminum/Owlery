//go:build !windows

package ipblock

import (
	"context"
	"errors"
	"net/netip"
)

type noFirewall struct{}

// NewFirewall: only Windows has one here. On Linux the addresses are shut out by Fail2ban.
func NewFirewall() Firewall { return noFirewall{} }

var errUnsupported = errors.New("ipblock: no firewall on this system")

func (noFirewall) Block(context.Context, netip.Addr) error       { return errUnsupported }
func (noFirewall) Unblock(context.Context, netip.Addr) error     { return errUnsupported }
func (noFirewall) Blocked(context.Context) ([]netip.Addr, error) { return nil, nil }
