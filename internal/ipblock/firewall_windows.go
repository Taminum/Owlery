//go:build windows

package ipblock

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// rulePrefix names every rule the engine makes, and is how it finds them again. Nothing else is ever listed or removed.
const rulePrefix = "Owlery block "

type winFirewall struct{}

// NewFirewall is the Windows Firewall. One inbound rule per address, closed on every port: the people guessing passwords
// do not care which port remote desktop was moved to.
func NewFirewall() Firewall { return winFirewall{} }

func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func (winFirewall) Block(ctx context.Context, ip netip.Addr) error {
	if !ip.IsValid() {
		return errors.New("ipblock: not an address")
	}
	name := rulePrefix + ip.String()
	// Make it again from scratch: a rule left over from before must not stay next to a new one.
	_, _ = run(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
	_, err := run(ctx, "netsh", "advfirewall", "firewall", "add", "rule", "name="+name, "dir=in", "action=block", "remoteip="+ip.String(), "profile=any", "enable=yes")
	return err
}

func (winFirewall) Unblock(ctx context.Context, ip netip.Addr) error {
	if !ip.IsValid() {
		return errors.New("ipblock: not an address")
	}
	_, err := run(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+rulePrefix+ip.String())
	return err
}

func (winFirewall) Blocked(ctx context.Context) ([]netip.Addr, error) {
	// The names are ours and plain ASCII, so the console code page does not matter here.
	out, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"Get-NetFirewallRule -DisplayName '"+rulePrefix+"*' -ErrorAction SilentlyContinue | ForEach-Object { $_.DisplayName }")
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, rulePrefix) {
			continue
		}
		if ip, err := netip.ParseAddr(strings.TrimPrefix(line, rulePrefix)); err == nil {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}
