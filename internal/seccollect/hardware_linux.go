//go:build linux

package seccollect

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Taminum/Owlery/internal/secproto"
)

func dmi(name string) string {
	b, err := os.ReadFile("/sys/class/dmi/id/" + name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readHardware(ctx context.Context, r Runner) (secproto.Hardware, error) {
	h := secproto.Hardware{Vendor: dmi("sys_vendor"), Model: dmi("product_name")}
	if v, d := dmi("bios_version"), dmi("bios_date"); v != "" {
		h.BIOS = strings.TrimSpace(v + " " + d)
	}
	h.Virtual = virtualFrom(h.Vendor, h.Model)
	if res := r.Run(ctx, "systemd-detect-virt"); res.Err == nil && res.ExitCode == 0 {
		if v := strings.TrimSpace(res.Stdout); v != "" && v != "none" {
			h.Virtual, h.Hypervisor = true, v
		}
	}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				h.OSBuild = strings.Trim(v, `"`)
			}
		}
	}
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		h.CPU = ParseCPUInfo(string(b))
	}
	if b, err := os.ReadFile("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"); err == nil {
		if khz, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			h.CPU.MaxMHz = khz / 1000
		}
	}
	if res := r.Run(ctx, "lsblk", "-J", "-b", "-d", "-o", "NAME,MODEL,SIZE,ROTA,TRAN,TYPE"); res.Err == nil && res.ExitCode == 0 {
		h.Disks = ParseLsblk(res.Stdout)
	}
	if res := r.Run(ctx, "lspci", "-mm"); res.Err == nil && res.ExitCode == 0 {
		h.GPUs = ParseLspci(res.Stdout)
	}
	if res := r.Run(ctx, "ip", "-j", "addr"); res.Err == nil && res.ExitCode == 0 {
		h.NICs = ParseIPAddr(res.Stdout)
		for i, n := range h.NICs {
			if b, err := os.ReadFile(filepath.Join("/sys/class/net", n.Name, "speed")); err == nil {
				if mbps, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && mbps > 0 {
					h.NICs[i].SpeedMbps = mbps
				}
			}
		}
	}
	if len(h.NICs) > 0 {
		var gw map[string]string
		main := ""
		if res := r.Run(ctx, "ip", "-j", "route", "show", "default"); res.Err == nil && res.ExitCode == 0 {
			gw, main = ParseDefaultRoutes(res.Stdout)
		}
		var dns []string
		for _, f := range []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"} {
			if b, err := os.ReadFile(f); err == nil {
				if dns = ParseResolv(string(b)); len(dns) > 0 {
					break
				}
			}
		}
		for i, n := range h.NICs {
			h.NICs[i].Gateway = gw[n.Name]
			if n.Name == main {
				h.NICs[i].DNS = dns // the name servers are the machine's, shown with the interface it goes out through
			}
		}
	}
	return h, nil
}
