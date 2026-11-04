package seccollect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

// HardwareReader reads what the machine is made of. That changes only when someone opens the case, so the read is done
// once and then every couple of hours, and the same answer is handed back in between.
type HardwareReader struct {
	run   Runner
	every time.Duration
	read  func(ctx context.Context, r Runner) (secproto.Hardware, error)
	at    time.Time
	last  Snapshot
}

const hardwareEvery = 2 * time.Hour

func NewHardware(r Runner) *HardwareReader {
	return &HardwareReader{run: r, every: hardwareEvery, read: readHardware}
}

func (h *HardwareReader) Collect(ctx context.Context, now time.Time) Snapshot {
	if !h.at.IsZero() && now.Sub(h.at) < h.every && h.last.Status != "" {
		return h.last
	}
	h.at = now
	snap := Snapshot{Category: secproto.CatHardware}
	hw, err := h.read(ctx, h.run)
	switch {
	case errors.Is(err, errHardwareUnsupported):
		snap.Status = secproto.StatusUnsupported
	case err != nil:
		snap.Status = secproto.StatusError
		if h.last.Status == secproto.StatusOK {
			return h.last // a failed read must not wipe what was known
		}
	default:
		snap.Status = secproto.StatusOK
		snap.Data = tidyHardware(hw)
	}
	h.last = snap
	return snap
}

var errHardwareUnsupported = errors.New("seccollect: hardware is not read on this system")

// tidyHardware trims text and caps the lists, so whatever a machine says cannot make the snapshot grow without bound.
func tidyHardware(h secproto.Hardware) secproto.Hardware {
	cut := func(s string, n int) string {
		s = strings.TrimSpace(s)
		if len(s) > n {
			s = s[:n]
		}
		return s
	}
	h.Vendor, h.Model, h.BIOS, h.Hypervisor, h.OSBuild = cut(h.Vendor, 64), cut(h.Model, 96), cut(h.BIOS, 96), cut(h.Hypervisor, 32), cut(h.OSBuild, 96)
	h.CPU.Model = cut(h.CPU.Model, 96)
	h.Memory.Type = cut(h.Memory.Type, 16)
	if len(h.Disks) > secproto.MaxHWItems {
		h.Disks = h.Disks[:secproto.MaxHWItems]
	}
	if len(h.GPUs) > secproto.MaxHWItems {
		h.GPUs = h.GPUs[:secproto.MaxHWItems]
	}
	if len(h.NICs) > secproto.MaxHWItems {
		h.NICs = h.NICs[:secproto.MaxHWItems]
	}
	for i := range h.Disks {
		h.Disks[i].Model = cut(h.Disks[i].Model, 96)
	}
	for i := range h.GPUs {
		h.GPUs[i].Name, h.GPUs[i].Driver = cut(h.GPUs[i].Name, 96), cut(h.GPUs[i].Driver, 32)
	}
	for i := range h.NICs {
		h.NICs[i].Name = cut(h.NICs[i].Name, 64)
		if len(h.NICs[i].IPs) > 8 {
			h.NICs[i].IPs = h.NICs[i].IPs[:8]
		}
	}
	if h.Disks == nil {
		h.Disks = []secproto.HWDisk{}
	}
	if h.GPUs == nil {
		h.GPUs = []secproto.HWGPU{}
	}
	if h.NICs == nil {
		h.NICs = []secproto.HWNic{}
	}
	return h
}

var virtualMarkers = []string{"virtual", "vmware", "kvm", "qemu", "xen", "bochs", "hvm domu", "openstack", "google compute", "amazon ec2", "droplet", "parallels", "bhyve", "hyper-v"}

// virtualFrom guesses from what the firmware calls the machine whether it is a virtual one.
func virtualFrom(vendor, model string) bool {
	s := strings.ToLower(vendor + " " + model)
	for _, m := range virtualMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// many decodes a JSON value that PowerShell wrote as an object when there was one item and as an array when there were more.
type many[T any] []T

func (m *many[T]) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '[' {
		var s []T
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*m = s
		return nil
	}
	var one T
	if err := json.Unmarshal(b, &one); err != nil {
		return err
	}
	*m = []T{one}
	return nil
}

// winAdapterRAMCap is what Win32_VideoController.AdapterRAM shows for every card with 4 GB or more.
const winAdapterRAMCap = 4293918720

// notAVideoCard is true for the virtual displays that remote-desktop programs and Windows itself add: they are not hardware.
func notAVideoCard(name string) bool {
	n := strings.ToLower(name)
	for _, m := range []string{"virtual display", "basic display", "basic render", "remote display", "indirect display", "mirage"} {
		if strings.Contains(n, m) {
			return true
		}
	}
	return false
}

var memTypes = map[int]string{20: "DDR", 21: "DDR2", 24: "DDR3", 26: "DDR4", 34: "DDR5"}

// ParseWinHardware reads what the PowerShell script in hardware_windows.go prints.
func ParseWinHardware(out string) (secproto.Hardware, error) {
	out = strings.TrimPrefix(toUTF8(out), string([]byte{0xEF, 0xBB, 0xBF})) // PowerShell may still answer in the console code page, or start with a byte order mark
	var v struct {
		Vendor string `json:"vendor"`
		Model  string `json:"model"`
		BIOS   string `json:"bios"`
		Build  string `json:"build"`
		CPU    struct {
			Name    string `json:"name"`
			Cores   int    `json:"cores"`
			Threads int    `json:"threads"`
			MHz     int    `json:"mhz"`
			CacheKB int    `json:"cache_kb"`
		} `json:"cpu"`
		Mem struct {
			Slots int `json:"slots"`
			Used  int `json:"used"`
			Type  int `json:"type"`
			Speed int `json:"speed"`
		} `json:"mem"`
		Disks many[struct {
			Name  string `json:"name"`
			Size  int64  `json:"size"`
			Media string `json:"media"`
			Bus   string `json:"bus"`
		}] `json:"disks"`
		GPUs many[struct {
			Name   string `json:"name"`
			Mem    int64  `json:"mem"`
			Driver string `json:"driver"`
		}] `json:"gpus"`
		NICs many[struct {
			Name  string       `json:"name"`
			Speed int64        `json:"speed"`
			IPs   many[string] `json:"ips"`
		}] `json:"nics"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &v); err != nil {
		return secproto.Hardware{}, err
	}
	h := secproto.Hardware{Vendor: v.Vendor, Model: v.Model, BIOS: v.BIOS, OSBuild: v.Build, Virtual: virtualFrom(v.Vendor, v.Model)}
	h.CPU = secproto.HWCPU{Model: v.CPU.Name, Cores: v.CPU.Cores, Threads: v.CPU.Threads, MHz: v.CPU.MHz, CacheMB: v.CPU.CacheKB / 1024}
	h.Memory = secproto.HWMemory{Slots: v.Mem.Slots, SlotsUsed: v.Mem.Used, Type: memTypes[v.Mem.Type], SpeedMT: v.Mem.Speed}
	for _, d := range v.Disks {
		kind := "unknown"
		switch {
		case strings.EqualFold(d.Bus, "NVMe"):
			kind = "nvme"
		case strings.EqualFold(d.Media, "SSD"):
			kind = "ssd"
		case strings.EqualFold(d.Media, "HDD"):
			kind = "hdd"
		}
		h.Disks = append(h.Disks, secproto.HWDisk{Model: d.Name, Size: d.Size, Kind: kind})
	}
	for _, g := range v.GPUs {
		if notAVideoCard(g.Name) {
			continue
		}
		// Windows keeps this number in 32 bits: a card with 4 GB or more reports just under 4 GB, which is not its memory.
		if g.Mem >= winAdapterRAMCap {
			g.Mem = 0
		}
		h.GPUs = append(h.GPUs, secproto.HWGPU{Name: g.Name, Mem: g.Mem, Driver: g.Driver})
	}
	for _, n := range v.NICs {
		h.NICs = append(h.NICs, secproto.HWNic{Name: n.Name, SpeedMbps: int(n.Speed / 1_000_000), IPs: n.IPs})
	}
	return h, nil
}

// ParseLsblk reads `lsblk -J -b -d -o NAME,MODEL,SIZE,ROTA,TRAN,TYPE`: the whole disks, not their partitions.
func ParseLsblk(out string) []secproto.HWDisk {
	var v struct {
		Devices []struct {
			Name  string          `json:"name"`
			Model *string         `json:"model"`
			Size  json.Number     `json:"size"`
			Rota  json.RawMessage `json:"rota"`
			Tran  *string         `json:"tran"`
			Type  string          `json:"type"`
		} `json:"blockdevices"`
	}
	if json.Unmarshal([]byte(out), &v) != nil {
		return nil
	}
	var disks []secproto.HWDisk
	for _, d := range v.Devices {
		if d.Type != "disk" || strings.HasPrefix(d.Name, "zram") || strings.HasPrefix(d.Name, "loop") || strings.HasPrefix(d.Name, "ram") {
			continue
		}
		size, _ := d.Size.Int64()
		rota := strings.Trim(string(d.Rota), `"`) // 1, true or "1" depending on the version of lsblk
		kind := "unknown"
		switch {
		case strings.HasPrefix(d.Name, "nvme") || (d.Tran != nil && *d.Tran == "nvme"):
			kind = "nvme"
		case rota == "0" || rota == "false":
			kind = "ssd"
		case rota == "1" || rota == "true":
			kind = "hdd"
		}
		model := d.Name
		if d.Model != nil && strings.TrimSpace(*d.Model) != "" {
			model = strings.TrimSpace(*d.Model)
		}
		disks = append(disks, secproto.HWDisk{Model: model, Size: size, Kind: kind})
	}
	return disks
}

// ParseIPAddr reads `ip -j addr`: the interfaces that are up and carry an address, without loopback and without the
// virtual ones containers make.
func ParseIPAddr(out string) []secproto.HWNic {
	var v []struct {
		Name  string   `json:"ifname"`
		State string   `json:"operstate"`
		Flags []string `json:"flags"`
		Addrs []struct {
			Family string `json:"family"`
			Local  string `json:"local"`
			Scope  string `json:"scope"`
		} `json:"addr_info"`
	}
	if json.Unmarshal([]byte(out), &v) != nil {
		return nil
	}
	var nics []secproto.HWNic
	for _, i := range v {
		if i.Name == "lo" || strings.HasPrefix(i.Name, "veth") || strings.HasPrefix(i.Name, "docker") || strings.HasPrefix(i.Name, "br-") || strings.HasPrefix(i.Name, "virbr") {
			continue
		}
		up := i.State == "UP"
		for _, f := range i.Flags {
			if f == "LOOPBACK" {
				up = false
			}
		}
		if !up && i.State != "UNKNOWN" { // a tunnel reports UNKNOWN while it works
			continue
		}
		n := secproto.HWNic{Name: i.Name}
		for _, a := range i.Addrs {
			if a.Scope == "global" && (a.Family == "inet" || a.Family == "inet6") {
				n.IPs = append(n.IPs, a.Local)
			}
		}
		if len(n.IPs) > 0 {
			nics = append(nics, n)
		}
	}
	sort.Slice(nics, func(a, b int) bool { return nics[a].Name < nics[b].Name })
	return nics
}

// ParseLspci reads `lspci -mm`: the video controllers.
func ParseLspci(out string) []secproto.HWGPU {
	var gpus []secproto.HWGPU
	for _, line := range strings.Split(out, "\n") {
		f := splitQuoted(line)
		if len(f) < 4 {
			continue
		}
		class := strings.ToLower(f[1])
		if !strings.Contains(class, "vga") && !strings.Contains(class, "3d controller") && !strings.Contains(class, "display controller") {
			continue
		}
		gpus = append(gpus, secproto.HWGPU{Name: strings.TrimSpace(f[2] + " " + f[3])})
	}
	return gpus
}

// splitQuoted splits an lspci -mm line: words separated by spaces, with "quoted words" kept whole.
func splitQuoted(s string) []string {
	var out []string
	var cur strings.Builder
	in := false
	for _, r := range s {
		switch {
		case r == '"':
			in = !in
		case r == ' ' && !in:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// ParseCPUInfo reads /proc/cpuinfo: the model, the cores and the threads.
func ParseCPUInfo(s string) secproto.HWCPU {
	var c secproto.HWCPU
	cores := map[string]bool{}
	phys, core := "", ""
	flush := func() {
		if core != "" {
			cores[phys+"/"+core] = true
		}
		phys, core = "", ""
	}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			if strings.TrimSpace(line) == "" {
				flush()
			}
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "model name":
			if c.Model == "" {
				c.Model = v
			}
			c.Threads++
		case "physical id":
			phys = v
		case "core id":
			core = v
		}
	}
	flush()
	c.Cores = len(cores)
	if c.Cores == 0 {
		c.Cores = c.Threads
	}
	return c
}
