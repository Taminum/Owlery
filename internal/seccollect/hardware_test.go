package seccollect

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

func TestParseWinHardware(t *testing.T) {
	// PowerShell writes one item as an object and several as an array; both must come out as lists.
	out := `{"vendor":"ASUS","model":"ROG STRIX B650-F","bios":"2611 12.03.2025","build":"Microsoft Windows 11 Pro 26100",
	"cpu":{"name":"AMD Ryzen 7 7800X3D 8-Core Processor ","cores":8,"threads":16,"mhz":4200,"cache_kb":98304},
	"mem":{"slots":4,"used":2,"type":34,"speed":6000},
	"disks":[{"name":"Samsung SSD 990 PRO 2TB","size":2000398934016,"media":"SSD","bus":"NVMe"},{"name":"WDC WD40EZAZ","size":4000787030016,"media":"HDD","bus":"SATA"}],
	"gpus":{"name":"NVIDIA GeForce RTX 4070","mem":4293918720,"driver":"32.0.15.6094"},
	"nics":{"name":"Ethernet","speed":2500000000,"ips":"192.168.1.50"}}`
	h, err := ParseWinHardware(out)
	if err != nil {
		t.Fatal(err)
	}
	if h.Vendor != "ASUS" || h.Virtual || h.CPU.Cores != 8 || h.CPU.Threads != 16 || h.CPU.CacheMB != 96 || h.Memory.Type != "DDR5" || h.Memory.SlotsUsed != 2 {
		t.Errorf("system: %+v", h)
	}
	if len(h.Disks) != 2 || h.Disks[0].Kind != "nvme" || h.Disks[1].Kind != "hdd" {
		t.Errorf("disks: %+v", h.Disks)
	}
	if len(h.GPUs) != 1 || h.GPUs[0].Name != "NVIDIA GeForce RTX 4070" {
		t.Errorf("gpus: %+v", h.GPUs)
	}
	if len(h.NICs) != 1 || h.NICs[0].SpeedMbps != 2500 || len(h.NICs[0].IPs) != 1 || h.NICs[0].IPs[0] != "192.168.1.50" {
		t.Errorf("nics: %+v", h.NICs)
	}
	if _, err := ParseWinHardware("not json"); err == nil {
		t.Error("garbage must be an error, not an empty machine")
	}
	vm, _ := ParseWinHardware(`{"vendor":"Microsoft Corporation","model":"Virtual Machine"}`)
	if !vm.Virtual {
		t.Error("a Hyper-V guest is virtual")
	}
}

func TestParseLinuxHardware(t *testing.T) {
	disks := ParseLsblk(`{"blockdevices":[
		{"name":"nvme0n1","model":"Samsung SSD 980 ","size":500107862016,"rota":false,"tran":"nvme","type":"disk"},
		{"name":"sda","model":"ST4000DM004","size":"4000787030016","rota":true,"tran":"sata","type":"disk"},
		{"name":"vda","model":null,"size":21474836480,"rota":"1","tran":null,"type":"disk"},
		{"name":"zram0","model":null,"size":1,"rota":false,"tran":null,"type":"disk"},
		{"name":"sr0","model":"DVD","size":1,"rota":true,"tran":"sata","type":"rom"}]}`)
	if len(disks) != 3 || disks[0].Kind != "nvme" || disks[0].Model != "Samsung SSD 980" || disks[1].Kind != "hdd" || disks[1].Size != 4000787030016 || disks[2].Model != "vda" {
		t.Errorf("disks: %+v", disks)
	}

	nics := ParseIPAddr(`[
		{"ifname":"lo","operstate":"UNKNOWN","flags":["LOOPBACK","UP"],"addr_info":[{"family":"inet","local":"127.0.0.1","scope":"host"}]},
		{"ifname":"eth0","operstate":"UP","flags":["UP"],"addr_info":[{"family":"inet","local":"203.0.113.5","scope":"global"},{"family":"inet6","local":"fe80::1","scope":"link"}]},
		{"ifname":"docker0","operstate":"UP","flags":["UP"],"addr_info":[{"family":"inet","local":"172.17.0.1","scope":"global"}]},
		{"ifname":"wg0","operstate":"UNKNOWN","flags":["UP"],"addr_info":[{"family":"inet","local":"10.8.0.1","scope":"global"}]},
		{"ifname":"eth1","operstate":"DOWN","flags":[],"addr_info":[]}]`)
	if len(nics) != 2 || nics[0].Name != "eth0" || nics[0].IPs[0] != "203.0.113.5" || nics[1].Name != "wg0" {
		t.Errorf("nics: %+v", nics)
	}

	gpus := ParseLspci(`00:02.0 "VGA compatible controller" "Intel Corporation" "UHD Graphics 630" -r02 "ASUSTeK" "Device 8694"
00:1f.3 "Audio device" "Intel Corporation" "Cannon Lake PCH cAVS" -r10 "ASUSTeK" "Device 8694"
01:00.0 "3D controller" "NVIDIA Corporation" "GA104 [GeForce RTX 3070]" -ra1`)
	if len(gpus) != 2 || gpus[0].Name != "Intel Corporation UHD Graphics 630" || gpus[1].Name != "NVIDIA Corporation GA104 [GeForce RTX 3070]" {
		t.Errorf("gpus: %+v", gpus)
	}

	cpu := ParseCPUInfo("processor\t: 0\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680\nphysical id\t: 0\ncore id\t\t: 0\n\nprocessor\t: 1\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680\nphysical id\t: 0\ncore id\t\t: 0\n\nprocessor\t: 2\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680\nphysical id\t: 0\ncore id\t\t: 1\n\n")
	if cpu.Threads != 3 || cpu.Cores != 2 || cpu.Model != "Intel(R) Xeon(R) CPU E5-2680" {
		t.Errorf("cpu: %+v", cpu)
	}
	if v := ParseCPUInfo("processor\t: 0\nmodel name\t: Virtual CPU\n\nprocessor\t: 1\nmodel name\t: Virtual CPU\n"); v.Cores != 2 {
		t.Errorf("a virtual machine with no core ids has as many cores as threads: %+v", v)
	}
}

func TestHardwareIsReadOnceInAWhileAndAFailedReadKeepsWhatWasKnown(t *testing.T) {
	calls := 0
	fail := false
	h := &HardwareReader{every: time.Hour, read: func(context.Context, Runner) (secproto.Hardware, error) {
		calls++
		if fail {
			return secproto.Hardware{}, errors.New("boom")
		}
		return secproto.Hardware{Vendor: " ASUS "}, nil
	}}
	t0 := time.Date(2026, 11, 4, 8, 0, 0, 0, time.UTC)
	first := h.Collect(context.Background(), t0)
	if first.Status != secproto.StatusOK || first.Data.(secproto.Hardware).Vendor != "ASUS" {
		t.Fatalf("first: %+v", first)
	}
	h.Collect(context.Background(), t0.Add(30*time.Minute))
	if calls != 1 {
		t.Errorf("within the hour nothing is read again: %d reads", calls)
	}
	fail = true
	again := h.Collect(context.Background(), t0.Add(2*time.Hour))
	if calls != 2 || again.Status != secproto.StatusOK || again.Data.(secproto.Hardware).Vendor != "ASUS" {
		t.Errorf("a failed read must not wipe what was known: %d reads, %+v", calls, again)
	}
}
