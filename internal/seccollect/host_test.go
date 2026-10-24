package seccollect

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func put(t *testing.T, dir, name, text string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHostReaderComputesCPUFromTwoReadingsAndMemoryFromAvailable(t *testing.T) {
	proc, etc := t.TempDir(), t.TempDir()
	put(t, proc, "stat", "cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 2 3 4\n")
	put(t, proc, "meminfo", "MemTotal:        2048000 kB\nMemFree:          100000 kB\nMemAvailable:    1024000 kB\nSwapTotal:        512000 kB\nSwapFree:         500000 kB\n")
	put(t, proc, "loadavg", "0.52 0.40 0.30 1/200 12345\n")
	put(t, proc, "uptime", "3600.55 7000.00\n")
	put(t, proc, "net/dev", "Inter-|   Receive\n face |bytes\n    lo: 999 1 0 0 0 0 0 0 999 1 0 0 0 0 0 0\n  eth0: 5000 10 0 0 0 0 0 0 7000 10 0 0 0 0 0 0\nveth1: 400 1 0 0 0 0 0 0 400 1 0 0 0 0 0 0\n")
	put(t, proc, "sys/kernel/osrelease", "6.8.0-147-generic\n")
	put(t, proc, "cpuinfo", "processor\t: 0\nmodel name\t: Test CPU @ 3GHz\nprocessor\t: 1\nmodel name\t: Test CPU @ 3GHz\n")
	put(t, etc, "os-release", "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\n")
	h := &HostReader{Proc: proc, Etc: etc}
	first := h.Read(time.Now())
	if first.CPUPct != -1 {
		t.Fatalf("the first reading has no CPU figure: %v", first.CPUPct)
	}
	// 100 more busy jiffies out of 500 more in all: a fifth.
	put(t, proc, "stat", "cpu  150 0 150 900 300 0 0 0 0 0\n")
	got := h.Read(time.Now())
	if got.CPUPct < 19.9 || got.CPUPct > 20.1 {
		t.Fatalf("cpu %v", got.CPUPct)
	}
	if got.MemTotal != 2048000*1024 || got.MemUsed != 1024000*1024 || got.SwapUsed != 12000*1024 {
		t.Fatalf("%+v", got)
	}
	if got.Load1 != 0.52 || got.UptimeSec != 3600 || got.NetRX != 5000 || got.NetTX != 7000 {
		t.Fatalf("loopback and virtual interfaces are not counted: %+v", got)
	}
	if got.OS != "Ubuntu 24.04.3 LTS" || got.Kernel != "6.8.0-147-generic" || got.CPUs != 2 || got.CPUModel != "Test CPU @ 3GHz" {
		t.Fatalf("%+v", got)
	}
}

func TestParseMountsKeepsRealFileSystemsOnceAndSkipsDockerAndSnaps(t *testing.T) {
	text := "/dev/vda2 / ext4 rw 0 0\nproc /proc proc rw 0 0\ntmpfs /run tmpfs rw 0 0\n/dev/vda2 /var/lib/docker/x ext4 rw 0 0\n/dev/vdb1 /data xfs rw 0 0\n/dev/loop3 /snap/core xfs rw 0 0\noverlay /var/lib/docker/overlay2/a overlay rw 0 0\n"
	m := ParseMounts(text)
	if len(m) != 2 || m[0].Mount != "/" || m[1].Mount != "/data" {
		t.Fatalf("%+v", m)
	}
}

func TestParseCPUStatRejectsGarbage(t *testing.T) {
	if _, _, ok := ParseCPUStat("cpu  a b c d e\n"); ok {
		t.Fatal("garbage accepted")
	}
	if _, _, ok := ParseCPUStat(""); ok {
		t.Fatal("nothing accepted")
	}
}
