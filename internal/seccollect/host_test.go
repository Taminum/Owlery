package seccollect

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

func procFiles(t *testing.T, proc string, pid int, name string, ticks, start uint64, rssPages int64, cgroup string) {
	t.Helper()
	d := filepath.Join(proc, strconv.Itoa(pid))
	stat := strconv.Itoa(pid) + " (" + name + ") S 1 1 1 0 -1 4194560 0 0 0 0 " + strconv.FormatUint(ticks, 10) + " 0 0 0 20 0 1 0 " + strconv.FormatUint(start, 10) + " 1000 100\n"
	put(t, d, "stat", stat)
	put(t, d, "statm", "1000 "+strconv.FormatInt(rssPages, 10)+" 0 0 0 0 0\n")
	put(t, d, "cgroup", cgroup)
}

func TestHostReaderGroupsProcessesByProgramAndUnitAndSendsNoCommandLine(t *testing.T) {
	proc := t.TempDir()
	put(t, proc, "stat", "cpu  100 0 100 700 100 0 0 0 0 0\n")
	put(t, proc, "meminfo", "MemTotal: 1000 kB\nMemAvailable: 500 kB\n")
	put(t, proc, "cmdline-must-not-be-read-by-name", "x")
	cg := "0::/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n"
	// Two workers of one program in one container, a service, and a process with brackets in its name.
	procFiles(t, proc, 100, "nginx", 1000, 5, 100, cg)
	procFiles(t, proc, 101, "nginx", 1000, 6, 50, cg)
	procFiles(t, proc, 200, "sshd", 50, 7, 10, "0::/system.slice/ssh.service\n")
	procFiles(t, proc, 300, "a b)c", 10, 8, 5, "0::/user.slice/user-1000.slice/session-3.scope\n")
	put(t, filepath.Join(proc, "100"), "cmdline", "nginx\x00--password=hunter2")
	h := &HostReader{Proc: proc, Etc: t.TempDir()}
	t0 := time.Now()
	first := h.Read(t0)
	for _, p := range first.Procs {
		if p.CPU != 0 {
			t.Fatalf("the first reading has no CPU share: %+v", p)
		}
	}
	// A second later nginx has used 100 more ticks in all (one whole core), sshd none.
	procFiles(t, proc, 100, "nginx", 1060, 5, 100, cg)
	procFiles(t, proc, 101, "nginx", 1040, 6, 50, cg)
	got := h.Read(t0.Add(time.Second))
	var nginx, ssh *struct {
		cpu   float64
		count int
		unit  string
		rss   int64
	}
	for _, p := range got.Procs {
		if p.Name == "nginx" {
			nginx = &struct {
				cpu   float64
				count int
				unit  string
				rss   int64
			}{p.CPU, p.Count, p.Unit, p.RSS}
		}
		if p.Name == "sshd" {
			ssh = &struct {
				cpu   float64
				count int
				unit  string
				rss   int64
			}{p.CPU, p.Count, p.Unit, p.RSS}
		}
	}
	if nginx == nil || nginx.count != 2 || nginx.unit != "docker:0123456789ab" || nginx.cpu < 99 || nginx.cpu > 101 || nginx.rss != 150*int64(os.Getpagesize()) {
		t.Fatalf("%+v", got.Procs)
	}
	if ssh == nil || ssh.unit != "ssh.service" || ssh.cpu != 0 {
		t.Fatalf("%+v", got.Procs)
	}
	if got.Procs[0].Name != "nginx" {
		t.Fatalf("the busiest comes first: %+v", got.Procs)
	}
	for _, p := range got.Procs {
		if strings.Contains(p.Name, "hunter2") || strings.Contains(p.Unit, "hunter2") {
			t.Fatalf("a command line leaked: %+v", p)
		}
	}
}

func TestParseProcStatHandlesNamesWithSpacesAndBrackets(t *testing.T) {
	name, ticks, start, ok := ParseProcStat("4242 (my (odd) name) S 1 1 1 0 -1 0 0 0 0 0 30 12 0 0 20 0 1 0 99 1 1\n")
	if !ok || name != "my (odd) name" || ticks != 42 || start != 99 {
		t.Fatalf("%q %d %d %v", name, ticks, start, ok)
	}
	if _, _, _, ok := ParseProcStat("garbage"); ok {
		t.Fatal("garbage accepted")
	}
}
