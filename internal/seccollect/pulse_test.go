package seccollect

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeProc(t *testing.T, dir, stat, net string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"stat":    stat,
		"meminfo": "MemTotal: 1000 kB\nMemAvailable: 400 kB\n",
		"net/dev": net,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

const netHead = "Inter-|   Receive\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"

func TestPulseReadsTheProcessorAndTheNetworkAgainstTheLastOne(t *testing.T) {
	dir := t.TempDir()
	h := &HostReader{Proc: dir, Etc: dir}
	t0 := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	writeProc(t, dir, "cpu  100 0 100 800 0 0 0 0\n", netHead+"  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n")
	first := h.Pulse(t0)
	if first.CPUPct != -1 || first.RXBps != 0 {
		t.Errorf("the first pulse has nothing to compare: %+v", first)
	}
	if first.MemTotal != 1000*1024 || first.MemUsed != 600*1024 {
		t.Errorf("memory: %+v", first)
	}
	// Five seconds on: 100 of the 200 new jiffies are busy, and the network moved 5000 and 10000 bytes.
	writeProc(t, dir, "cpu  150 0 150 900 0 0 0 0\n", netHead+"  eth0: 6000 10 0 0 0 0 0 0 12000 20 0 0 0 0 0 0\n")
	second := h.Pulse(t0.Add(5 * time.Second))
	if second.CPUPct != 50 {
		t.Errorf("processor: %v", second.CPUPct)
	}
	if second.RXBps != 1000 || second.TXBps != 2000 {
		t.Errorf("network: %d %d", second.RXBps, second.TXBps)
	}
	// A counter that went down (a reboot) is not a speed.
	writeProc(t, dir, "cpu  1 0 1 1 0 0 0 0\n", netHead+"  eth0: 10 1 0 0 0 0 0 0 10 1 0 0 0 0 0 0\n")
	third := h.Pulse(t0.Add(10 * time.Second))
	if third.CPUPct != -1 || third.RXBps != 0 {
		t.Errorf("after a reboot: %+v", third)
	}
}
