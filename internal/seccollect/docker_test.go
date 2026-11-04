package seccollect

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

const dockerList = `{"id":"aaaaaaaaaaaa1111","name":"/rw-node","image":"remnawave/node:2.1","state":"running","exit":0,"started":"2026-10-23T10:00:00.5Z","finished":"0001-01-01T00:00:00Z","restarts":0,"health":"","policy":"unless-stopped","ports":{"2222/tcp":[{"HostIp":"0.0.0.0","HostPort":"2222"},{"HostIp":"::","HostPort":"2222"}]}}
{"id":"bbbbbbbbbbbb2222","name":"/nginx","image":"nginx:1.27","state":"restarting","exit":1,"started":"2026-11-04T10:00:00Z","finished":"2026-11-04T10:00:03Z","restarts":14,"health":"","policy":"always","ports":{"7443/tcp":[{"HostPort":"7443"}],"80/tcp":null}}
{"id":"cccccccccccc3333","name":"/awg","image":"amneziavpn/awg:2","state":"running","exit":0,"started":"2026-11-01T10:00:00Z","finished":"","restarts":0,"health":"healthy","policy":"always","ports":{"55424/udp":[{"HostPort":"55424"}]}}
{"id":"dddddddddddd4444","name":"/bad name","image":"x","state":"running","ports":null}
not json
{"id":"short","name":"/x","state":"running"}
{"id":"eeeeeeeeeeee5555","name":"/old","image":"alpine:3.20","state":"strange","exit":0,"started":"0001-01-01T00:00:00Z","finished":"2026-09-25T10:00:00Z","restarts":0,"policy":"no","ports":{}}
`

const dockerStats = `{"ID":"aaaaaaaaaaaa","Name":"rw-node","CPUPerc":"3.05%","MemUsage":"210.5MiB / 15.5GiB"}
{"ID":"bbbbbbbbbbbb","Name":"nginx","CPUPerc":"0.00%","MemUsage":"4MiB / 15.5GiB"}
{"ID":"cccccccccccc","Name":"awg","CPUPerc":"--","MemUsage":"38.2MB / 15.5GiB"}
`

func writeDocker(t *testing.T, list, stats string) *DockerReader {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "docker.jsonl")
	if err := os.WriteFile(file, []byte(list), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-stats.jsonl"), []byte(stats), 0o600); err != nil {
		t.Fatal(err)
	}
	return NewDocker(file)
}

func TestDockerReadsTheListAndTheStatistics(t *testing.T) {
	d := writeDocker(t, dockerList, dockerStats)
	snap := d.Collect(time.Now())
	if snap.Status != secproto.StatusOK {
		t.Fatalf("%s", snap.Status)
	}
	got := snap.Data.(secproto.Docker).Containers
	if len(got) != 4 { // the bad name, the broken line and the short id are dropped
		t.Fatalf("%d: %+v", len(got), got)
	}
	by := map[string]secproto.DockerContainer{}
	for _, c := range got {
		by[c.Name] = c
	}
	n := by["rw-node"]
	if n.ID != "aaaaaaaaaaaa" || n.State != "running" || n.Started == nil || n.Finished != nil || len(n.Ports) != 1 || n.Ports[0] != "2222" || n.Policy != "unless-stopped" {
		t.Errorf("%+v", n)
	}
	if n.CPU == nil || *n.CPU != 3.05 || n.Mem != int64(210.5*(1<<20)) {
		t.Errorf("stats: %v %d", n.CPU, n.Mem)
	}
	if x := by["nginx"]; x.State != "restarting" || x.Restarts != 14 || x.Exit != 1 || len(x.Ports) != 1 {
		t.Errorf("%+v", x)
	}
	if x := by["awg"]; x.CPU != nil || x.Mem != 38_200_000 || x.Ports[0] != "UDP 55424" || x.Health != "healthy" {
		t.Errorf("%+v", x)
	}
	if x := by["old"]; x.State != "unknown" || x.Started != nil || x.Finished == nil || x.Ports == nil {
		t.Errorf("%+v", x)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Name > got[i].Name {
			t.Fatal("the list is sorted by name")
		}
	}
}

func TestDockerWithoutTheUnitOrWithAnOldList(t *testing.T) {
	if s := NewDocker(filepath.Join(t.TempDir(), "docker.jsonl")).Collect(time.Now()); s.Status != secproto.StatusNotInstalled || s.Data != nil {
		t.Fatalf("%+v", s)
	}
	d := writeDocker(t, dockerList, "")
	if s := d.Collect(time.Now().Add(time.Hour)); s.Status != secproto.StatusStopped {
		t.Fatalf("a list nobody refreshes: %+v", s)
	}
	if s := writeDocker(t, "", "").Collect(time.Now()); s.Status != secproto.StatusOK || len(s.Data.(secproto.Docker).Containers) != 0 {
		t.Fatalf("a machine with Docker and no containers is ok and empty: %+v", s)
	}
}

func TestDockerCountsRestartsOfTheLastHour(t *testing.T) {
	d := NewDocker("")
	at := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	if n := d.restartsInHour("a", 5, at); n != 0 {
		t.Fatalf("the first look sees nothing new: %d", n)
	}
	if n := d.restartsInHour("a", 6, at.Add(10*time.Minute)); n != 1 {
		t.Fatalf("%d", n)
	}
	if n := d.restartsInHour("a", 9, at.Add(30*time.Minute)); n != 4 {
		t.Fatalf("%d", n)
	}
	// An hour on, the first restarts are too old to count.
	if n := d.restartsInHour("a", 9, at.Add(95*time.Minute)); n != 0 {
		t.Fatalf("%d", n)
	}
	// A total that dropped means the container was made anew.
	if n := d.restartsInHour("a", 0, at.Add(100*time.Minute)); n != 0 {
		t.Fatalf("%d", n)
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"1KiB": 1024, "2MiB": 2 << 20, "1.5GB": 1_500_000_000, "0B": 0, "--": 0, "": 0, "12 MiB ": 12 << 20, "5furlongs": 0} {
		if got := parseSize(in); got != want {
			t.Errorf("%q: %d, want %d", in, got, want)
		}
	}
}
