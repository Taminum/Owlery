package secagent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/seccollect"
)

type tsRunner struct{}

func (tsRunner) Run(_ context.Context, name string, args ...string) seccollect.Result {
	if name != "tailscale" {
		return seccollect.Result{Err: os.ErrNotExist}
	}
	return seccollect.Result{Stdout: `{"Self":{"HostName":"pve","TailscaleIPs":["100.114.204.78"],"Online":true},
		"Peer":{"k1":{"HostName":"Cloud","TailscaleIPs":["100.81.225.100"],"Online":true},"k2":{"HostName":"media","TailscaleIPs":["100.92.74.117"],"Online":false}}}`}
}

func TestPVEReaderReadsNodeGuestsBackupsAndTailnetWithOnlyGets(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "PVEAPIToken=owlery@pve!collector=sekret" {
			t.Errorf("unexpected request %s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		switch strings.TrimPrefix(r.URL.RequestURI(), "/api2/json") {
		case "/version":
			_, _ = w.Write([]byte(`{"data":{"version":"9.2.1"}}`))
		case "/nodes":
			_, _ = w.Write([]byte(`{"data":[{"node":"pve","status":"online"}]}`))
		case "/nodes/pve/status":
			_, _ = w.Write([]byte(`{"data":{"cpu":0.04,"cpuinfo":{"cpus":12},"memory":{"used":5,"total":63},"rootfs":{"used":18,"total":100},"uptime":712}}`))
		case "/cluster/resources":
			_, _ = w.Write([]byte(`{"data":[
				{"type":"node","node":"pve"},
				{"type":"lxc","node":"pve","vmid":205,"name":"cloud","status":"running","maxcpu":4,"cpu":0.02,"mem":3,"maxmem":6,"disk":88,"maxdisk":100,"uptime":99},
				{"type":"lxc","node":"pve","vmid":200,"name":"media","status":"stopped","maxcpu":6},
				{"type":"qemu","node":"pve","vmid":300,"name":"vm1","status":"running"},
				{"type":"storage","node":"pve","storage":"local","plugintype":"dir","disk":10,"maxdisk":50,"content":"iso,backup","status":"available"}]}`))
		case "/nodes/pve/storage/local/content?content=backup":
			// A token that may only read sees no backup files; the logs of the jobs are what tells.
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/nodes/pve/tasks?typefilter=vzdump&limit=20":
			_, _ = w.Write([]byte(`{"data":[{"upid":"UPID:old","endtime":200,"status":"OK"},{"upid":"UPID:new","endtime":400,"status":"job errors"}]}`))
		case "/nodes/pve/tasks/UPID:new/log?limit=2000":
			_, _ = w.Write([]byte(`{"data":[{"n":1,"t":"INFO: Finished Backup of VM 205 (00:00:42)"},{"n":2,"t":"ERROR: Backup of VM 200 failed - boom"}]}`))
		case "/nodes/pve/tasks/UPID:old/log?limit=2000":
			_, _ = w.Write([]byte(`{"data":[{"n":1,"t":"INFO: Finished Backup of VM 200 (00:01:10)"},{"n":2,"t":"INFO: Finished Backup of VM 205 (00:00:40)"}]}`))
		case "/nodes/pve/lxc/205/interfaces":
			_, _ = w.Write([]byte(`{"data":[{"name":"lo","inet":"127.0.0.1/8"},{"name":"eth0","inet":"192.168.1.205/24"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "token.json")
	if err := os.WriteFile(tok, []byte(`{"full-tokenid":"owlery@pve!collector","value":"sekret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rd, err := newPVEReader(srv.URL, tok, tsRunner{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := rd.Read(context.Background(), time.Unix(1000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if p.Node != "pve" || !p.Online || p.Version != "9.2.1" || p.CPUs != 12 || p.Uptime != 712 || p.Tailnet != "100.114.204.78" || p.CPUPct < 3.9 || p.CPUPct > 4.1 {
		t.Fatalf("node: %+v", p)
	}
	if len(p.Guests) != 3 || p.Guests[0].ID != 200 || p.Guests[1].ID != 205 || p.Guests[2].Kind != "qemu" {
		t.Fatalf("guests (sorted by id, both kinds): %+v", p.Guests)
	}
	cloud := p.Guests[1]
	if cloud.LAN != "192.168.1.205" || cloud.Tailnet != "100.81.225.100" || cloud.TSOnline == nil || !*cloud.TSOnline || cloud.Backup != 400 || cloud.DiskUsed != 88 {
		t.Fatalf("cloud: %+v", cloud)
	}
	if m := p.Guests[0]; m.TSOnline == nil || *m.TSOnline || m.Backup != 200 || m.LAN != "" {
		t.Fatalf("a stopped guest has no address from the host but is known to Tailscale: %+v", m)
	}
	if p.Guests[2].TSOnline != nil {
		t.Fatalf("a guest Tailscale does not know has no state: %+v", p.Guests[2])
	}
	if len(p.Storages) != 1 || !p.Storages[0].Backups || p.LastBackupOK == nil || *p.LastBackupOK || p.LastBackupAt != 400 {
		t.Fatalf("storage and backups: %+v ok=%v", p.Storages, p.LastBackupOK)
	}
}

func TestPVETokenFileAcceptsJSONOrPlainAndRefusesOtherText(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	if a, err := loadPVEToken(write("a", "owlery@pve!c=abc\n")); err != nil || a != "PVEAPIToken=owlery@pve!c=abc" {
		t.Fatalf("%q %v", a, err)
	}
	if _, err := loadPVEToken(write("b", "nonsense")); err == nil {
		t.Fatal("garbage must be refused")
	}
}
