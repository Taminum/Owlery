package secagent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/seccollect"
	"github.com/Taminum/Owlery/internal/secproto"
)

// pveReader reads a Proxmox host through its own API on this machine, with a token that may only read. Nothing here
// changes anything: every request is a GET.
type pveReader struct {
	base   string
	auth   string
	node   string
	hc     *http.Client
	runner seccollect.Runner
}

// loadPVEToken reads the token from the file `pveum user token add --output-format json` wrote, or from a plain
// "<token id>=<secret>" line.
func loadPVEToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var j struct {
		ID    string `json:"full-tokenid"`
		Value string `json:"value"`
	}
	if json.Unmarshal(b, &j) == nil && j.ID != "" && j.Value != "" {
		return "PVEAPIToken=" + j.ID + "=" + j.Value, nil
	}
	if s := strings.TrimSpace(string(b)); strings.Contains(s, "!") && strings.Contains(s, "=") {
		return "PVEAPIToken=" + s, nil
	}
	return "", fmt.Errorf("secagent: the Proxmox token file holds neither the JSON of pveum nor <token id>=<secret>")
}

// newPVEReader makes a reader for the API at base (default https://127.0.0.1:8006). The API of a Proxmox host answers
// with a certificate of its own, and it is on this very machine, so the certificate is not checked.
func newPVEReader(base, tokenFile string, runner seccollect.Runner) (*pveReader, error) {
	auth, err := loadPVEToken(tokenFile)
	if err != nil {
		return nil, err
	}
	if base == "" {
		base = "https://127.0.0.1:8006"
	}
	return &pveReader{base: strings.TrimRight(base, "/"), auth: auth, runner: runner,
		hc: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}}, nil // #nosec G402 -- loopback
}

func (r *pveReader) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.base+"/api2/json"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", r.auth)
	resp, err := r.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxmox: %s answered %d", path, resp.StatusCode)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return err
	}
	return json.Unmarshal(env.Data, out)
}

func num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case string:
		f, _ := strconv.ParseFloat(x, 64)
		return f
	}
	return 0
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// maxBackupLogs is how many of the newest backup jobs have their logs read.
const maxBackupLogs = 8

var finishedBackup = regexp.MustCompile(`Finished Backup of VM (\d+)`)

type tsPeer struct {
	ip     string
	online bool
}

// tailscalePeers asks the Tailscale on this host who is in the tailnet: the guests are, by their host name.
func (r *pveReader) tailscalePeers(ctx context.Context) (self string, peers map[string]tsPeer) {
	peers = map[string]tsPeer{}
	if r.runner == nil {
		return
	}
	res := r.runner.Run(ctx, "tailscale", "status", "--json")
	if res.Err != nil || len(res.Stdout) == 0 {
		return
	}
	type node struct {
		HostName     string   `json:"HostName"`
		DNSName      string   `json:"DNSName"`
		TailscaleIPs []string `json:"TailscaleIPs"`
		Online       bool     `json:"Online"`
	}
	var st struct {
		Self node            `json:"Self"`
		Peer map[string]node `json:"Peer"`
	}
	if json.Unmarshal([]byte(res.Stdout), &st) != nil {
		return
	}
	if len(st.Self.TailscaleIPs) > 0 {
		self = st.Self.TailscaleIPs[0]
	}
	for _, p := range st.Peer {
		if len(p.TailscaleIPs) == 0 {
			continue
		}
		peers[strings.ToLower(p.HostName)] = tsPeer{ip: p.TailscaleIPs[0], online: p.Online}
	}
	return
}

// Read takes one reading. A part that cannot be read is left empty; the node itself being unreadable is an error.
func (r *pveReader) Read(ctx context.Context, now time.Time) (secproto.Proxmox, error) {
	out := secproto.Proxmox{Type: "proxmox", At: now.UTC(), Guests: []secproto.PVEGuest{}, Storages: []secproto.PVEStorage{}}
	var ver map[string]any
	if err := r.get(ctx, "/version", &ver); err == nil {
		out.Version = str(ver["version"])
	}
	if r.node == "" {
		var nodes []map[string]any
		if err := r.get(ctx, "/nodes", &nodes); err != nil {
			return out, err
		}
		for _, n := range nodes {
			if str(n["status"]) == "online" {
				r.node = str(n["node"])
				break
			}
		}
		if r.node == "" && len(nodes) > 0 {
			r.node = str(nodes[0]["node"])
		}
		if r.node == "" {
			return out, fmt.Errorf("proxmox: no node")
		}
	}
	out.Node = r.node
	node := url.PathEscape(r.node)
	var st map[string]any
	if err := r.get(ctx, "/nodes/"+node+"/status", &st); err != nil {
		return out, err
	}
	out.Online = true
	out.CPUPct = num(st["cpu"]) * 100
	if ci, ok := st["cpuinfo"].(map[string]any); ok {
		out.CPUs = int(num(ci["cpus"]))
	}
	if m, ok := st["memory"].(map[string]any); ok {
		out.MemUsed, out.MemTotal = int64(num(m["used"])), int64(num(m["total"]))
	}
	if m, ok := st["rootfs"].(map[string]any); ok {
		out.DiskUsed, out.DiskTotal = int64(num(m["used"])), int64(num(m["total"]))
	}
	out.Uptime = int64(num(st["uptime"]))

	var res []map[string]any
	if err := r.get(ctx, "/cluster/resources", &res); err != nil {
		return out, nil
	}
	self, peers := r.tailscalePeers(ctx)
	out.Tailnet = self
	var backupStores []string
	for _, e := range res {
		switch str(e["type"]) {
		case "lxc", "qemu":
			if str(e["node"]) != "" && str(e["node"]) != r.node || len(out.Guests) >= secproto.MaxPVEGuests {
				continue
			}
			g := secproto.PVEGuest{ID: int(num(e["vmid"])), Kind: str(e["type"]), Name: str(e["name"]), Status: str(e["status"]), CPUs: int(num(e["maxcpu"])),
				CPUPct: num(e["cpu"]) * 100, MemUsed: int64(num(e["mem"])), MemTotal: int64(num(e["maxmem"])), DiskUsed: int64(num(e["disk"])),
				DiskMax: int64(num(e["maxdisk"])), Uptime: int64(num(e["uptime"])), Template: num(e["template"]) == 1}
			if p, ok := peers[strings.ToLower(g.Name)]; ok {
				up := p.online
				g.Tailnet, g.TSOnline = p.ip, &up
			}
			out.Guests = append(out.Guests, g)
		case "storage":
			if str(e["node"]) != "" && str(e["node"]) != r.node || len(out.Storages) >= secproto.MaxPVEStorages {
				continue
			}
			s := secproto.PVEStorage{Name: str(e["storage"]), Type: str(e["plugintype"]), Used: int64(num(e["disk"])), Total: int64(num(e["maxdisk"])),
				Backups: strings.Contains(str(e["content"]), "backup"), Active: str(e["status"]) == "available"}
			if s.Backups && s.Active {
				backupStores = append(backupStores, s.Name)
			}
			out.Storages = append(out.Storages, s)
		}
	}
	sort.Slice(out.Guests, func(i, j int) bool { return out.Guests[i].ID < out.Guests[j].ID })

	// The newest backup of each guest. The storages are asked first, but a token that may only read does not see the
	// backup files; the logs of the backup jobs say the same, and those it may read.
	newest := map[int]int64{}
	for _, s := range backupStores {
		var vols []map[string]any
		if r.get(ctx, "/nodes/"+node+"/storage/"+url.PathEscape(s)+"/content?content=backup", &vols) != nil {
			continue
		}
		for _, v := range vols {
			if id, at := int(num(v["vmid"])), int64(num(v["ctime"])); id > 0 && at > newest[id] {
				newest[id] = at
			}
		}
	}
	var tasks []map[string]any
	if r.get(ctx, "/nodes/"+node+"/tasks?typefilter=vzdump&limit=20", &tasks) == nil {
		sort.Slice(tasks, func(i, j int) bool { return num(tasks[i]["endtime"]) > num(tasks[j]["endtime"]) })
		for i, t := range tasks {
			end := int64(num(t["endtime"]))
			if i == 0 && end > 0 {
				ok := str(t["status"]) == "OK"
				out.LastBackupOK, out.LastBackupAt = &ok, end
			}
			if i >= maxBackupLogs || end == 0 {
				continue
			}
			var lines []map[string]any
			if r.get(ctx, "/nodes/"+node+"/tasks/"+url.PathEscape(str(t["upid"]))+"/log?limit=2000", &lines) != nil {
				continue
			}
			for _, ln := range lines {
				if m := finishedBackup.FindStringSubmatch(str(ln["t"])); m != nil {
					if id, _ := strconv.Atoi(m[1]); id > 0 && end > newest[id] {
						newest[id] = end
					}
				}
			}
		}
	}
	for i := range out.Guests {
		g := &out.Guests[i]
		g.Backup = newest[g.ID]
		if g.Kind == "lxc" && g.Status == "running" {
			var ifs []map[string]any
			if r.get(ctx, "/nodes/"+node+"/lxc/"+strconv.Itoa(g.ID)+"/interfaces", &ifs) == nil {
				for _, ifc := range ifs {
					if inet := str(ifc["inet"]); inet != "" && str(ifc["name"]) != "lo" {
						g.LAN, _, _ = strings.Cut(inet, "/")
						break
					}
				}
			}
		}
	}
	return out, nil
}
