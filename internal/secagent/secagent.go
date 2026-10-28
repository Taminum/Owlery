// Package secagent is the client side of the security channel: it collects the host's security state
// and reports it over an outbound WebSocket. It listens on nothing. The server may send it exactly one kind
// of request, "ban or unban one address in one jail", and only when the host has set that up (a helper
// socket and a state directory); everything else it is told is refused.
package secagent

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/Taminum/Owlery/internal/f2bhelper"
	"github.com/Taminum/Owlery/internal/seccollect"
	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/secshell"
)

type Config struct {
	ServerURL     string // wss://host (the path is added)
	TokenFile     string // holds <agent id>.<secret>
	CAFile        string
	AllowInsecure bool // allow ws:// (local testing only)
	Interval      time.Duration
	Version       string
	Log           *slog.Logger
	Runner        seccollect.Runner

	Fail2banBin string
	SSBin       string
	NftBin      string
	IptablesBin string
	// HelperSocket is the Unix socket of the Fail2ban helper. With it the agent reads Fail2ban through the
	// helper instead of running fail2ban-client itself, and, if StateDir is also set, accepts ban and unban.
	HelperSocket string
	// StateDir holds the list of command IDs already carried out, so that a restart cannot run one twice.
	StateDir string
	// Disabled categories are neither collected nor announced as capabilities.
	NoFail2ban, NoSockets, NoFirewall bool
	// NoHost turns off the report of CPU, memory, disks and network that goes with every full tick.
	NoHost bool
	// ContainersFile is the list of running containers written by a small root unit (the agent itself cannot ask
	// Docker). Empty: containers are shown by their short id.
	ContainersFile string
	// Probe makes this host a checker: the server may ask it to connect to a public TCP port or read a TLS
	// certificate, so that a target is seen from somewhere other than the target. Off unless the host chooses it.
	Probe bool
	// FastInterval is how often the set of banned addresses is compared between full reads, so that a ban is
	// named within seconds. Zero means 5 seconds; negative turns it off.
	FastInterval time.Duration
	// AllowShell lets Owlery open a terminal on this machine with the agent's own rights (Windows, where the agent
	// runs as the system). ShellSocket is the root helper that opens terminals on Linux; the agent offers a terminal
	// only when that socket is there, so a machine without the helper cannot be given one.
	AllowShell  bool
	ShellSocket string
	// AllowDesktop lets Owlery reach this machine's own RDP or VNC port through the agent, so that the port need not be
	// open to the network at all.
	AllowDesktop bool
	// AllowWeb lets Owlery reach web services bound to 127.0.0.1 on this machine (admin panels) through the agent.
	AllowWeb bool
	// AllowScreen is the machine's explicit permission for screen sharing; without it the capability is never offered,
	// whatever else is installed.
	AllowScreen bool
	// RemoteSecretFile is the screen-sharing helper's shared secret (Windows). The agent (a system service) launches the
	// helper — this same binary, run as "screen-helper" — into the signed-in person's own session as the system account,
	// so it can see and drive that screen including the secure desktop (UAC and the lock screen); the secret, which only
	// the system and administrators can read, guards the loopback port the agent then relays through. Its presence,
	// together with AllowScreen, is what turns the capability on — the same shape as ShellSocket for the Linux terminal.
	RemoteSecretFile string
}

func (c *Config) defaults() {
	if c.Interval <= 0 {
		c.Interval = 30 * time.Second
	}
	if c.Log == nil {
		c.Log = slog.Default()
	}
	if c.Runner == nil {
		c.Runner = seccollect.ExecRunner{}
	}
	for p, d := range map[*string]string{&c.Fail2banBin: "fail2ban-client", &c.SSBin: "ss", &c.NftBin: "nft", &c.IptablesBin: "iptables-save"} {
		if *p == "" {
			*p = d
		}
	}
}

func (c *Config) endpoint() (string, error) {
	u := strings.TrimRight(c.ServerURL, "/")
	switch {
	case strings.HasPrefix(u, "wss://"):
	case strings.HasPrefix(u, "ws://") && c.AllowInsecure:
	default:
		return "", errors.New("secagent: the server URL must be wss:// (ws:// only with -insecure-ws)")
	}
	return u + secproto.Path, nil
}

func (c *Config) httpClient() (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("secagent: no certificate in the CA file")
		}
		tc.RootCAs = pool
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tc}}, nil
}

func newEpoch() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Run reports until ctx ends. A lost connection is retried with a growing, jittered delay.
func Run(ctx context.Context, cfg Config) error {
	cfg.defaults()
	url, err := cfg.endpoint()
	if err != nil {
		return err
	}
	hc, err := cfg.httpClient()
	if err != nil {
		return err
	}
	a := &agent{cfg: cfg, url: url, hc: hc, epoch: newEpoch(), probes: make(chan struct{}, maxProbes), socks: seccollect.NewSocketWatch(10 * time.Minute), host: newHostReader(cfg), runCtx: ctx}
	back := secshell.Dialer{BaseURL: strings.TrimRight(cfg.ServerURL, "/"), Token: a.token, Client: hc}
	a.shells, a.dialBack = &secshell.Runner{Log: cfg.Log, Dial: back.Dial}, back.DialPath
	if cfg.HelperSocket != "" {
		a.helper = f2bhelper.Client{Path: cfg.HelperSocket}
		// Fail2ban is read through the helper, and the agent never runs fail2ban-client itself.
		a.cfg.Runner = f2bhelper.Runner{Client: a.helper, Bin: cfg.Fail2banBin, Next: cfg.Runner}
		if cfg.StateDir != "" {
			a.done, err = openExecuted(cfg.StateDir)
			if err != nil {
				return fmt.Errorf("secagent: the state directory is not usable, commands stay off: %w", err)
			}
			defer a.done.Close()
		}
	}
	delay := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := a.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		cfg.Log.Warn("connection ended", "err", err)
		if time.Since(start) > time.Minute {
			delay = time.Second
		}
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(delay/2)+1))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay/2 + time.Duration(j.Int64())):
		}
		delay = min(delay*2, time.Minute)
	}
	return nil
}

type agent struct {
	cfg    Config
	url    string
	hc     *http.Client
	epoch  string
	seq    int64
	helper f2bhelper.Client
	done   *executed
	cmdMu  sync.Mutex // one command at a time, in the order they arrive
	probes chan struct{}
	socks  *seccollect.SocketWatch
	host   *seccollect.HostReader
	runCtx context.Context // lives as long as the agent: a terminal outlives a reconnect of the reports
	shells *secshell.Runner
	// dialBack connects back to Owlery for one session (terminal or tunnel).
	dialBack func(ctx context.Context, path, id string) (*websocket.Conn, error)
}

// shellReady says whether this machine allows a terminal right now.
func (a *agent) shellReady() bool {
	if a.cfg.AllowShell {
		return true
	}
	if a.cfg.ShellSocket == "" {
		return false
	}
	st, err := os.Stat(a.cfg.ShellSocket)
	return err == nil && st.Mode()&os.ModeSocket != 0
}

// openShell starts a terminal: through the helper when there is one, else by the agent itself if it may.
func (a *agent) openShell(req secproto.ShellOpen) {
	switch {
	case a.cfg.AllowShell:
		a.shells.Open(a.runCtx, req)
	case a.shellReady():
		ctx, cancel := context.WithTimeout(a.runCtx, 10*time.Second)
		defer cancel()
		if err := secshell.Ask(ctx, a.cfg.ShellSocket, req); err != nil {
			a.cfg.Log.Warn("terminal helper", "err", err)
		}
	default:
		a.cfg.Log.Warn("terminal asked for, but this machine does not allow one", "id", req.ID)
	}
}

func (a *agent) token() (string, error) {
	b, err := os.ReadFile(a.cfg.TokenFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// canBan is true when this host has been set up to carry out ban and unban: a helper that answers and a
// place to remember what has been done. It is decided when the connection starts.
func (a *agent) canBan(ctx context.Context) bool {
	return a.done != nil && !a.cfg.NoFail2ban && a.helper.Available(ctx)
}

func (a *agent) capabilities(ban bool) []string {
	var caps []string
	if !a.cfg.NoFail2ban {
		caps = append(caps, "fail2ban_read")
	}
	if !a.cfg.NoSockets {
		caps = append(caps, "socket_read")
	}
	if !a.cfg.NoFirewall {
		caps = append(caps, "firewall_read")
	}
	if ban {
		caps = append(caps, secproto.CapFail2banBan)
	}
	if a.cfg.Probe {
		caps = append(caps, secproto.CapProbe)
	}
	if a.shellReady() {
		caps = append(caps, secproto.CapShell)
	}
	if a.cfg.AllowDesktop {
		caps = append(caps, secproto.CapDesktop)
	}
	if a.cfg.AllowWeb {
		caps = append(caps, secproto.CapWeb)
	}
	if a.remoteReady() {
		caps = append(caps, secproto.CapRemote)
	}
	return caps
}

// remoteReady says whether screen sharing can be offered: the machine allowed it and the helper and its secret are in
// place. The agent does not keep the helper running — it launches one into the signed-in session when a session is
// asked for (openScreen) — it only checks the files are there.
func (a *agent) remoteReady() bool {
	if !a.cfg.AllowScreen || a.cfg.RemoteSecretFile == "" {
		return false
	}
	_, err := os.Stat(a.cfg.RemoteSecretFile)
	return err == nil
}

func (a *agent) session(ctx context.Context) error {
	tok, err := a.token()
	if err != nil {
		return err
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	c, _, err := websocket.Dial(dctx, a.url, &websocket.DialOptions{HTTPClient: a.hc, HTTPHeader: http.Header{"Authorization": {"Bearer " + tok}},
		CompressionMode: websocket.CompressionDisabled})
	cancel()
	if err != nil {
		return err
	}
	defer c.CloseNow()
	c.SetReadLimit(secproto.MaxMessageBytes)

	ban := a.canBan(ctx)
	host, _ := os.Hostname()
	if err := write(ctx, c, secproto.Hello{Type: "hello", ProtoVersion: secproto.Version, AgentVersion: a.cfg.Version, Epoch: a.epoch,
		Hostname: host, Capabilities: a.capabilities(ban)}); err != nil {
		return err
	}
	var w secproto.Welcome
	if err := read(ctx, c, &w, "welcome"); err != nil {
		return err
	}
	if a.seq < w.AckSeq {
		a.seq = w.AckSeq
	}
	a.cfg.Log.Info("connected", "ack_seq", w.AckSeq, "server_interval_s", w.IntervalSeconds, "can_ban", ban)

	// From here on one goroutine reads every frame: acknowledgements go to the sender, commands to the
	// executor, and anything else ends the session.
	sctx, stop := context.WithCancel(ctx)
	defer stop()
	acks := make(chan secproto.Ack, 16)
	errc := make(chan error, 1)
	go a.reader(sctx, c, ban, acks, errc)

	t := time.NewTicker(a.cfg.Interval)
	defer t.Stop()
	var fastC <-chan time.Time
	if d := a.cfg.FastInterval; d >= 0 && !a.cfg.NoFail2ban {
		if d == 0 {
			d = 5 * time.Second
		}
		ft := time.NewTicker(d)
		defer ft.Stop()
		fastC = ft.C
	}
	var watch banWatch
	full := true
	for {
		if full {
			for _, s := range a.collect(sctx) {
				if err := a.send(sctx, c, s, acks, errc); err != nil {
					return err
				}
			}
			// How loaded the host is: nothing to acknowledge, a lost one is a gap in a chart.
			if !a.cfg.NoHost {
				if err := write(sctx, c, a.host.Read(time.Now())); err != nil {
					return err
				}
			}
		}
		full = false
		select {
		case <-ctx.Done():
			_ = c.Close(websocket.StatusNormalClosure, "bye")
			return nil
		case err := <-errc:
			return err
		case <-t.C:
			full = true
		case <-fastC:
			// Only Fail2ban is read and sent, and only when the banned set moved.
			if watch.changed(sctx, a.cfg.Runner, a.cfg.Fail2banBin) {
				if err := a.send(sctx, c, seccollect.Fail2ban(sctx, a.cfg.Runner, a.cfg.Fail2banBin), acks, errc); err != nil {
					return err
				}
			}
		}
	}
}

func (a *agent) reader(ctx context.Context, c *websocket.Conn, ban bool, acks chan<- secproto.Ack, errc chan<- error) {
	fail := func(err error) {
		select {
		case errc <- err:
		default:
		}
	}
	for {
		_, b, err := c.Read(ctx)
		if err != nil {
			fail(err)
			return
		}
		received := time.Now()
		var head struct {
			Type string `json:"type"`
			Code string `json:"code"`
		}
		if json.Unmarshal(b, &head) != nil {
			fail(errors.New("secagent: an unreadable message from the server"))
			return
		}
		switch head.Type {
		case "ack":
			var ack secproto.Ack
			if json.Unmarshal(b, &ack) != nil {
				fail(errors.New("secagent: a bad acknowledgement"))
				return
			}
			select {
			case acks <- ack:
			default:
			}
		case "command":
			var cmd secproto.Command
			if json.Unmarshal(b, &cmd) != nil {
				fail(errors.New("secagent: a bad command"))
				return
			}
			go func() {
				res := a.carryOut(ctx, cmd, received, ban)
				if err := write(ctx, c, res); err != nil {
					a.cfg.Log.Warn("could not report a command result", "id", cmd.ID, "err", err)
				}
			}()
		case "probe":
			var p secproto.Probe
			if json.Unmarshal(b, &p) != nil {
				fail(errors.New("secagent: a bad probe"))
				return
			}
			if !a.cfg.Probe {
				// Not set up as a checker: answer that, and never dial.
				_ = write(ctx, c, secproto.ProbeResult{Type: "probe_result", ID: p.ID, Kind: p.Kind, Refused: "bad_request"})
				continue
			}
			busy := false
			select {
			case a.probes <- struct{}{}:
			default:
				busy = true
			}
			go func() {
				if !busy {
					defer func() { <-a.probes }()
				}
				if err := write(ctx, c, a.probe(ctx, p, busy)); err != nil {
					a.cfg.Log.Warn("could not report a probe result", "err", err)
				}
			}()
		case "shell_open":
			var req secproto.ShellOpen
			if json.Unmarshal(b, &req) != nil || req.ID == "" || len(req.ID) > 64 {
				fail(errors.New("secagent: a bad terminal request"))
				return
			}
			go a.openShell(req)
		case "tunnel_open":
			var req secproto.TunnelOpen
			if json.Unmarshal(b, &req) != nil || req.ID == "" || len(req.ID) > 64 {
				fail(errors.New("secagent: a bad tunnel request"))
				return
			}
			if !a.cfg.AllowDesktop {
				a.cfg.Log.Warn("desktop asked for, but this machine does not allow it", "id", req.ID)
				continue
			}
			go func() {
				if err := secshell.Tunnel(a.runCtx, a.dialBack, req); err != nil {
					a.cfg.Log.Warn("desktop tunnel", "port", req.Port, "err", err)
				}
			}()
		case "proxy_open":
			var req secproto.ProxyOpen
			if json.Unmarshal(b, &req) != nil || req.ID == "" || len(req.ID) > 64 {
				fail(errors.New("secagent: a bad web service request"))
				return
			}
			if !a.cfg.AllowWeb {
				a.cfg.Log.Warn("web service asked for, but this machine does not allow it", "id", req.ID)
				continue
			}
			go func() {
				if err := secshell.Proxy(a.runCtx, a.dialBack, req); err != nil {
					a.cfg.Log.Warn("web service", "port", req.Port, "err", err)
				}
			}()
		case "remote_open":
			var req secproto.RemoteOpen
			if json.Unmarshal(b, &req) != nil || req.ID == "" || len(req.ID) > 64 {
				fail(errors.New("secagent: a bad remote-control request"))
				return
			}
			if !a.remoteReady() {
				a.cfg.Log.Warn("screen asked for, but this machine does not allow it", "id", req.ID)
				continue
			}
			go a.openScreen(req)
		case "error":
			fail(fmt.Errorf("secagent: the server refused: %s", head.Code))
			return
		default:
			fail(fmt.Errorf("secagent: unexpected message %q", head.Type))
			return
		}
	}
}

func (a *agent) collect(ctx context.Context) []seccollect.Snapshot {
	var out []seccollect.Snapshot
	var banned map[string]bool // what Fail2ban holds now, so its per-address rules are not read as firewall changes
	if !a.cfg.NoFail2ban {
		f := seccollect.Fail2ban(ctx, a.cfg.Runner, a.cfg.Fail2banBin)
		out = append(out, f)
		banned = bannedSet(f)
	}
	if !a.cfg.NoSockets {
		out = append(out, a.socks.Collect(ctx, a.cfg.Runner, a.cfg.SSBin, time.Now()))
	}
	if !a.cfg.NoFirewall {
		out = append(out, seccollect.FirewallWithBans(ctx, a.cfg.Runner, a.cfg.NftBin, a.cfg.IptablesBin, banned))
	}
	return out
}

func (a *agent) send(ctx context.Context, c *websocket.Conn, s seccollect.Snapshot, acks <-chan secproto.Ack, errc <-chan error) error {
	a.seq++
	m := secproto.Snapshot{Type: "snapshot", Seq: a.seq, Category: s.Category, Schema: 1, ObservedAt: time.Now().UTC(), Status: s.Status}
	if s.Data != nil {
		b, err := json.Marshal(s.Data)
		if err != nil {
			return err
		}
		m.Data = b
	}
	if err := write(ctx, c, m); err != nil {
		return err
	}
	timeout := time.NewTimer(20 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case ack := <-acks:
			if ack.AckSeq >= a.seq {
				return nil
			}
		case err := <-errc:
			return err
		case <-timeout.C:
			return errors.New("secagent: the server did not acknowledge a snapshot")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func write(ctx context.Context, c *websocket.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return c.Write(ctx, websocket.MessageText, b)
}

// read waits for one message of the expected type, used only before the reader goroutine starts.
func read(ctx context.Context, c *websocket.Conn, into any, want string) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	_, b, err := c.Read(ctx)
	if err != nil {
		return err
	}
	var head struct {
		Type string `json:"type"`
		Code string `json:"code"`
	}
	if json.Unmarshal(b, &head) != nil || head.Type != want {
		if head.Type == "error" {
			return fmt.Errorf("secagent: the server refused: %s", head.Code)
		}
		return fmt.Errorf("secagent: unexpected message %q, wanted %q", head.Type, want)
	}
	return json.Unmarshal(b, into)
}

// --- commands ------------------------------------------------------------------------------------

var cmdIDRe = regexp.MustCompile(`^[0-9a-fA-F-]{8,64}$`)

// carryOut checks a command again from scratch, makes sure this ID has never been carried out before
// (also across a restart), and asks the helper. The ID is written down before anything runs: a crash in
// the middle then leaves a command that is not repeated, and the server learns the outcome from the next
// state it reads, not from a guess.
func (a *agent) carryOut(ctx context.Context, cmd secproto.Command, received time.Time, enabled bool) secproto.CommandResult {
	res := func(status, code string, verified bool) secproto.CommandResult {
		return secproto.CommandResult{Type: "command_result", ID: cmd.ID, Status: status, Code: code, Verified: verified}
	}
	if !cmdIDRe.MatchString(cmd.ID) {
		return secproto.CommandResult{Type: "command_result", ID: "", Status: secproto.CmdRejected, Code: "bad_id"}
	}
	if !enabled {
		return res(secproto.CmdRejected, "not_enabled", false)
	}
	if cmd.Type != "command" || (cmd.Op != secproto.OpBan && cmd.Op != secproto.OpUnban) || !f2bhelper.ValidJail(cmd.Jail) {
		return res(secproto.CmdRejected, f2bhelper.CodeBadRequest, false)
	}
	if _, code := f2bhelper.ParseIP(cmd.IP); code != "" {
		return res(secproto.CmdRejected, code, false)
	}
	if cmd.TTLSeconds < 1 || cmd.TTLSeconds > secproto.MaxCommandTTL {
		return res(secproto.CmdRejected, "bad_ttl", false)
	}
	a.cmdMu.Lock()
	defer a.cmdMu.Unlock()
	deadline := received.Add(time.Duration(cmd.TTLSeconds) * time.Second)
	if time.Now().After(deadline) {
		return res(secproto.CmdExpired, "", false)
	}
	first, err := a.done.claim(cmd.ID)
	if err != nil {
		return res(secproto.CmdFailed, "state_unwritable", false)
	}
	if !first {
		return res(secproto.CmdDuplicate, "", false)
	}
	rctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	op := f2bhelper.OpBan
	if cmd.Op == secproto.OpUnban {
		op = f2bhelper.OpUnban
	}
	rs, err := a.helper.Do(rctx, f2bhelper.Request{Op: op, Jail: cmd.Jail, IP: cmd.IP})
	if err != nil {
		return res(secproto.CmdFailed, f2bhelper.CodeUnavailable, false)
	}
	switch rs.Code {
	case f2bhelper.CodeExecuted:
		return res(secproto.CmdExecuted, "", rs.Verified)
	case f2bhelper.CodeAlreadyDone:
		return res(secproto.CmdAlreadyDone, "", rs.Verified)
	case f2bhelper.CodeNoSuchJail, f2bhelper.CodeBadRequest, f2bhelper.CodeProtectedIP:
		return res(secproto.CmdRejected, rs.Code, false)
	}
	code := rs.Code
	if code == "" {
		code = f2bhelper.CodeCommandError
	}
	return res(secproto.CmdFailed, code, false)
}

// executed remembers command IDs on disk, one per line, appended and synced before a command runs.
type executed struct {
	mu   sync.Mutex
	ids  map[string]bool
	file *os.File
}

const keepExecuted = 2000

func openExecuted(dir string) (*executed, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "executed-commands")
	e := &executed{ids: map[string]bool{}}
	var order []string
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if id := strings.TrimSpace(sc.Text()); cmdIDRe.MatchString(id) && !e.ids[id] {
				e.ids[id] = true
				order = append(order, id)
			}
		}
		f.Close()
	}
	// Keep the file bounded: rewrite it with the most recent IDs when it has grown.
	if len(order) > keepExecuted {
		order = order[len(order)-keepExecuted:]
		e.ids = map[string]bool{}
		for _, id := range order {
			e.ids[id] = true
		}
		if err := os.WriteFile(path, []byte(strings.Join(order, "\n")+"\n"), 0o600); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	e.file = f
	return e, nil
}

// Close releases the file.
func (e *executed) Close() error { return e.file.Close() }

// claim records the ID and reports whether this is the first time it was seen. If it cannot be written
// down, the command must not run.
func (e *executed) claim(id string) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ids[id] {
		return false, nil
	}
	if _, err := e.file.WriteString(id + "\n"); err != nil {
		return false, err
	}
	if err := e.file.Sync(); err != nil {
		return false, err
	}
	e.ids[id] = true
	return true, nil
}

// bannedSet lists the addresses of a Fail2ban snapshot that was read in full; nothing for one that was not.
func bannedSet(s seccollect.Snapshot) map[string]bool {
	f, ok := s.Data.(secproto.Fail2ban)
	if !ok || s.Status != secproto.StatusOK {
		return nil
	}
	m := map[string]bool{}
	for _, j := range f.Jails {
		for _, ip := range j.BannedIPs {
			m[ip] = true
		}
	}
	return m
}

func newHostReader(cfg Config) *seccollect.HostReader {
	h := seccollect.NewHostReader()
	h.ContainersFile = cfg.ContainersFile
	return h
}
