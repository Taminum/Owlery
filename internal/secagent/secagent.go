// Package secagent is the client side of the security channel: it collects the host's security state
// and reports it over an outbound WebSocket. It listens on nothing and executes nothing it is told; the
// only messages it accepts from the server are acknowledgements.
package secagent

import (
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
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/Taminum/RemnaScope/internal/seccollect"
	"github.com/Taminum/RemnaScope/internal/secproto"
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
	// Disabled categories are neither collected nor announced as capabilities.
	NoFail2ban, NoSockets, NoFirewall bool
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

func (c *Config) capabilities() []string {
	var caps []string
	if !c.NoFail2ban {
		caps = append(caps, "fail2ban_read")
	}
	if !c.NoSockets {
		caps = append(caps, "socket_read")
	}
	if !c.NoFirewall {
		caps = append(caps, "firewall_read")
	}
	return caps
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
	a := &agent{cfg: cfg, url: url, hc: hc, epoch: newEpoch()}
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
	cfg   Config
	url   string
	hc    *http.Client
	epoch string
	seq   int64
}

func (a *agent) token() (string, error) {
	b, err := os.ReadFile(a.cfg.TokenFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
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

	host, _ := os.Hostname()
	if err := write(ctx, c, secproto.Hello{Type: "hello", ProtoVersion: secproto.Version, AgentVersion: a.cfg.Version, Epoch: a.epoch,
		Hostname: host, Capabilities: a.cfg.capabilities()}); err != nil {
		return err
	}
	var w secproto.Welcome
	if err := read(ctx, c, &w, "welcome"); err != nil {
		return err
	}
	if a.seq < w.AckSeq {
		a.seq = w.AckSeq
	}
	interval := a.cfg.Interval
	a.cfg.Log.Info("connected", "ack_seq", w.AckSeq, "server_interval_s", w.IntervalSeconds)

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		for _, s := range a.collect(ctx) {
			if err := a.send(ctx, c, s); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			_ = c.Close(websocket.StatusNormalClosure, "bye")
			return nil
		case <-t.C:
		}
	}
}

func (a *agent) collect(ctx context.Context) []seccollect.Snapshot {
	var out []seccollect.Snapshot
	if !a.cfg.NoFail2ban {
		out = append(out, seccollect.Fail2ban(ctx, a.cfg.Runner, a.cfg.Fail2banBin))
	}
	if !a.cfg.NoSockets {
		out = append(out, seccollect.Sockets(ctx, a.cfg.Runner, a.cfg.SSBin))
	}
	if !a.cfg.NoFirewall {
		out = append(out, seccollect.Firewall(ctx, a.cfg.Runner, a.cfg.NftBin, a.cfg.IptablesBin))
	}
	return out
}

func (a *agent) send(ctx context.Context, c *websocket.Conn, s seccollect.Snapshot) error {
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
	var ack secproto.Ack
	if err := read(ctx, c, &ack, "ack"); err != nil {
		return err
	}
	if ack.AckSeq < a.seq {
		return fmt.Errorf("secagent: server acknowledged %d, expected %d", ack.AckSeq, a.seq)
	}
	return nil
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

// read waits for one message of the expected type. Anything else from the server is an error: the
// server has nothing else to say to this agent.
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
