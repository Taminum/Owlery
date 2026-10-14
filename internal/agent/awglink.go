package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/Taminum/RemnaScope/internal/ingestproto"
)

var (
	opContainerRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
	opNameRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,39}$`)
	opKeyRe       = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
)

// AWGLink is the whole connection of an AmneziaWG agent. It has no spool and no ordered stream: it
// sends the latest snapshot, answers pings, and, only if ManageArgv is set, carries out the two
// commands the server may send (add a device, revoke a device) through one fixed helper.
type AWGLink struct {
	URL, TokenFile, CAFile string
	AllowInsecure          bool
	Version, SourceID      string
	Snapshots              <-chan ingestproto.AWG
	Flows                  <-chan ingestproto.AWGFlows // reports of the traffic sensor (nil = no sensor)
	// ManageArgv is the helper command (run without a shell). Empty means management is off and every
	// command is refused.
	ManageArgv []string
	PingEvery  time.Duration
	AckTimeout time.Duration
	Log        *slog.Logger
	// RunCmd replaces the process execution in tests.
	RunCmd func(ctx context.Context, argv []string) ([]byte, error)

	opMu sync.Mutex
}

func (l *AWGLink) log() *slog.Logger {
	if l.Log != nil {
		return l.Log
	}
	return slog.Default()
}

// Run keeps the connection up until ctx ends.
func (l *AWGLink) Run(ctx context.Context) error {
	if !strings.HasPrefix(l.URL, "wss://") && !(l.AllowInsecure && strings.HasPrefix(l.URL, "ws://")) {
		return errors.New("agent: the server URL must be wss://")
	}
	backoff := time.Second
	for {
		err := l.session(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		wait := backoff
		if errors.Is(err, ErrRevoked) {
			wait = 5 * time.Minute
		}
		l.log().Warn("connection ended", "err", err, "retry_in", wait.Round(time.Second).String())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		if backoff *= 2; backoff > time.Minute {
			backoff = time.Minute
		}
	}
}

func (l *AWGLink) session(ctx context.Context) error {
	sh := &Shipper{URL: l.URL, TokenFile: l.TokenFile, CAFile: l.CAFile, AllowInsecure: l.AllowInsecure}
	tok, err := sh.token()
	if err != nil {
		return err
	}
	hc, err := sh.httpClient()
	if err != nil {
		return err
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	c, resp, err := websocket.Dial(dctx, l.URL, &websocket.DialOptions{
		HTTPClient: hc, HTTPHeader: map[string][]string{"Authorization": {"Bearer " + tok}}, CompressionMode: websocket.CompressionDisabled,
	})
	cancel()
	if err != nil {
		if resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 403) {
			return ErrRevoked
		}
		return err
	}
	defer c.CloseNow()
	c.SetReadLimit(ingestproto.MaxMessageBytes)

	epoch := make([]byte, 8)
	_, _ = rand.Read(epoch)
	if err := writeMsg(ctx, c, ingestproto.Hello{Type: "hello", ProtoVersion: ingestproto.Version, AgentVersion: l.Version, Epoch: hex.EncodeToString(epoch), SourceID: l.SourceID}); err != nil {
		return err
	}
	var w ingestproto.Welcome
	if err := readMsg(ctx, c, 15*time.Second, &w); err != nil {
		return sh.closeErr(err)
	}
	if w.Type != "welcome" {
		return fmt.Errorf("agent: unexpected %q instead of welcome", w.Type)
	}
	l.log().Info("connected", "management", len(l.ManageArgv) > 0)

	ctx, cancel = context.WithCancel(ctx)
	defer cancel()
	frames := make(chan json.RawMessage, 8)
	readErr := make(chan error, 1)
	go func() {
		for {
			_, b, err := c.Read(ctx)
			if err != nil {
				readErr <- err
				return
			}
			select {
			case frames <- b:
			case <-ctx.Done():
				return
			}
		}
	}()

	pingEvery, ackTimeout := l.PingEvery, l.AckTimeout
	if pingEvery <= 0 {
		pingEvery = 25 * time.Second
	}
	if ackTimeout <= 0 {
		ackTimeout = 30 * time.Second
	}
	ping := time.NewTicker(pingEvery)
	defer ping.Stop()
	var pongDue time.Time
	for {
		var overdue <-chan time.Time
		if !pongDue.IsZero() {
			overdue = time.After(time.Until(pongDue))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErr:
			return sh.closeErr(err)
		case <-overdue:
			return errors.New("agent: the server did not answer a ping")
		case snap := <-l.Snapshots:
			// only the newest matters
			for drained := false; !drained; {
				select {
				case n := <-l.Snapshots:
					snap = n
				default:
					drained = true
				}
			}
			if err := writeMsg(ctx, c, snap); err != nil {
				return err
			}
		case fl := <-l.Flows:
			if err := writeMsg(ctx, c, fl); err != nil {
				return err
			}
		case <-ping.C:
			if err := writeMsg(ctx, c, ingestproto.Ping{Type: "ping"}); err != nil {
				return err
			}
			if pongDue.IsZero() {
				pongDue = time.Now().Add(ackTimeout)
			}
		case raw := <-frames:
			var head struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(raw, &head) != nil {
				continue
			}
			switch head.Type {
			case "pong":
				pongDue = time.Time{}
			case "awg_op":
				var op ingestproto.AWGOp
				if json.Unmarshal(raw, &op) == nil {
					go l.handleOp(ctx, c, op)
				}
			}
		}
	}
}

// handleOp runs one command and writes the answer. One at a time: two changes to one config at once
// would be asking for trouble.
func (l *AWGLink) handleOp(ctx context.Context, c *websocket.Conn, op ingestproto.AWGOp) {
	l.opMu.Lock()
	defer l.opMu.Unlock()
	res := l.runOp(ctx, op)
	res.Type, res.ID = "awg_op_result", op.ID
	// The log says what was asked and how it ended, never the configuration.
	l.log().Info("management command", "op", op.Op, "container", op.Container, "status", res.Status, "code", res.Code)
	if err := writeMsg(ctx, c, res); err != nil {
		l.log().Warn("could not send the answer to a management command")
	}
}

func (l *AWGLink) runOp(ctx context.Context, op ingestproto.AWGOp) ingestproto.AWGOpResult {
	fail := func(code string) ingestproto.AWGOpResult { return ingestproto.AWGOpResult{Status: "error", Code: code} }
	if len(l.ManageArgv) == 0 {
		return fail("management_off")
	}
	if !opContainerRe.MatchString(op.Container) {
		return fail("bad_container")
	}
	var arg string
	switch op.Op {
	case "add":
		if !opNameRe.MatchString(op.Name) {
			return fail("bad_name")
		}
		arg = op.Name
	case "revoke":
		if !opKeyRe.MatchString(op.Key) {
			return fail("bad_key")
		}
		arg = op.Key
	default:
		return fail("bad_operation")
	}
	argv := append(append([]string{}, l.ManageArgv...), op.Op, op.Container, arg)
	rctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	run := l.RunCmd
	if run == nil {
		run = runArgv
	}
	out, err := run(rctx, argv)
	if err != nil && len(out) == 0 {
		return fail("helper_failed")
	}
	return parseOpOutput(op.Op, string(out))
}

func runArgv(ctx context.Context, argv []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var out bytes.Buffer
	cmd.Stdout = &limitWriter{w: &out, n: 64 << 10}
	err := cmd.Run()
	return out.Bytes(), err
}

// parseOpOutput reads the helper's answer: "RESULT<TAB>ok<TAB>key<TAB>ip" or "RESULT<TAB>error<TAB>code",
// and, after "ok" for add, a blank line and the client configuration.
func parseOpOutput(op, text string) ingestproto.AWGOpResult {
	first, rest, _ := strings.Cut(text, "\n")
	f := strings.Split(strings.TrimRight(first, "\r"), "\t")
	if len(f) < 3 || f[0] != "RESULT" {
		return ingestproto.AWGOpResult{Status: "error", Code: "bad_helper_output"}
	}
	if f[1] != "ok" {
		code := f[2]
		if !regexp.MustCompile(`^[a-z0-9_]{1,40}$`).MatchString(code) {
			code = "helper_error"
		}
		return ingestproto.AWGOpResult{Status: "error", Code: code}
	}
	res := ingestproto.AWGOpResult{Status: "ok", Key: f[2]}
	if len(f) >= 4 {
		res.IP = f[3]
	}
	if !opKeyRe.MatchString(res.Key) {
		return ingestproto.AWGOpResult{Status: "error", Code: "bad_helper_output"}
	}
	if op == "add" {
		cfg := strings.TrimLeft(rest, "\r\n")
		if cfg == "" || len(cfg) > ingestproto.MaxAWGConfigBytes || !strings.Contains(cfg, "[Interface]") {
			return ingestproto.AWGOpResult{Status: "error", Code: "bad_helper_output"}
		}
		res.Config = cfg
	}
	return res
}
