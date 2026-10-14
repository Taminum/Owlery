package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/Taminum/RemnaScope/internal/ingestproto"
)

// Counters accumulates what the agent could not deliver until the server has acknowledged
// a batch that reported it.
type Counters struct {
	mu      sync.Mutex
	dropped int64
	gaps    []ingestproto.Gap
}

func (c *Counters) Drop(reason string, lines int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().UTC()
	c.dropped += lines
	for i := range c.gaps {
		if c.gaps[i].Reason == reason && lines > 0 {
			c.gaps[i].Lines += lines
			c.gaps[i].To = &now
			return
		}
	}
	g := ingestproto.Gap{Reason: reason, Lines: lines, From: &now, To: &now}
	if len(c.gaps) < 20 {
		c.gaps = append(c.gaps, g)
	}
}

// Load restores loss recorded by an earlier run that the server has not been told about yet.
func (c *Counters) Load(dropped int64, gaps []ingestproto.Gap) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dropped += dropped
	c.gaps = append(append([]ingestproto.Gap(nil), gaps...), c.gaps...)
}

// Pending reports whether there is loss waiting to be reported.
func (c *Counters) Pending() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropped > 0 || len(c.gaps) > 0
}

type snapshot struct {
	dropped int64
	gaps    []ingestproto.Gap
}

func (c *Counters) Snapshot() snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return snapshot{dropped: c.dropped, gaps: append([]ingestproto.Gap(nil), c.gaps...)}
}

// Confirm removes what a snapshot reported once the server acknowledged it.
func (c *Counters) Confirm(s snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dropped -= s.dropped
	if len(s.gaps) <= len(c.gaps) {
		c.gaps = c.gaps[len(s.gaps):]
	}
}

type Shipper struct {
	URL           string
	TokenFile     string
	CAFile        string
	AllowInsecure bool // permits ws:// (local tests only)
	Spool         *Spool
	Counters      *Counters
	Epoch         string
	SourceID      string
	Version       string
	BatchLines    int
	BatchBytes    int
	BatchWait     time.Duration
	PingEvery     time.Duration
	AckTimeout    time.Duration
	OnAck         func(seq int64)
	Log           *slog.Logger
	// Live carries best-effort snapshots (router agents). They are sent when the connection is up
	// and dropped otherwise; they never delay or reorder the acknowledged stream.
	Live <-chan ingestproto.Live
}

// ErrUnrecoverableGap means the server expects lines the spool no longer has.
var ErrUnrecoverableGap = errors.New("agent: the server expects lines that are no longer in the spool")

// ErrRevoked means the server no longer accepts this agent.
var ErrRevoked = errors.New("agent: the server refused this agent (revoked or bad credential)")

func (s *Shipper) defaults() {
	if s.BatchLines <= 0 || s.BatchLines > ingestproto.MaxBatchLines {
		s.BatchLines = 500
	}
	if s.BatchBytes <= 0 {
		s.BatchBytes = 512 << 10
	}
	if s.BatchWait <= 0 {
		s.BatchWait = 2 * time.Second
	}
	if s.PingEvery <= 0 {
		s.PingEvery = 25 * time.Second
	}
	if s.AckTimeout <= 0 {
		s.AckTimeout = 30 * time.Second
	}
	if s.Log == nil {
		s.Log = slog.Default()
	}
}

func (s *Shipper) httpClient() (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.CAFile != "" {
		pem, err := os.ReadFile(s.CAFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("agent: no certificates in the CA file")
		}
		tc.RootCAs = pool
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tc, Proxy: http.ProxyFromEnvironment}}, nil
}

func (s *Shipper) token() (string, error) {
	b, err := os.ReadFile(s.TokenFile) // read on every connect so a rotated credential is picked up
	if err != nil {
		return "", err
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", errors.New("agent: the token file is empty")
	}
	return t, nil
}

// Run keeps one connection alive until ctx ends, reconnecting with backoff and jitter.
func (s *Shipper) Run(ctx context.Context) error {
	s.defaults()
	if !strings.HasPrefix(s.URL, "wss://") && !(s.AllowInsecure && strings.HasPrefix(s.URL, "ws://")) {
		return errors.New("agent: the server URL must be wss://")
	}
	backoff := time.Second
	for {
		progressed, err := s.session(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, ErrUnrecoverableGap) {
			return err
		}
		switch {
		case progressed:
			backoff = time.Second
		case errors.Is(err, ErrRevoked):
			backoff = max(backoff, 5*time.Minute) // do not hammer a server that said no
		}
		s.Log.Warn("connection ended", "err", err, "retry_in", backoff.Round(time.Second).String())
		wait := backoff/2 + time.Duration(rand.Int64N(int64(backoff/2)+1))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		if backoff *= 2; backoff > time.Minute && !errors.Is(err, ErrRevoked) {
			backoff = time.Minute
		}
	}
}

func readMsg(ctx context.Context, c *websocket.Conn, timeout time.Duration, v any) error {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, b, err := c.Read(rctx)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func writeMsg(ctx context.Context, c *websocket.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return c.Write(wctx, websocket.MessageText, b)
}

// session is one connection. progressed reports whether the server acknowledged anything.
func (s *Shipper) session(ctx context.Context) (progressed bool, err error) {
	tok, err := s.token()
	if err != nil {
		return false, err
	}
	hc, err := s.httpClient()
	if err != nil {
		return false, err
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	c, resp, err := websocket.Dial(dctx, s.URL, &websocket.DialOptions{
		HTTPClient: hc, HTTPHeader: http.Header{"Authorization": {"Bearer " + tok}}, CompressionMode: websocket.CompressionDisabled,
	})
	cancel()
	if err != nil {
		if resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 403) {
			return false, ErrRevoked
		}
		return false, err
	}
	defer c.CloseNow()
	c.SetReadLimit(ingestproto.MaxMessageBytes)

	if err := writeMsg(ctx, c, ingestproto.Hello{Type: "hello", ProtoVersion: ingestproto.Version, AgentVersion: s.Version, Epoch: s.Epoch, SourceID: s.SourceID}); err != nil {
		return false, err
	}
	var w ingestproto.Welcome
	if err := readMsg(ctx, c, 15*time.Second, &w); err != nil {
		return false, s.closeErr(err)
	}
	if w.Type != "welcome" {
		return false, fmt.Errorf("agent: unexpected %q instead of welcome", w.Type)
	}
	if w.AckSeq > 0 {
		if err := s.Spool.Ack(w.AckSeq); err != nil { // the server already has these
			return false, err
		}
		if s.OnAck != nil {
			s.OnAck(w.AckSeq)
		}
	}
	acked := w.AckSeq
	maxLines := min(s.BatchLines, w.MaxBatchLines)
	s.Log.Info("connected", "ack_seq", acked, "spool_bytes", s.Spool.Bytes())

	ping := time.NewTicker(s.PingEvery)
	defer ping.Stop()
	for {
		if err := s.flushLive(ctx, c); err != nil {
			return progressed, err
		}
		items, err := s.Spool.ReadFrom(acked+1, maxLines, s.BatchBytes)
		if err != nil {
			return progressed, err
		}
		if len(items) > 0 && items[0].Seq != acked+1 {
			return progressed, ErrUnrecoverableGap
		}
		if len(items) == 0 {
			select {
			case <-ctx.Done():
				return progressed, ctx.Err()
			case <-s.Spool.Ready():
				continue
			case f := <-s.Live: // a nil channel never fires, so node agents are unaffected
				if err := writeMsg(ctx, c, f); err != nil {
					return progressed, err
				}
			case <-ping.C:
				if err := writeMsg(ctx, c, ingestproto.Ping{Type: "ping", SpoolBytes: s.Spool.Bytes()}); err != nil {
					return progressed, err
				}
				var p ingestproto.Pong
				if err := readMsg(ctx, c, s.AckTimeout, &p); err != nil {
					return progressed, s.closeErr(err)
				}
			}
			continue
		}
		if len(items) < maxLines { // give a trickle a moment to fill the batch
			select {
			case <-time.After(s.BatchWait):
			case <-ctx.Done():
				return progressed, ctx.Err()
			}
			if items, err = s.Spool.ReadFrom(acked+1, maxLines, s.BatchBytes); err != nil {
				return progressed, err
			}
		}

		snap := s.Counters.Snapshot()
		b := ingestproto.Batch{Type: "batch", BatchID: fmt.Sprintf("%s-%d", s.Epoch, items[0].Seq), SpoolBytes: s.Spool.Bytes(),
			Dropped: snap.dropped, Gaps: snap.gaps}
		for _, it := range items {
			b.Items = append(b.Items, ingestproto.Item{Seq: it.Seq, Line: it.Line})
		}
		if err := writeMsg(ctx, c, b); err != nil {
			return progressed, err
		}
		var raw struct {
			Type        string `json:"type"`
			Code        string `json:"code"`
			ExpectedSeq int64  `json:"expected_seq"`
			BatchID     string `json:"batch_id"`
			AckSeq      int64  `json:"ack_seq"`
		}
		if err := readMsg(ctx, c, s.AckTimeout, &raw); err != nil {
			return progressed, s.closeErr(err)
		}
		switch {
		case raw.Type == "error" && raw.Code == "seq_gap":
			if raw.ExpectedSeq < items[0].Seq && !s.Spool.has(raw.ExpectedSeq) {
				return progressed, ErrUnrecoverableGap
			}
			return progressed, fmt.Errorf("agent: server expected sequence %d", raw.ExpectedSeq)
		case raw.Type != "ack" || raw.BatchID != b.BatchID || raw.AckSeq != items[len(items)-1].Seq:
			return progressed, fmt.Errorf("agent: unexpected reply %q (%s)", raw.Type, raw.Code)
		}
		acked = raw.AckSeq
		progressed = true
		s.Counters.Confirm(snap)
		if err := s.Spool.Ack(acked); err != nil {
			return progressed, err
		}
		if s.OnAck != nil {
			s.OnAck(acked)
		}
	}
}

// flushLive sends the newest waiting snapshot, if any, and drops older ones.
func (s *Shipper) flushLive(ctx context.Context, c *websocket.Conn) error {
	var last *ingestproto.Live
	for {
		select {
		case f := <-s.Live:
			last = &f
			continue
		default:
		}
		break
	}
	if last == nil {
		return nil
	}
	return writeMsg(ctx, c, *last)
}

func (s *Shipper) closeErr(err error) error {
	switch websocket.CloseStatus(err) {
	case websocket.StatusCode(ingestproto.CloseRevoked):
		return ErrRevoked
	}
	return err
}

// has reports whether the spool still holds the given sequence.
func (sp *Spool) has(seq int64) bool {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	for _, sg := range sp.segs {
		if seq >= sg.first && seq <= sg.last {
			return true
		}
	}
	return false
}
