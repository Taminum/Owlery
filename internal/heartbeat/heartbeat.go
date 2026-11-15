// Package heartbeat tells somebody outside that the panel is alive. Telegram messages are sent by the panel itself, so when the
// panel (or its database) stops, nobody would be told. Once a minute, and only while the database answers, the panel asks one
// address of an outside service that raises the alarm when the asking stops (a dead man's switch). Nothing is sent but the ask.
package heartbeat

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Parse checks the address: https, a host, no login in it.
func Parse(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return "", errors.New("HEARTBEAT_URL must be an https address with a host and no login in it")
	}
	return u.String(), nil
}

// Beater asks the address while Alive says the panel is well.
type Beater struct {
	URL    string
	Alive  func(context.Context) error
	Client *http.Client
	Log    *slog.Logger

	failing bool
}

func (b *Beater) once(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if b.Alive != nil {
		if err := b.Alive(ctx); err != nil {
			return // a panel that is not well says nothing, which is the signal
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.URL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "owlery-heartbeat")
	c := b.Client
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := c.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode >= 400 {
			err = errors.New(resp.Status)
		}
	}
	if err != nil {
		if !b.failing && b.Log != nil && ctx.Err() == nil {
			b.Log.Warn("heartbeat did not go out", "detail", err.Error())
		}
		b.failing = true
		return
	}
	b.failing = false
}

// Run asks every interval until the context ends.
func (b *Beater) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		b.once(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
