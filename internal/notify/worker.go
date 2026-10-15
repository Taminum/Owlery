package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Taminum/RemnaScope/internal/secrets"
	"github.com/Taminum/RemnaScope/internal/store"
)

const (
	every       = 30 * time.Second
	maxPerRound = 8 // above this, alerts are announced as one summary instead of one message each
	sealContext = "notify:telegram"
)

// Secret is what a Telegram channel needs to send.
type Secret struct {
	Token  string `json:"t"`
	ChatID string `json:"c"`
}

// Seal encrypts a channel secret for storage.
func Seal(ring *secrets.Keyring, s Secret) (store.NotifySecret, error) {
	b, _ := json.Marshal(s)
	sealed, err := ring.Seal(sealContext, b)
	if err != nil {
		return store.NotifySecret{}, err
	}
	return store.NotifySecret{Ciphertext: sealed.Ciphertext, Nonce: sealed.Nonce, KeyVersion: sealed.KeyVersion}, nil
}

// Open decrypts a stored channel secret.
func Open(ring *secrets.Keyring, s store.NotifySecret) (Secret, error) {
	b, err := ring.Open(sealContext, secrets.Sealed{Ciphertext: s.Ciphertext, Nonce: s.Nonce, KeyVersion: s.KeyVersion})
	if err != nil {
		return Secret{}, err
	}
	var out Secret
	if err := json.Unmarshal(b, &out); err != nil {
		return Secret{}, err
	}
	return out, nil
}

type Worker struct {
	Store *store.Store
	Ring  *secrets.Keyring
	Log   *slog.Logger
	Now   func() time.Time
}

func (w *Worker) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		w.Round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// SendTo sends a text to one channel and records how it went.
func (w *Worker) SendTo(ctx context.Context, ch store.NotifyChannel, text string) error {
	sec, err := w.Store.NotifyChannelSecret(ctx, ch.ID)
	if err != nil {
		return err
	}
	s, err := Open(w.Ring, sec)
	if err != nil {
		_ = w.Store.NotifyResult(ctx, ch.ID, false, "key")
		return SendError{"key"}
	}
	err = Send(ctx, s.Token, s.ChatID, text)
	if err != nil {
		code := ErrNetwork
		if se, ok := err.(SendError); ok {
			code = se.Code
		}
		_ = w.Store.NotifyResult(ctx, ch.ID, false, code)
		return err
	}
	_ = w.Store.NotifyResult(ctx, ch.ID, true, "")
	return nil
}

// Round announces what is pending and sends a digest whose hour has come.
func (w *Worker) Round(ctx context.Context) {
	chans, err := w.Store.ListNotifyChannels(ctx)
	if err != nil || len(chans) == 0 {
		return
	}
	w.alerts(ctx, chans)
	w.digests(ctx, chans)
}

func alertLine(n store.PendingAlertNotice) string {
	if n.Closed {
		return "✅ Закрыто: " + n.Label
	}
	if n.Detail != "" {
		return "⚠️ " + n.Label + "\n" + n.Detail
	}
	return "⚠️ " + n.Label
}

func (w *Worker) alerts(ctx context.Context, chans []store.NotifyChannel) {
	var targets []store.NotifyChannel
	for _, c := range chans {
		if c.Enabled && c.OnAlerts {
			targets = append(targets, c)
		}
	}
	if len(targets) == 0 {
		return
	}
	pending, err := w.Store.PendingAlertNotices(ctx, 50)
	if err != nil || len(pending) == 0 {
		return
	}
	var texts []string
	if len(pending) > maxPerRound {
		var b strings.Builder
		fmt.Fprintf(&b, "RemnaScope: оповещений за раз: %d\n", len(pending))
		for i, n := range pending {
			if i >= 10 {
				b.WriteString("…\n")
				break
			}
			b.WriteString(alertLine(n) + "\n")
		}
		texts = []string{b.String()}
	} else {
		for _, n := range pending {
			texts = append(texts, alertLine(n))
		}
	}
	ok := false
	for _, c := range targets {
		allSent := true
		for _, tx := range texts {
			if err := w.SendTo(ctx, c, tx); err != nil {
				allSent = false
				break
			}
		}
		ok = ok || allSent
	}
	if !ok {
		return // nobody got it: try again next round
	}
	var opened, closed []string
	for _, n := range pending {
		if n.Closed {
			closed = append(closed, n.ID)
		} else {
			opened = append(opened, n.ID)
		}
	}
	if err := w.Store.MarkAlertsNotified(ctx, opened, closed); err != nil {
		w.Log.Error("notify: marking alerts", "err", err)
	}
}

func (w *Worker) digests(ctx context.Context, chans []store.NotifyChannel) {
	for _, c := range chans {
		if !c.Enabled || c.DigestHr == nil {
			continue
		}
		loc, err := time.LoadLocation(c.DigestTZ)
		if err != nil {
			loc = time.UTC
		}
		local := w.now().In(loc)
		today := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, time.UTC)
		if local.Hour() < *c.DigestHr {
			continue
		}
		if c.DigestOn != nil && !c.DigestOn.Before(today) {
			continue // today's is already out
		}
		text, err := BuildDigest(ctx, w.Store, w.now(), loc)
		if err != nil {
			w.Log.Error("notify: building the digest", "err", err)
			continue
		}
		if err := w.SendTo(ctx, c, text); err != nil {
			continue
		}
		if err := w.Store.MarkDigestSent(ctx, c.ID, today); err != nil {
			w.Log.Error("notify: marking the digest", "err", err)
		}
	}
}

// BuildDigest writes the last 24 hours as a short message, the same facts as the "what changed" page for the
// owner (all panels, all servers).
func BuildDigest(ctx context.Context, st *store.Store, now time.Time, loc *time.Location) (string, error) {
	from, to := now.Add(-24*time.Hour), now
	var b strings.Builder
	fmt.Fprintf(&b, "RemnaScope: за сутки (до %s)\n", now.In(loc).Format("02.01 15:04"))

	open, err := st.ListAlerts(ctx, nil, true, true, 50)
	if err != nil {
		return "", err
	}
	panels, err := st.ListPanels(ctx, store.Scope{All: true})
	if err != nil {
		return "", err
	}
	var ids []string
	for _, p := range panels {
		if !p.Demo {
			ids = append(ids, p.ID)
		}
	}
	all, err := st.ListAlerts(ctx, ids, true, true, 50)
	if err == nil {
		open = all
	}
	if len(open) == 0 {
		b.WriteString("\nОткрытых оповещений нет.\n")
	} else {
		fmt.Fprintf(&b, "\nОткрытых оповещений: %d\n", len(open))
		for i, a := range open {
			if i >= 5 {
				b.WriteString("…\n")
				break
			}
			b.WriteString("• " + a.Label + "\n")
		}
	}

	ev, err := st.SecurityEventCounts(ctx, store.Scope{All: true}, from, to)
	if err != nil {
		return "", err
	}
	if len(ev) > 0 {
		b.WriteString("\nСерверы:\n")
		for i, e := range ev {
			if i >= 6 {
				break
			}
			fmt.Fprintf(&b, "• %s: %d\n", eventWord(e.Type), e.Count)
		}
	}
	if dns, err := st.DNSChangeCounts(ctx, from, to); err == nil && (dns.Total > 0 || dns.Failed > 0) {
		fmt.Fprintf(&b, "\nDNS: изменений %d", dns.Total)
		if dns.Failed > 0 {
			fmt.Fprintf(&b, ", проверок с ошибкой %d", dns.Failed)
		}
		b.WriteString("\n")
	}
	if len(ids) > 0 {
		q := store.AnalyticsQuery{PanelIDs: ids, From: from, To: to, NewOnly: true, Limit: 5}
		if sites, _, _, err := st.Sites(ctx, q); err == nil && len(sites) > 0 {
			b.WriteString("\nНовые сайты: ")
			for i, s := range sites {
				if i > 0 {
					b.WriteString(", ")
				}
				b.WriteString(s.Site)
			}
			b.WriteString("\n")
		}
		if nd, err := st.NewDevices(ctx, ids, from, to); err == nil && len(nd) > 0 {
			b.WriteString("\nНовые устройства дома: ")
			for i, d := range nd {
				if i > 0 {
					b.WriteString(", ")
				}
				if d.Name != "" {
					b.WriteString(d.Name)
				} else {
					b.WriteString(d.IP)
				}
			}
			b.WriteString("\n")
		}
	}
	return b.String(), nil
}

var eventWords = map[string]string{
	"fail2ban.ban": "блокировок Fail2ban", "fail2ban.unban": "снято блокировок", "firewall.rules_changed": "изменений правил firewall",
	"port.local_added": "новых слушающих портов", "port.local_removed": "портов перестали слушать", "port.public_reachable": "портов стали отвечать снаружи",
	"port.public_lost": "портов перестали отвечать", "port.discovered": "портов найдено поиском", "tls.discovered": "новых TLS-адресов",
	"tls.expired": "сертификатов истекло", "tls.expiry_threshold": "сертификатов скоро истекут",
}

func eventWord(t string) string {
	if w, ok := eventWords[t]; ok {
		return w
	}
	return t
}
