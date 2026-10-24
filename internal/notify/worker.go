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

// quietNow says whether the channel is in its quiet hours or muted: only critical alerts are announced then.
func quietNow(c store.NotifyChannel, now time.Time) bool {
	if c.MutedUntil != nil && c.MutedUntil.After(now) {
		return true
	}
	p := c.Prefs
	if !p.QuietOn || p.QuietFrom == "" || p.QuietTo == "" {
		return false
	}
	loc, err := time.LoadLocation(c.DigestTZ)
	if err != nil {
		loc = time.UTC
	}
	l := now.In(loc)
	cur := l.Hour()*60 + l.Minute()
	from, to := minutesOf(p.QuietFrom), minutesOf(p.QuietTo)
	if from < 0 || to < 0 || from == to {
		return false
	}
	if from < to {
		return cur >= from && cur < to
	}
	return cur >= from || cur < to // across midnight
}

func minutesOf(hhmm string) int {
	var h, m int
	if _, err := fmt.Sscanf(hhmm, "%d:%d", &h, &m); err != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return -1
	}
	return h*60 + m
}

type verdict int

const (
	skip verdict = iota // this channel does not want it
	hold                // it wants it, but not now
	send
)

// judge decides what a channel does with one announcement.
func judge(c store.NotifyChannel, kind string, closed bool, now time.Time) verdict {
	if c.Prefs.GroupOff(kind) || (closed && c.Prefs.NoResolved) {
		return skip
	}
	if quietNow(c, now) && !store.CriticalKinds[kind] {
		return hold
	}
	return send
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
	now := w.now()
	pending, err := w.Store.PendingAlertNotices(ctx, 50)
	if err != nil {
		return
	}
	var opened, closed []string
	mark := func(n store.PendingAlertNotice) {
		if n.Closed {
			closed = append(closed, n.ID)
		} else {
			opened = append(opened, n.ID)
		}
	}
	batches := map[string][]store.PendingAlertNotice{} // channel id -> what it is to get now
	wantedBy := map[string][]string{}                  // alert id -> the channels that are to get it
	for _, n := range pending {
		held := false
		for _, c := range targets {
			switch judge(c, n.Kind, n.Closed, now) {
			case send:
				batches[c.ID] = append(batches[c.ID], n)
				wantedBy[n.ID] = append(wantedBy[n.ID], c.ID)
			case hold:
				held = true
			}
		}
		if len(wantedBy[n.ID]) == 0 && !held {
			mark(n) // nobody wants it: it is settled without a word
		}
	}
	delivered := map[string]bool{}
	for _, c := range targets {
		list := batches[c.ID]
		if len(list) == 0 {
			continue
		}
		var texts []string
		if len(list) > maxPerRound {
			var b strings.Builder
			fmt.Fprintf(&b, "RemnaScope: оповещений за раз: %d\n", len(list))
			for i, n := range list {
				if i >= 10 {
					b.WriteString("…\n")
					break
				}
				b.WriteString(alertLine(n) + "\n")
			}
			texts = []string{b.String()}
		} else {
			for _, n := range list {
				texts = append(texts, alertLine(n))
			}
		}
		allSent := true
		for _, tx := range texts {
			if err := w.SendTo(ctx, c, tx); err != nil {
				allSent = false
				break
			}
		}
		if allSent {
			for _, n := range list {
				delivered[n.ID] = true
			}
		}
	}
	for _, n := range pending {
		if delivered[n.ID] {
			mark(n)
		}
	}
	if len(opened) > 0 || len(closed) > 0 {
		if err := w.Store.MarkAlertsNotified(ctx, opened, closed); err != nil {
			w.Log.Error("notify: marking alerts", "err", err)
		}
	}
	w.reminders(ctx, targets, now)
}

// reminders repeats alerts that are still open, for the channels that asked for it.
func (w *Worker) reminders(ctx context.Context, targets []store.NotifyChannel, now time.Time) {
	for _, c := range targets {
		h := c.Prefs.RemindHours
		if h <= 0 {
			continue
		}
		due, err := w.Store.AlertsDueReminder(ctx, now.Add(-time.Duration(h)*time.Hour), 5)
		if err != nil || len(due) == 0 {
			continue
		}
		var ids []string
		for _, n := range due {
			if judge(c, n.Kind, false, now) != send {
				continue
			}
			line := fmt.Sprintf("🔔 Всё ещё открыто (%s): %s", sinceText(now.Sub(n.OpenedAt)), n.Label)
			if n.Detail != "" {
				line += "\n" + n.Detail
			}
			if err := w.SendTo(ctx, c, line); err != nil {
				break
			}
			ids = append(ids, n.ID)
		}
		if len(ids) > 0 {
			_ = w.Store.MarkAlertsReminded(ctx, ids)
		}
	}
}

func sinceText(d time.Duration) string {
	h := int(d.Hours())
	if h >= 48 {
		return fmt.Sprintf("%d дн.", h/24)
	}
	if h >= 1 {
		return fmt.Sprintf("%d ч", h)
	}
	return fmt.Sprintf("%d мин", int(d.Minutes()))
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

// buildDayEvents writes what happened in the last 24 hours, the same facts as the "what changed" page for the
// owner (all panels, all servers).
func buildDayEvents(ctx context.Context, st *store.Store, now time.Time, loc *time.Location) (string, error) {
	from, to := now.Add(-24*time.Hour), now
	var b strings.Builder
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

// BuildDigest is the daily message: the summary of the whole cluster, then what happened in the last day.
func BuildDigest(ctx context.Context, st *store.Store, now time.Time, loc *time.Location) (string, error) {
	head, err := buildStats(ctx, st, now, loc, "ЕЖЕДНЕВНАЯ СВОДКА RemnaScope")
	if err != nil {
		return "", err
	}
	day, err := buildDayEvents(ctx, st, now, loc)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(day) == "" {
		return head, nil
	}
	return head + "\n📈 За последние сутки:\n" + strings.TrimLeft(day, "\n"), nil
}
