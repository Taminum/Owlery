package notify

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Taminum/Owlery/internal/secrets"
	"github.com/Taminum/Owlery/internal/store"
)

// Bot answers commands written to a channel's bot, from the channel's own chat and from no other. It only
// reads Owlery and replies; the one thing it changes is how long notifications are muted.
type Bot struct {
	Store *store.Store
	Ring  *secrets.Keyring
	Log   *slog.Logger
	Now   func() time.Time

	mu      sync.Mutex
	running map[string]context.CancelFunc
}

func (b *Bot) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// Run starts a poller for every channel that has commands on, and stops it when the channel is switched off or
// deleted.
func (b *Bot) Run(ctx context.Context) {
	b.running = map[string]context.CancelFunc{}
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		b.sync(ctx)
		select {
		case <-ctx.Done():
			b.mu.Lock()
			for _, c := range b.running {
				c()
			}
			b.mu.Unlock()
			return
		case <-t.C:
		}
	}
}

func (b *Bot) sync(ctx context.Context) {
	chans, err := b.Store.ListNotifyChannels(ctx)
	if err != nil {
		return
	}
	want := map[string]bool{}
	for _, c := range chans {
		if c.Enabled && c.Commands {
			want[c.ID] = true
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, cancel := range b.running {
		if !want[id] {
			cancel()
			delete(b.running, id)
		}
	}
	for id := range want {
		if _, ok := b.running[id]; !ok {
			cctx, cancel := context.WithCancel(ctx)
			b.running[id] = cancel
			go b.poll(cctx, id)
		}
	}
}

func (b *Bot) channel(ctx context.Context, id string) (store.NotifyChannel, bool) {
	chans, err := b.Store.ListNotifyChannels(ctx)
	if err != nil {
		return store.NotifyChannel{}, false
	}
	for _, c := range chans {
		if c.ID == id {
			return c, c.Enabled && c.Commands
		}
	}
	return store.NotifyChannel{}, false
}

func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func (b *Bot) poll(ctx context.Context, id string) {
	var recent []time.Time // when the last commands came, to keep a flood of them from doing work
	for ctx.Err() == nil {
		ch, ok := b.channel(ctx, id)
		if !ok {
			return
		}
		sec, err := b.Store.NotifyChannelSecret(ctx, id)
		if err != nil {
			return
		}
		s, err := Open(b.Ring, sec)
		if err != nil {
			if !sleep(ctx, time.Minute) {
				return
			}
			continue
		}
		offset := ch.BotOffset
		if offset == 0 {
			// First time: what was written before this moment is old and is not answered.
			_, last, err := Updates(ctx, s.Token, -1, 0)
			if err != nil {
				if !sleep(ctx, 30*time.Second) {
					return
				}
				continue
			}
			offset = last + 1
			_ = b.Store.SetBotOffset(ctx, id, offset)
			continue
		}
		ups, last, err := Updates(ctx, s.Token, offset, 8)
		if err != nil {
			if !sleep(ctx, 20*time.Second) { // the Bot API said no or is not reachable: not a reason to hammer it
				return
			}
			continue
		}
		if last >= offset {
			_ = b.Store.SetBotOffset(ctx, id, last+1)
		}
		for _, u := range ups {
			if u.ChatID != s.ChatID || !u.HasText {
				continue // only the channel's own chat may ask
			}
			now := b.now()
			if now.Unix()-u.Date > 120 {
				continue // stale: written while the server was down
			}
			cut := now.Add(-time.Minute)
			kept := recent[:0]
			for _, t := range recent {
				if t.After(cut) {
					kept = append(kept, t)
				}
			}
			recent = append(kept, now)
			if len(recent) > 12 {
				continue
			}
			b.handle(ctx, ch, s, u.Text)
		}
		if len(ups) == 0 && !sleep(ctx, time.Second) {
			return
		}
	}
}

// Command splits "/stats@my_bot arg" into "stats" and "arg".
func Command(text string) (cmd, arg string, ok bool) {
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, "/") {
		return "", "", false
	}
	first, rest, _ := strings.Cut(text, " ")
	first = strings.TrimPrefix(first, "/")
	if at := strings.IndexByte(first, '@'); at >= 0 {
		first = first[:at]
	}
	return strings.ToLower(first), strings.TrimSpace(rest), first != ""
}

func (b *Bot) handle(ctx context.Context, ch store.NotifyChannel, s Secret, text string) {
	cmd, arg, ok := Command(text)
	if !ok {
		return
	}
	reply := func(t string) {
		if t == "" {
			return
		}
		if err := Send(ctx, s.Token, s.ChatID, t); err != nil {
			b.Log.Warn("notify bot: reply failed")
		}
	}
	now := b.now()
	loc, err := time.LoadLocation(ch.DigestTZ)
	if err != nil {
		loc = time.UTC
	}
	var out string
	switch cmd {
	case "start", "help":
		out = helpText
	case "stats", "summary", "svodka":
		out, err = BuildStats(ctx, b.Store, now, loc)
	case "servers", "hosts":
		out, err = BuildServers(ctx, b.Store, now)
	case "alerts":
		out, err = BuildAlerts(ctx, b.Store, now)
	case "bans", "fail2ban":
		out, err = BuildBans(ctx, b.Store, now)
	case "certs", "tls":
		out, err = BuildCerts(ctx, b.Store, now)
	case "pay", "billing":
		out, err = BuildPay(ctx, b.Store, now)
	case "awg":
		out, err = BuildAWG(ctx, b.Store, now)
	case "users":
		out, err = BuildUsers(ctx, b.Store, now)
	case "dns":
		out, err = BuildDNS(ctx, b.Store, now)
	case "mute":
		h := 1
		if arg != "" {
			n, perr := strconv.Atoi(strings.TrimSuffix(strings.TrimSuffix(arg, "h"), "ч"))
			if perr != nil || n < 1 || n > 24*14 {
				out = "Сколько часов? Например: /mute 2 (от 1 до 336)."
				break
			}
			h = n
		}
		until := now.UTC().Add(time.Duration(h) * time.Hour)
		if _, perr := b.Store.PatchNotifyChannel(ctx, ch.ID, store.NotifyPatch{SetMute: true, MutedUntil: &until}); perr != nil {
			err = perr
			break
		}
		out = fmt.Sprintf("🔕 Тихо до %s. Срочное (атака, сервер не отвечает) всё равно придёт. /unmute вернёт всё как было.", until.In(loc).Format("02.01 15:04"))
	case "unmute":
		if _, perr := b.Store.PatchNotifyChannel(ctx, ch.ID, store.NotifyPatch{SetMute: true}); perr != nil {
			err = perr
			break
		}
		out = "🔔 Оповещения снова идут как обычно."
	default:
		out = "Не знаю такой команды. /help покажет, что я умею."
	}
	if err != nil {
		b.Log.Error("notify bot: building a reply", "cmd", cmd)
		out = "Не получилось собрать ответ, попробуйте ещё раз чуть позже."
	}
	reply(out)
}
