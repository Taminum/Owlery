package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/notify"
	"github.com/Taminum/Owlery/internal/secproto"
)

// botTelegram is a bot that has a queue of messages written to it.
type botTelegram struct {
	mu      sync.Mutex
	queue   []map[string]any // updates not yet taken
	sent    []string
	offsets []int64
}

func (f *botTelegram) push(id int64, chat int64, text string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queue = append(f.queue, map[string]any{"update_id": id, "message": map[string]any{"date": time.Now().Unix(), "text": text, "chat": map[string]any{"id": chat}}})
}

func (f *botTelegram) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if !strings.HasPrefix(r.URL.Path, "/bot"+tgToken+"/") {
		_, _ = w.Write([]byte(`{"ok":false}`))
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/getMe"):
		_, _ = w.Write([]byte(`{"ok":true,"result":{"username":"scope_bot"}}`))
	case strings.HasSuffix(r.URL.Path, "/getUpdates"):
		var in struct {
			Offset int64 `json:"offset"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &in)
		f.offsets = append(f.offsets, in.Offset)
		var out []map[string]any
		for _, u := range f.queue {
			id := int64(u["update_id"].(int64))
			if in.Offset == -1 || id >= in.Offset {
				out = append(out, u)
			}
		}
		if in.Offset == -1 && len(out) > 1 {
			out = out[len(out)-1:]
		}
		res, _ := json.Marshal(map[string]any{"ok": true, "result": out})
		_, _ = w.Write(res)
	case strings.HasSuffix(r.URL.Path, "/sendMessage"):
		var in struct {
			Text string `json:"text"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &in)
		f.sent = append(f.sent, in.Text)
		_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
	}
}

func (f *botTelegram) replies() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sent...)
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestTheBotAnswersCommandsOnlyFromItsOwnChatAndIgnoresOldMessages(t *testing.T) {
	w := newWorld(t)
	fake := &botTelegram{}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	old := notify.BaseURL
	notify.BaseURL = srv.URL
	defer func() { notify.BaseURL = old }()
	ctx := context.Background()

	// A server with a reading, so that the summary has something to say.
	vps, err := w.h.st.CreateVPS(ctx, "", "exit-bot", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	gb := int64(1 << 30)
	_ = w.h.st.SaveHost(ctx, vps.ID, secproto.Host{Type: "host", MemTotal: 4 * gb, MemUsed: gb, CPUPct: 12, Disks: []secproto.HostDisk{{Mount: "/", Total: 100 * gb, Used: 30 * gb}}}, time.Now().UTC())
	if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO bills (name, amount, currency, period_months, next_due) VALUES ('exit-bot VPS', 5, 'EUR', 1, current_date + 2)`); err != nil {
		t.Fatal(err)
	}

	fake.push(1, 424242, "/stats") // written before the bot started listening: never answered
	st, b := w.owner.do("POST", "/api/v1/notify/channels", map[string]any{"name": "Me", "token": tgToken, "chat_id": "424242", "digest_hour": nil, "digest_tz": "UTC"})
	if st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	var ch struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &ch)
	before := len(fake.replies()) // the test message of the channel's creation

	bctx, cancel := context.WithCancel(ctx)
	defer cancel()
	bot := &notify.Bot{Store: w.h.st, Ring: w.h.srv.Ring, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	go bot.Run(bctx)
	time.Sleep(1500 * time.Millisecond) // the first pass only learns where the queue stands
	if n := len(fake.replies()); n != before {
		t.Fatalf("an old message was answered: %v", fake.replies()[before:])
	}

	fake.push(10, 999, "/stats") // another chat: not answered
	fake.push(11, 424242, "/stats")
	waitFor(t, "the summary", func() bool { return len(fake.replies()) > before })
	reply := fake.replies()[before]
	for _, want := range []string{"СВОДКА Owlery", "Всего серверов: 1", "exit-bot", "ЦП: 12%", "RAM: 25%", "exit-bot VPS", "Ближайшие оплаты"} {
		if !strings.Contains(reply, want) {
			t.Errorf("%q is missing from the summary:\n%s", want, reply)
		}
	}
	for _, r := range fake.replies() {
		if strings.Contains(r, "999") {
			t.Fatal("the other chat got an answer")
		}
	}

	// /mute sets the mute and says until when; /help lists the commands.
	fake.push(12, 424242, "/mute 2")
	waitFor(t, "the mute", func() bool { return len(fake.replies()) > before+1 })
	if !strings.Contains(fake.replies()[before+1], "Тихо до") {
		t.Fatalf("%v", fake.replies())
	}
	_, lb := w.owner.get("/api/v1/notify/channels")
	if !strings.Contains(string(lb), `"muted_until":"`) {
		t.Fatalf("%s", lb)
	}
	fake.push(13, 424242, "/unmute")
	waitFor(t, "the unmute", func() bool { return len(fake.replies()) > before+2 })
	_, lb = w.owner.get("/api/v1/notify/channels")
	if strings.Contains(string(lb), `"muted_until":"`) {
		t.Fatalf("%s", lb)
	}
	fake.push(14, 424242, "/help")
	waitFor(t, "the help", func() bool { return len(fake.replies()) > before+3 })
	if !strings.Contains(fake.replies()[before+3], "/stats") {
		t.Fatalf("%v", fake.replies())
	}
	// Commands can be switched off for a channel: the bot stops answering.
	if st, _ := w.owner.do("PATCH", "/api/v1/notify/channels/"+ch.ID, map[string]any{"commands": false}); st != 200 {
		t.Fatalf("%d", st)
	}
}

func TestNotificationTuningFiltersByGroupHoldsInQuietHoursAndRemindsOfWhatStaysOpen(t *testing.T) {
	w := newWorld(t)
	fake := &botTelegram{}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	old := notify.BaseURL
	notify.BaseURL = srv.URL
	defer func() { notify.BaseURL = old }()
	ctx := context.Background()

	st, b := w.owner.do("POST", "/api/v1/notify/channels", map[string]any{"name": "Me", "token": tgToken, "chat_id": "424242", "digest_hour": nil, "digest_tz": "UTC"})
	if st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	var ch struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &ch)
	for name, bad := range map[string]map[string]any{
		"unknown group":  {"prefs": map[string]any{"off": []string{"nonsense"}}},
		"quiet no hours": {"prefs": map[string]any{"quiet_on": true}},
		"bad time":       {"prefs": map[string]any{"quiet_on": true, "quiet_from": "25:00", "quiet_to": "07:00"}},
		"unknown key":    {"prefs": map[string]any{"evil": true}},
		"long reminder":  {"prefs": map[string]any{"remind_hours": 9999}},
		"long mute":      {"mute_hours": 9999},
	} {
		if st, _ := w.owner.do("PATCH", "/api/v1/notify/channels/"+ch.ID, bad); st != 422 {
			t.Errorf("%s was accepted: %d", name, st)
		}
	}
	if st, b := w.owner.do("PATCH", "/api/v1/notify/channels/"+ch.ID, map[string]any{"prefs": map[string]any{"off": []string{"dns"}, "no_resolved": true, "quiet_on": true, "quiet_from": "22:00", "quiet_to": "07:00", "remind_hours": 1}}); st != 200 || !strings.Contains(string(b), `"no_resolved":true`) {
		t.Fatalf("%d %s", st, b)
	}

	loc := time.UTC
	at := func(h, m int) time.Time { return time.Date(2026, 10, 20, h, m, 0, 0, loc) }
	wk := &notify.Worker{Store: w.h.st, Ring: w.h.srv.Ring, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ins := func(kind, subject, label string) {
		if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO alerts (kind, subject, label, detail, opened_at, last_seen_at) VALUES ($1,$2,$3,'',now(),now())`, kind, subject, label); err != nil {
			t.Fatal(err)
		}
	}
	base := len(fake.replies())
	ins("dns_change", "d", "DNS thing")        // a group switched off: never announced
	ins("user_expiry", "u", "Subscription x")  // not critical: held in quiet hours
	ins("host_flood", "f", "Flood on exit-nl") // critical: goes out at night
	wk.Now = func() time.Time { return at(23, 30) }
	wk.Round(ctx)
	got := fake.replies()[base:]
	if len(got) != 1 || !strings.Contains(got[0], "Flood on exit-nl") {
		t.Fatalf("at night only the critical one goes out: %v", got)
	}
	// In the morning the held one goes out, the switched-off one never does.
	wk.Now = func() time.Time { return at(8, 0) }
	wk.Round(ctx)
	got = fake.replies()[base:]
	if len(got) != 2 || !strings.Contains(got[1], "Subscription x") {
		t.Fatalf("%v", got)
	}
	for _, g := range got {
		if strings.Contains(g, "DNS thing") {
			t.Fatalf("a switched-off group was announced: %v", got)
		}
	}
	// Closing is not announced when the channel does not want it.
	if _, err := w.h.st.Pool().Exec(ctx, `UPDATE alerts SET resolved_at = now() WHERE subject = 'u'`); err != nil {
		t.Fatal(err)
	}
	wk.Round(ctx)
	if n := len(fake.replies()) - base; n != 2 {
		t.Fatalf("a closing was announced: %v", fake.replies()[base:])
	}
	// An alert that stays open is repeated after the hours asked for.
	if _, err := w.h.st.Pool().Exec(ctx, `UPDATE alerts SET notified_open_at = now() - interval '3 hours' WHERE subject = 'f'`); err != nil {
		t.Fatal(err)
	}
	wk.Now = func() time.Time { return time.Now().UTC() }
	wk.Round(ctx)
	got = fake.replies()[base:]
	if len(got) != 3 || !strings.Contains(got[2], "Всё ещё открыто") || !strings.Contains(got[2], "Flood on exit-nl") {
		t.Fatalf("%v", got)
	}
	wk.Round(ctx)
	if n := len(fake.replies()) - base; n != 3 {
		t.Fatalf("a reminder was repeated at once: %v", fake.replies()[base:])
	}
}
