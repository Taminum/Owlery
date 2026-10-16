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

	"github.com/Taminum/RemnaScope/internal/notify"
)

const tgToken = "123456789:AAEhBP0av28wFoZxqlx-ab_cdEfGhIjKlMnOp"

type fakeTelegram struct {
	mu   sync.Mutex
	sent []string
	chat string
	fail bool
}

func (f *fakeTelegram) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if !strings.HasPrefix(r.URL.Path, "/bot"+tgToken+"/") || f.fail {
		_, _ = w.Write([]byte(`{"ok":false,"description":"Unauthorized"}`))
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/getMe"):
		_, _ = w.Write([]byte(`{"ok":true,"result":{"username":"scope_bot"}}`))
	case strings.HasSuffix(r.URL.Path, "/getUpdates"):
		_, _ = w.Write([]byte(`{"ok":true,"result":[{"message":{"chat":{"id":424242,"type":"private","first_name":"Mish","username":"mish"}}}]}`))
	case strings.HasSuffix(r.URL.Path, "/sendMessage"):
		var in struct {
			ChatID string `json:"chat_id"`
			Text   string `json:"text"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &in)
		f.chat = in.ChatID
		f.sent = append(f.sent, in.Text)
		_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
	}
}

func (f *fakeTelegram) texts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sent...)
}

func TestTelegramChannelIsStoredSealedAndAnnouncesAlertsOnce(t *testing.T) {
	w := newAgentWorld(t)
	fake := &fakeTelegram{}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	old := notify.BaseURL
	notify.BaseURL = srv.URL
	defer func() { notify.BaseURL = old }()
	ctx := context.Background()

	// An alert that is open before the channel exists is not announced afterwards.
	if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO alerts (kind, subject, label, detail, opened_at, last_seen_at) VALUES ('agent_silent','old','Old thing','x',now(),now())`); err != nil {
		t.Fatal(err)
	}

	if st, _ := w.viewer.do("POST", "/api/v1/notify/telegram/discover", map[string]string{"token": tgToken}); st != 403 {
		t.Fatalf("a viewer used the discovery: %d", st)
	}
	if st, _ := w.owner.do("POST", "/api/v1/notify/telegram/discover", map[string]string{"token": "nope"}); st != 422 {
		t.Fatalf("a bad token was accepted: %d", st)
	}
	st, b := w.owner.do("POST", "/api/v1/notify/telegram/discover", map[string]string{"token": tgToken})
	if st != 200 || !strings.Contains(string(b), `"424242"`) || !strings.Contains(string(b), "scope_bot") {
		t.Fatalf("%d %s", st, b)
	}

	// A wrong chat id never gets stored; a channel is created only after a message reached the chat.
	fake.mu.Lock()
	fake.fail = true
	fake.mu.Unlock()
	if st, _ := w.owner.do("POST", "/api/v1/notify/channels", map[string]any{"name": "Me", "token": tgToken, "chat_id": "424242"}); st != 422 {
		t.Fatalf("a rejected send created a channel: %d", st)
	}
	fake.mu.Lock()
	fake.fail = false
	fake.mu.Unlock()
	st, b = w.owner.do("POST", "/api/v1/notify/channels", map[string]any{"name": "Me", "token": tgToken, "chat_id": "424242", "digest_hour": 9, "digest_tz": "Asia/Yekaterinburg"})
	if st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	if strings.Contains(string(b), tgToken) {
		t.Fatal("the response carries the token")
	}
	var ch struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &ch)
	var raw []byte
	_ = w.h.st.Pool().QueryRow(ctx, `SELECT secret_ct FROM notify_channels WHERE id=$1`, ch.ID).Scan(&raw)
	if len(raw) == 0 || strings.Contains(string(raw), "AAEhBP0av28") {
		t.Fatal("the token is stored in the clear")
	}
	_, lb := w.owner.get("/api/v1/notify/channels")
	if strings.Contains(string(lb), tgToken) || !strings.Contains(string(lb), "…4242") {
		t.Fatalf("%s", lb)
	}
	before := len(fake.texts())

	wk := &notify.Worker{Store: w.h.st, Ring: w.h.srv.Ring, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	// Before the digest hour, whatever the real clock says, so that this round is not a digest round.
	early, _ := time.LoadLocation("Asia/Yekaterinburg")
	wk.Now = func() time.Time { return time.Date(2026, 10, 16, 3, 0, 0, 0, early) }
	wk.Round(ctx)
	if len(fake.texts()) != before {
		t.Fatalf("an alert that was already open was announced: %v", fake.texts()[before:])
	}

	// A new alert goes out once, and its closing goes out once.
	if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO alerts (kind, subject, label, detail, opened_at, last_seen_at) VALUES ('sec_tls','n','Certificate x.example:443','expires in 3 days',now(),now())`); err != nil {
		t.Fatal(err)
	}
	wk.Round(ctx)
	wk.Round(ctx)
	got := fake.texts()[before:]
	if len(got) != 1 || !strings.Contains(got[0], "Certificate x.example:443") {
		t.Fatalf("%v", got)
	}
	if _, err := w.h.st.Pool().Exec(ctx, `UPDATE alerts SET resolved_at=now() WHERE subject='n'`); err != nil {
		t.Fatal(err)
	}
	wk.Round(ctx)
	wk.Round(ctx)
	got = fake.texts()[before:]
	if len(got) != 2 || !strings.HasPrefix(got[1], "✅ Закрыто") {
		t.Fatalf("%v", got)
	}

	// The digest goes out once a day, when its hour has come.
	loc, _ := time.LoadLocation("Asia/Yekaterinburg")
	day := time.Date(2026, 10, 16, 10, 0, 0, 0, loc)
	wk.Now = func() time.Time { return day }
	n := len(fake.texts())
	wk.Round(ctx)
	wk.Round(ctx)
	if d := fake.texts()[n:]; len(d) != 1 || !strings.HasPrefix(d[0], "RemnaScope: за сутки") {
		t.Fatalf("%v", d)
	}
	wk.Now = func() time.Time { return day.Add(24 * time.Hour) }
	wk.Round(ctx)
	if len(fake.texts()) != n+2 {
		t.Fatalf("the next day's digest was not sent: %d", len(fake.texts())-n)
	}

	// Removing the channel stops everything.
	if st, _ := w.owner.do("DELETE", "/api/v1/notify/channels/"+ch.ID, nil); st != 204 {
		t.Fatal(st)
	}
}
