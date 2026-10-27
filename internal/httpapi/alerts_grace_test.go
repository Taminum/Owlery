package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/notify"
	"github.com/Taminum/Owlery/internal/store"
)

func TestABlipThatClosesWithinTheGraceNeverShowsOrNotifies(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	fake := &botTelegram{}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	old := notify.BaseURL
	notify.BaseURL = srv.URL
	defer func() { notify.BaseURL = old }()
	if st, b := w.owner.do("POST", "/api/v1/notify/channels", map[string]any{"name": "Me", "token": tgToken, "chat_id": "424242", "digest_hour": nil, "digest_tz": "UTC"}); st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	base := len(fake.replies())
	store.AlertGrace = 2 * time.Minute

	ins := func(subject, label, opened string) {
		if _, err := w.h.st.Pool().Exec(ctx, `INSERT INTO alerts (kind, subject, label, detail, opened_at, last_seen_at) VALUES ('probe_down',$1,$2,'x',`+opened+`,now())`, subject, label); err != nil {
			t.Fatal(err)
		}
	}
	list := func() string { _, b := w.owner.get("/api/v1/alerts?state=all"); return string(b) }
	wk := &notify.Worker{Store: w.h.st, Ring: w.h.srv.Ring, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	ins("new", "Just opened", "now()")
	ins("steady", "Open for ten minutes", "now() - interval '10 minutes'")
	// One that opened and closed within a minute.
	ins("blip", "Came and went", "now() - interval '90 seconds'")
	if _, err := w.h.st.Pool().Exec(ctx, `UPDATE alerts SET resolved_at = opened_at + interval '40 seconds' WHERE subject = 'blip'`); err != nil {
		t.Fatal(err)
	}
	out := list()
	if strings.Contains(out, "Just opened") || strings.Contains(out, "Came and went") || !strings.Contains(out, "Open for ten minutes") {
		t.Fatalf("a new alert and a blip stay out of the list until they have lasted: %s", out)
	}
	wk.Round(ctx)
	got := strings.Join(fake.replies()[base:], "|")
	if strings.Contains(got, "Just opened") || strings.Contains(got, "Came and went") || !strings.Contains(got, "Open for ten minutes") {
		t.Fatalf("Telegram: %s", got)
	}
	// Once the new one has held for the grace period, it shows and is announced.
	if _, err := w.h.st.Pool().Exec(ctx, `UPDATE alerts SET opened_at = now() - interval '3 minutes' WHERE subject = 'new'`); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(list(), "Just opened") {
		t.Fatalf("%s", list())
	}
	wk.Round(ctx)
	if !strings.Contains(strings.Join(fake.replies()[base:], "|"), "Just opened") {
		t.Fatalf("%v", fake.replies()[base:])
	}
}
