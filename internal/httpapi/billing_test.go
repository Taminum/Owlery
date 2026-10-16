package httpapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/alerts"
)

func TestBillsBelongToTheOwnerMoveOnWhenPaidAndRaiseAnAlertWhenDue(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	now := time.Now().UTC()
	day := func(n int) string { return now.AddDate(0, 0, n).Format("2006-01-02") }

	for _, c := range []*client{w.viewer, w.op, w.adm} {
		if st, _ := c.get("/api/v1/billing"); st != 403 {
			t.Fatalf("only the owner reads payments: %d", st)
		}
	}
	body := map[string]any{"name": "exit-2 VPS", "provider": "Senko", "amount": 5.5, "currency": "eur", "period_months": 1, "next_due": day(2), "note": ""}
	if st, _ := w.viewer.do("POST", "/api/v1/billing", body); st != 403 {
		t.Fatalf("%d", st)
	}
	for name, bad := range map[string]map[string]any{
		"name":     {"name": "", "amount": 1, "currency": "EUR", "period_months": 1, "next_due": day(5)},
		"amount":   {"name": "x", "amount": -1, "currency": "EUR", "period_months": 1, "next_due": day(5)},
		"currency": {"name": "x", "amount": 1, "currency": "euro", "period_months": 1, "next_due": day(5)},
		"period":   {"name": "x", "amount": 1, "currency": "EUR", "period_months": 0, "next_due": day(5)},
		"date":     {"name": "x", "amount": 1, "currency": "EUR", "period_months": 1, "next_due": "20.11.2026"},
	} {
		if st, _ := w.owner.do("POST", "/api/v1/billing", bad); st != 422 {
			t.Errorf("%s was accepted: %d", name, st)
		}
	}
	st, b := w.owner.do("POST", "/api/v1/billing", body)
	if st != 201 {
		t.Fatalf("%d %s", st, b)
	}
	created := parse[struct {
		ID       string `json:"id"`
		Currency string `json:"currency"`
		NextDue  string `json:"next_due"`
	}](t, b)
	if created.Currency != "EUR" || created.NextDue != day(2) {
		t.Fatalf("%+v", created)
	}
	yearly := map[string]any{"name": "domain", "amount": 12, "currency": "EUR", "period_months": 12, "next_due": day(200)}
	if st, _ := w.owner.do("POST", "/api/v1/billing", yearly); st != 201 {
		t.Fatal(st)
	}
	_, lb := w.owner.get("/api/v1/billing")
	if !strings.Contains(string(lb), `"EUR":6.5`) {
		t.Fatalf("5.5 a month and 12 a year make 6.5 a month: %s", lb)
	}

	// Due in two days: the alert is open, says what is due, and is the owner's.
	if _, _, err := alerts.Evaluate(ctx, w.h.st, now); err != nil {
		t.Fatal(err)
	}
	_, ab := w.owner.get("/api/v1/alerts")
	if !strings.Contains(string(ab), "bill_due") || !strings.Contains(string(ab), "exit-2 VPS") || strings.Contains(string(ab), "domain") {
		t.Fatalf("%s", ab)
	}

	// Paying moves the date on by a period from the date that was due, and the alert closes.
	st, pb := w.owner.do("POST", "/api/v1/billing/"+created.ID+"/paid", nil)
	want := now.AddDate(0, 0, 2).AddDate(0, 1, 0).Format("2006-01-02")
	if st != 200 || !strings.Contains(string(pb), want) {
		t.Fatalf("%d %s, want next due %s", st, pb, want)
	}
	if _, _, err := alerts.Evaluate(ctx, w.h.st, now); err != nil {
		t.Fatal(err)
	}
	_, ab = w.owner.get("/api/v1/alerts")
	if strings.Contains(string(ab), `"resolved_at":null`) && strings.Contains(string(ab), "exit-2 VPS") {
		t.Fatalf("a paid bill still raises an alert: %s", ab)
	}

	// Editing and removing.
	body["amount"] = 6
	if st, eb := w.owner.do("PUT", "/api/v1/billing/"+created.ID, body); st != 200 || !strings.Contains(string(eb), `"amount":6`) {
		t.Fatalf("%d %s", st, eb)
	}
	if st, _ := w.owner.do("DELETE", "/api/v1/billing/"+created.ID, nil); st != 204 {
		t.Fatal(st)
	}
	if st, _ := w.owner.do("DELETE", "/api/v1/billing/"+created.ID, nil); st != 404 {
		t.Fatalf("a removed payment: %d", st)
	}
}
