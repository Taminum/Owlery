package httpapi

import (
	"context"
	"testing"

	"github.com/Taminum/RemnaScope/internal/store"
)

type serverResp struct {
	store.VPS
	CanEdit  bool          `json:"can_edit"`
	Status   string        `json:"status"`
	Reason   string        `json:"reason"`
	Open     int           `json:"alerts_open"`
	Critical int           `json:"alerts_critical"`
	Alerts   []store.Alert `json:"alerts"`
}

func TestServerInventoryAndCard(t *testing.T) {
	w := newAgentWorld(t)
	st, b := w.owner.do("POST", "/api/v1/security/vps", map[string]any{"name": "exit-9", "addresses": []string{"203.0.113.9"}})
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	v := parse[vpsResp](t, b)

	// The inventory is replaced as a whole and tidied: duplicate roles and tags go, text is trimmed.
	inv := map[string]any{"roles": []string{"exit", "service", "exit"}, "os": " Ubuntu 24.04 ", "provider": "Aeza", "country": "Нидерланды",
		"city": "Амстердам", "group": "VPN", "tags": []string{"nl", "nl", "main"}, "purchased_on": "2026-03-01"}
	st, b = w.owner.do("PATCH", "/api/v1/security/vps/"+v.ID, map[string]any{"inventory": inv})
	if st != 200 {
		t.Fatalf("patch: %d %s", st, b)
	}
	got := parse[vpsResp](t, b)
	if len(got.Roles) != 2 || got.OS != "Ubuntu 24.04" || got.Group != "VPN" || len(got.Tags) != 2 || got.PurchasedOn == nil || got.PurchasedOn.Format("2006-01-02") != "2026-03-01" {
		t.Fatalf("inventory: %+v", got.Inventory)
	}
	for name, bad := range map[string]map[string]any{
		"role": {"roles": []string{"toaster"}}, "date": {"purchased_on": "01.03.2026"}, "long": {"os": string(make([]byte, 81))},
	} {
		if st, _ := w.owner.do("PATCH", "/api/v1/security/vps/"+v.ID, map[string]any{"inventory": bad}); st != 422 {
			t.Errorf("%s: %d", name, st)
		}
	}

	// Without an agent the machine is "unknown", not "ok".
	_, b = w.owner.get("/api/v1/servers")
	list := parse[struct {
		Servers []serverResp `json:"servers"`
		Roles   []string     `json:"roles"`
	}](t, b)
	if len(list.Servers) != 1 || list.Servers[0].Status != "unknown" || list.Servers[0].Reason != "no_agent" || len(list.Roles) != len(store.ServerRoles) {
		t.Fatalf("list: %s", b)
	}

	// An alert about the machine (here a full disk) is counted on the list and shown on the card; a critical one too.
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO alerts (kind, subject, label, opened_at) VALUES ('host_disk', $1 || ':/', 'Диск', now())`,
		`INSERT INTO alerts (kind, subject, label, opened_at) VALUES ('host_flood', $1, 'DDoS', now())`,
		`INSERT INTO alerts (kind, subject, label, opened_at, resolved_at) VALUES ('host_cpu', $1, 'CPU', now() - interval '2 days', now() - interval '1 day')`,
		`INSERT INTO alerts (kind, subject, label, opened_at) VALUES ('host_cpu', 'someone-else-' || $1, 'CPU', now())`,
	} {
		if _, err := w.h.st.Pool().Exec(ctx, q, v.ID); err != nil {
			t.Fatal(err)
		}
	}
	st, b = w.owner.get("/api/v1/servers/" + v.ID)
	if st != 200 {
		t.Fatalf("card: %d %s", st, b)
	}
	card := parse[serverResp](t, b)
	if card.Open != 2 || card.Critical != 1 || len(card.Alerts) != 3 {
		t.Fatalf("card alerts: open %d critical %d, %d alerts", card.Open, card.Critical, len(card.Alerts))
	}

	// The card of a server is as private as the server.
	if st, _ := w.adm.get("/api/v1/servers/" + v.ID); st != 404 {
		t.Errorf("another admin sees the card: %d", st)
	}
}
