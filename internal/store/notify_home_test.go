package store_test

import (
	"context"
	"testing"

	"github.com/Taminum/Owlery/internal/store"
)

func TestProxmoxAlertsHaveTheirOwnGroupAndANewChannelStartsWithItOff(t *testing.T) {
	e := newAgentEnv(t)
	ctx := context.Background()
	for _, k := range []string{store.AlertPVEGuest, store.AlertPVEDisk, store.AlertPVEBackup, store.AlertPVETailscale} {
		if g := store.AlertGroupOf(k); g != "home" {
			t.Fatalf("%s is in group %q", k, g)
		}
	}
	ch, err := e.s.CreateNotifyChannel(ctx, "Me", "hint", store.NotifySecret{Ciphertext: []byte("x"), Nonce: []byte("n"), KeyVersion: 1}, true, nil, "UTC")
	if err != nil {
		t.Fatal(err)
	}
	if !ch.Prefs.GroupOff(store.AlertPVEBackup) || !ch.Prefs.GroupOff(store.AlertPVEDisk) {
		t.Fatalf("the home group starts switched off: %+v", ch.Prefs)
	}
	if ch.Prefs.GroupOff(store.AlertHostDisk) || ch.Prefs.GroupOff(store.AlertPanelSync) {
		t.Fatalf("everything else is announced as before: %+v", ch.Prefs)
	}
}
