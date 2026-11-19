package store_test

import (
	"testing"

	"github.com/Taminum/Owlery/internal/store"
)

func TestNewRouterClientNotificationsAreIndependentOfSecurity(t *testing.T) {
	for _, tc := range []struct {
		group       string
		clientsOff  bool
		securityOff bool
	}{
		{"lan_clients", true, false},
		{"security", false, true},
	} {
		if !store.ValidAlertGroup(tc.group) {
			t.Fatalf("unknown group %q", tc.group)
		}
		prefs := store.NotifyPrefs{Off: []string{tc.group}}
		if got := prefs.GroupOff(store.AlertLANNew); got != tc.clientsOff {
			t.Errorf("%s off: new clients suppressed = %v", tc.group, got)
		}
		for _, kind := range []string{store.AlertSecAgent, store.AlertSecTLS, store.AlertSecPort, store.AlertNetForward} {
			if got := prefs.GroupOff(kind); got != tc.securityOff {
				t.Errorf("%s off: %s suppressed = %v", tc.group, kind, got)
			}
		}
	}
}
