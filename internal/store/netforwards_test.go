package store_test

import (
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/netdev"
	"github.com/Taminum/Owlery/internal/store"
	"github.com/Taminum/Owlery/internal/store/storetest"
)

func TestANewOpenPortWaitsForTheOwnerButTheFirstListIsKnown(t *testing.T) {
	s := storetest.New(t)
	d, err := s.CreateNetDevice(ctx, "edge", "mikrotik", []byte("h"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	fw := func(port, to string) netdev.NatRule {
		return netdev.NatRule{Chain: "dstnat", Action: "dst-nat", DstPort: port, ToAddr: to, ToPorts: port}
	}
	masq := netdev.NatRule{Chain: "srcnat", Action: "masquerade"}
	save := func(at time.Time, rules ...netdev.NatRule) {
		t.Helper()
		if err := s.SaveNetReport(ctx, d.ID, netdev.Report{HasStats: true, ResetNat: true, Nat: rules}, at); err != nil {
			t.Fatal(err)
		}
	}
	news := func(at time.Time) int {
		t.Helper()
		ds, err := s.ListNetDevices(ctx, at)
		if err != nil || len(ds) != 1 {
			t.Fatal(err, ds)
		}
		return len(ds[0].NewForwards)
	}
	save(now, masq, fw("8080", "192.168.1.5"))
	if n := news(now); n != 0 {
		t.Fatalf("the first list is what the owner already has: %d", n)
	}
	later := now.Add(10 * time.Minute)
	save(later, masq, fw("8080", "192.168.1.5"), fw("3389", "192.168.1.9"))
	ds, _ := s.ListNetDevices(ctx, later)
	if len(ds[0].NewForwards) != 1 || ds[0].NewForwards[0].DstPort != "3389" {
		t.Fatalf("only the added port is new (and a masquerade rule never is): %+v", ds[0].NewForwards)
	}
	if err := s.ConfirmForwards(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if n := news(later); n != 0 {
		t.Fatalf("confirmed: %d", n)
	}
	gone := later.Add(time.Minute)
	save(gone, masq, fw("8080", "192.168.1.5"), fw("3389", "192.168.1.9"))
	if n := news(gone); n != 0 {
		t.Fatalf("a confirmed port stays known: %d", n)
	}
	if err := s.ConfirmForwards(ctx, "00000000-0000-0000-0000-000000000000"); err != store.ErrNotFound {
		t.Fatalf("unknown router: %v", err)
	}
}
