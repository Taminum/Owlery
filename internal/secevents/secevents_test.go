package secevents

import (
	"testing"

	"github.com/Taminum/RemnaScope/internal/secproto"
)

func f2b(status string, jails ...secproto.Jail) Snap {
	return Snap{Status: status, F2B: &secproto.Fail2ban{Jails: jails}}
}

func types(es []Event) map[string]int {
	m := map[string]int{}
	for _, e := range es {
		m[e.Type]++
	}
	return m
}

func TestFail2banBanUnbanAndJails(t *testing.T) {
	prev := f2b("ok", secproto.Jail{Name: "sshd", BannedIPs: []string{"1.1.1.1", "2.2.2.2"}}, secproto.Jail{Name: "old"})
	cur := f2b("ok", secproto.Jail{Name: "sshd", BannedIPs: []string{"2.2.2.2", "3.3.3.3"}}, secproto.Jail{Name: "new", BannedIPs: []string{"9.9.9.9"}})
	got := types(Diff(secproto.CatFail2ban, prev, cur))
	want := map[string]int{"fail2ban.ban": 1, "fail2ban.unban": 1, "fail2ban.jail_changed": 2}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %d want %d (%v)", k, got[k], v, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected: %v", got)
	}
}

func TestFail2banFailedReadIsNotMassUnban(t *testing.T) {
	prev := f2b("ok", secproto.Jail{Name: "sshd", BannedIPs: []string{"1.1.1.1"}})
	cur := Snap{Status: "permission_denied"}
	got := types(Diff(secproto.CatFail2ban, prev, cur))
	if got["fail2ban.unban"] != 0 || got["fail2ban.state_changed"] != 1 {
		t.Fatalf("%v", got)
	}
	// And the recovery must not replay every ban as new.
	back := types(Diff(secproto.CatFail2ban, cur, prev))
	if back["fail2ban.ban"] != 0 || back["fail2ban.state_changed"] != 1 {
		t.Fatalf("%v", back)
	}
}

func TestSocketsAddRemoveAndBindChange(t *testing.T) {
	l := func(addr string, port int) secproto.Listener {
		return secproto.Listener{Proto: "tcp", Addr: addr, Port: port}
	}
	prev := Snap{Status: "ok", Sock: &secproto.Sockets{Listeners: []secproto.Listener{l("0.0.0.0", 22), l("127.0.0.1", 5432), l("0.0.0.0", 8080)}}}
	cur := Snap{Status: "ok", Sock: &secproto.Sockets{Listeners: []secproto.Listener{l("0.0.0.0", 22), l("0.0.0.0", 5432), l("0.0.0.0", 9000)}}}
	got := types(Diff(secproto.CatSockets, prev, cur))
	if got["port.local_bind_changed"] != 1 || got["port.local_added"] != 1 || got["port.local_removed"] != 1 || len(got) != 3 {
		t.Fatalf("%v", got)
	}
}

func TestFirewallChangeOnlyWhenBothCompleteAndHashDiffers(t *testing.T) {
	a := Snap{Status: "ok", Hash: "a", FW: &secproto.Firewall{Backend: "nft"}}
	b := Snap{Status: "ok", Hash: "b", FW: &secproto.Firewall{Backend: "nft"}}
	if got := Diff(secproto.CatFirewall, a, b); len(got) != 1 || got[0].Severity != SevWarning {
		t.Fatalf("%+v", got)
	}
	if got := Diff(secproto.CatFirewall, a, a); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
	if got := Diff(secproto.CatFirewall, a, Snap{Status: "permission_denied"}); len(got) != 1 || got[0].Type != "firewall.state_changed" {
		t.Fatalf("%+v", got)
	}
}
