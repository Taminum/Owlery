package secfw

import (
	"strings"
	"testing"
)

const nft = `table inet filter {
	set blocked {
		type ipv4_addr
		elements = { 203.0.113.9 }
	}
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		tcp dport 22 accept
	}
	chain forward {
		type filter hook forward priority filter - 1; policy accept;
	}
}
table ip nat {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "eth0" masquerade
	}
}`

func TestNftIsReadIntoTablesChainsAndRules(t *testing.T) {
	m := Parse("nft", nft)
	if len(m.Tables) != 2 || m.Rules != 3 {
		t.Fatalf("%+v", m)
	}
	f := m.Tables[0]
	if f.Family != "inet" || f.Name != "filter" || len(f.Chains) != 2 || len(f.Other) != 1 || f.Other[0] != "set blocked" {
		t.Fatalf("%+v", f)
	}
	in := f.Chains[0]
	if in.Name != "input" || in.Hook != "input" || in.Policy != "drop" || in.Type != "filter" || len(in.Rules) != 2 || in.Rules[1] != "tcp dport 22 accept" {
		t.Fatalf("%+v", in)
	}
	// "priority filter - 1" is more than one word and must not swallow the policy.
	if fw := f.Chains[1]; fw.Priority != "filter - 1" || fw.Policy != "accept" || len(fw.Rules) != 0 {
		t.Fatalf("%+v", fw)
	}
	if nat := m.Tables[1]; nat.Chains[0].Hook != "postrouting" || nat.Chains[0].Rules[0] != `oifname "eth0" masquerade` {
		t.Fatalf("%+v", nat)
	}
}

func TestIptablesSaveIsReadToo(t *testing.T) {
	text := "*filter\n:INPUT DROP\n:FORWARD ACCEPT\n:f2b-sshd -\n-A INPUT -p tcp --dport 22 -j f2b-sshd\n-A INPUT -i lo -j ACCEPT\n-A f2b-sshd -j RETURN\nCOMMIT\n*nat\n:POSTROUTING ACCEPT\n-A POSTROUTING -o eth0 -j MASQUERADE\nCOMMIT\n"
	m := Parse("iptables", text)
	if len(m.Tables) != 2 || m.Rules != 4 {
		t.Fatalf("%+v", m)
	}
	in := m.Tables[0].Chains[0]
	if in.Name != "INPUT" || in.Policy != "drop" || len(in.Rules) != 2 || !strings.HasPrefix(in.Rules[0], "-p tcp --dport 22") {
		t.Fatalf("%+v", in)
	}
	if user := m.Tables[0].Chains[2]; user.Name != "f2b-sshd" || user.Policy != "" || len(user.Rules) != 1 {
		t.Fatalf("a user chain has no policy: %+v", user)
	}
}

func TestSomethingItDoesNotUnderstandIsNotAnError(t *testing.T) {
	for _, in := range []string{"", "garbage\n}}}{{{\n", "table\n", "chain x {\n"} {
		if m := Parse("nft", in); m.Rules != 0 {
			t.Fatalf("%q: %+v", in, m)
		}
	}
}

func TestDiffShowsOnlyWhatChangedWithContext(t *testing.T) {
	a := "a\nb\nc\nd\ne\nf\ng\nh\ni\nj"
	b := "a\nb\nc\nd\ne\nF\ng\nh\ni\nj\nk"
	lines, added, removed, trunc := Diff(a, b, 1, 100)
	if trunc || added != 2 || removed != 1 {
		t.Fatalf("%+v %d %d", lines, added, removed)
	}
	var got []string
	for _, l := range lines {
		got = append(got, l.Op+l.Text)
	}
	want := " e|-f|+F| g|…| j|+k"
	if strings.Join(got, "|") != want && strings.Join(got, "|") != " e|-f|+F| g| i| j|+k" {
		t.Fatalf("%v", got)
	}
	if l, ad, rm, _ := Diff(a, a, 2, 100); l != nil || ad != 0 || rm != 0 {
		t.Fatalf("equal texts differ: %+v", l)
	}
}

func TestDiffIsBoundedAndHandlesEmptySides(t *testing.T) {
	var many []string
	for i := 0; i < 500; i++ {
		many = append(many, "rule "+strings.Repeat("x", i%7)+string(rune('a'+i%26)))
	}
	lines, added, _, trunc := Diff("", strings.Join(many, "\n"), 2, 50)
	if !trunc || len(lines) != 50 || added != 500 {
		t.Fatalf("%d %d %v", len(lines), added, trunc)
	}
	if _, _, rm, _ := Diff("x\ny", "", 2, 50); rm != 2 {
		t.Fatalf("%d", rm)
	}
}
