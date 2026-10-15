package seccollect

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/Taminum/RemnaScope/internal/secproto"
)

const f2bStatus = `Status
|- Number of jail:	2
` + "`" + `- Jail list:	sshd, nginx-http-auth
`

const f2bSshd = `Status for the jail: sshd
|- Filter
|  |- Currently failed:	3
|  |- Total failed:	120
|  ` + "`" + `- File list:	/var/log/auth.log
` + "`" + `- Actions
   |- Currently banned:	2
   |- Total banned:	17
   ` + "`" + `- Banned IP list:	203.0.113.5 2001:db8::7
`

const f2bNginx = `Status for the jail: nginx-http-auth
|- Filter
|  |- Currently failed:	0
|  |- Total failed:	0
|  ` + "`" + `- File list:	/var/log/nginx/error.log
` + "`" + `- Actions
   |- Currently banned:	0
   |- Total banned:	0
   ` + "`" + `- Banned IP list:
`

type fake map[string]Result

func (f fake) Run(_ context.Context, name string, args ...string) Result {
	if r, ok := f[name+" "+strings.Join(args, " ")]; ok {
		return r
	}
	return Result{Err: exec.ErrNotFound}
}

func TestParseFail2banOutput(t *testing.T) {
	names, ok := ParseJailList(f2bStatus)
	if !ok || len(names) != 2 || names[1] != "nginx-http-auth" {
		t.Fatalf("%v %v", names, ok)
	}
	j, ok := ParseJailStatus("sshd", f2bSshd)
	if !ok || j.CurrentlyFailed != 3 || j.TotalFailed != 120 || j.CurrentlyBanned != 2 || j.TotalBanned != 17 || len(j.BannedIPs) != 2 || j.BannedIPs[1] != "2001:db8::7" {
		t.Fatalf("%+v %v", j, ok)
	}
	if e, ok := ParseJailStatus("x", f2bNginx); !ok || len(e.BannedIPs) != 0 {
		t.Fatalf("empty jail: %+v %v", e, ok)
	}
	if _, ok := ParseJailStatus("x", "garbage"); ok {
		t.Fatal("garbage parsed as a jail")
	}
}

func TestFail2banStates(t *testing.T) {
	ctx := context.Background()
	cases := map[string]struct {
		r    fake
		want string
	}{
		"not installed": {fake{}, secproto.StatusNotInstalled},
		"denied":        {fake{"f2b status": {Stderr: "ERROR  Permission denied to socket: /var/run/fail2ban/fail2ban.sock", ExitCode: 255}}, secproto.StatusPermissionDenied},
		"stopped":       {fake{"f2b status": {Stderr: "ERROR  Failed to access socket path: /var/run/fail2ban/fail2ban.sock. Is fail2ban running?", ExitCode: 255}}, secproto.StatusStopped},
		"garbage":       {fake{"f2b status": {Stdout: "hello"}}, secproto.StatusError},
		"one jail unreadable": {fake{"f2b status": {Stdout: f2bStatus}, "f2b status sshd": {Stdout: f2bSshd},
			"f2b status nginx-http-auth": {ExitCode: 1}}, secproto.StatusError},
		"ok": {fake{"f2b status": {Stdout: f2bStatus}, "f2b status sshd": {Stdout: f2bSshd}, "f2b status nginx-http-auth": {Stdout: f2bNginx}}, secproto.StatusOK},
	}
	for name, c := range cases {
		got := Fail2ban(ctx, c.r, "f2b")
		if got.Status != c.want {
			t.Errorf("%s: %s want %s", name, got.Status, c.want)
		}
		if (got.Status == secproto.StatusOK) != (got.Data != nil) {
			t.Errorf("%s: data %v with status %s", name, got.Data, got.Status)
		}
	}
	if d := Fail2ban(ctx, cases["ok"].r, "f2b").Data.(secproto.Fail2ban); len(d.Jails) != 2 || d.Jails[0].BannedIPs[0] != "203.0.113.5" {
		t.Fatalf("%+v", d)
	}
}

func TestFail2banNeverPassesAnOddJailNameToTheCommand(t *testing.T) {
	var asked []string
	r := recorder(func(args string) Result {
		asked = append(asked, args)
		if args == "status" {
			return Result{Stdout: "|- Number of jail:\t2\n`- Jail list:\t--help, ok-jail; rm\n"}
		}
		return Result{Stdout: f2bNginx}
	})
	Fail2ban(context.Background(), r, "f2b")
	for _, a := range asked {
		if strings.Contains(a, "--help") || strings.Contains(a, ";") {
			t.Fatalf("an unvalidated jail name reached the command: %q", a)
		}
	}
}

type recorder func(args string) Result

func (f recorder) Run(_ context.Context, _ string, args ...string) Result {
	return f(strings.Join(args, " "))
}

const ssOut = `tcp   LISTEN 0 4096   0.0.0.0:22          0.0.0.0:*    users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0 4096      [::]:22             [::]:*    users:(("sshd",pid=812,fd=4))
tcp   LISTEN 0 4096 127.0.0.54:53          0.0.0.0:*
udp   UNCONN 0 0   127.0.0.53%lo:53       0.0.0.0:*    users:(("systemd-resolve",pid=500,fd=13))
udp   UNCONN 0 0         [::]:51820          [::]:*
tcp   LISTEN 0 511          *:8443              *:*
`

func TestParseSS(t *testing.T) {
	s := ParseSS(ssOut)
	if len(s.Listeners) != 6 || !s.ProcessInfo {
		t.Fatalf("%+v", s)
	}
	by := map[string]secproto.Listener{}
	for _, l := range s.Listeners {
		by[l.Proto+"/"+l.Addr+"/"+strings.TrimSpace(string(rune('0'+l.Port%10)))] = l
	}
	first, v6, lo, wild := s.Listeners[0], s.Listeners[1], s.Listeners[3], s.Listeners[5]
	if first.Addr != "0.0.0.0" || first.Port != 22 || first.Process != "sshd" || first.PID != 812 {
		t.Errorf("%+v", first)
	}
	if v6.Addr != "::" || v6.Proto != "tcp" {
		t.Errorf("%+v", v6)
	}
	if lo.Addr != "127.0.0.53" || lo.Process != "systemd-resolve" {
		t.Errorf("an interface suffix must not stay in the address: %+v", lo)
	}
	if wild.Addr != "0.0.0.0" || wild.Port != 8443 {
		t.Errorf("%+v", wild)
	}
	if s.Listeners[2].Process != "" || s.Listeners[4].Process != "" {
		t.Error("a listener without process info must not invent one")
	}
}

func TestSocketsWithoutProcessNames(t *testing.T) {
	r := fake{"ss -H -tulnp": {Stdout: "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n"}}
	s := Sockets(context.Background(), r, "ss")
	if s.Status != secproto.StatusOK || s.Data.(secproto.Sockets).ProcessInfo {
		t.Fatalf("%+v", s)
	}
	if got := Sockets(context.Background(), fake{}, "ss"); got.Status != secproto.StatusUnsupported {
		t.Fatalf("%+v", got)
	}
}

func TestFirewallCanonicalFormIgnoresCountersAndTimestamps(t *testing.T) {
	a := CanonicalNft("table inet filter {\n\tchain input {\n\t\ttcp dport 22 counter packets 5 bytes 300 accept # handle 4\n\t}\n}\n")
	b := CanonicalNft("table inet filter {\n\tchain input {\n\t\ttcp dport 22 counter packets 9000 bytes 1 accept # handle 4\n\t}\n}\n")
	if a != b || !strings.Contains(a, "tcp dport 22 counter accept") {
		t.Fatalf("%q\n%q", a, b)
	}
	c := CanonicalNft("table inet filter {\n\tchain input {\n\t\ttcp dport 23 counter packets 5 bytes 300 accept # handle 4\n\t}\n}\n")
	if a == c {
		t.Fatal("a different rule must differ")
	}
	x := CanonicalIptables("# Generated by iptables-save v1.8 on Thu Oct 15 17:00:00 2026\n*filter\n:INPUT ACCEPT [10:200]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n# Completed on Thu Oct 15 17:00:00 2026\n")
	y := CanonicalIptables("# Generated by iptables-save v1.8 on Thu Oct 15 17:05:00 2026\n*filter\n:INPUT ACCEPT [99:1]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n# Completed on Thu Oct 15 17:05:00 2026\n")
	if x != y {
		t.Fatalf("%q\n%q", x, y)
	}
}

func TestFirewallBackendsAndHonestFailures(t *testing.T) {
	ctx := context.Background()
	nft := "table inet filter {\n}\ntable ip nat {\n\tchain p {\n\t}\n}\n"
	if s := Firewall(ctx, fake{"nft list ruleset": {Stdout: nft}}, "nft", "iptables-save"); s.Status != secproto.StatusOK || s.Data.(secproto.Firewall).Backend != "nft" {
		t.Errorf("%+v", s)
	}
	if s := Firewall(ctx, fake{"iptables-save ": {Stdout: "*filter\nCOMMIT\n"}}, "nft", "iptables-save"); s.Status != secproto.StatusOK || s.Data.(secproto.Firewall).Backend != "iptables" {
		t.Errorf("%+v", s)
	}
	if s := Firewall(ctx, fake{}, "nft", "iptables-save"); s.Status != secproto.StatusNotInstalled {
		t.Errorf("%+v", s)
	}
	denied := Result{Stderr: "Operation not permitted (you must be root)", ExitCode: 1}
	if s := Firewall(ctx, fake{"nft list ruleset": denied, "iptables-save ": denied}, "nft", "iptables-save"); s.Status != secproto.StatusPermissionDenied {
		t.Errorf("%+v", s)
	}
	// An empty nftables ruleset is a real answer, not a failure.
	if s := Firewall(ctx, fake{"nft list ruleset": {Stdout: ""}}, "nft", "iptables-save"); s.Status != secproto.StatusOK {
		t.Errorf("%+v", s)
	}
}
