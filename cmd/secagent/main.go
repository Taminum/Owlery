// Command secagent reports a VPS's security state (Fail2ban, listening sockets, firewall rules) to
// RemnaScope, and, when the host sets it up, carries out a ban or unban of one address that an owner
// asked for. It listens on nothing and runs no other command the server sends.
//
//	secagent -server wss://scope.example.com -token-file /etc/remnascope/secagent.token
//	secagent helper -socket /run/remnascope-sec/f2b.sock       (the Fail2ban helper, a separate service)
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Taminum/RemnaScope/internal/f2bhelper"
	"github.com/Taminum/RemnaScope/internal/secagent"
	"github.com/Taminum/RemnaScope/internal/seccollect"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "helper" {
		runHelper(os.Args[2:])
		return
	}
	var (
		server    = flag.String("server", "", "wss:// URL of RemnaScope")
		tokenFile = flag.String("token-file", "", "file holding the agent credential (<agent id>.<secret>)")
		caFile    = flag.String("ca-file", "", "optional PEM bundle to trust in addition to the system roots")
		insecure  = flag.Bool("insecure-ws", false, "allow ws:// (local testing only)")
		interval  = flag.Duration("interval", 30*time.Second, "how often to read and report")
		helper    = flag.String("helper-socket", "", "Unix socket of the Fail2ban helper: Fail2ban is read through it, and ban/unban become possible with -state-dir")
		stateDir  = flag.String("state-dir", "", "directory that remembers which commands were carried out (needed for ban/unban)")
		noF2B     = flag.Bool("no-fail2ban", false, "do not read Fail2ban")
		noSock    = flag.Bool("no-sockets", false, "do not read listening sockets")
		noFW      = flag.Bool("no-firewall", false, "do not read the firewall")
		noHost    = flag.Bool("no-host", false, "do not report CPU, memory, disk and network use")
		probe     = flag.Bool("probe", false, "act as a checker: let the server ask this host to connect to a public TCP port or read a TLS certificate")
		showVer   = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()
	if *showVer {
		fmt.Println(version)
		return
	}
	if *server == "" || *tokenFile == "" {
		fmt.Fprintln(os.Stderr, "secagent: -server and -token-file are required")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	err := secagent.Run(ctx, secagent.Config{ServerURL: *server, TokenFile: *tokenFile, CAFile: *caFile, AllowInsecure: *insecure,
		Interval: *interval, Version: version, Log: log, HelperSocket: *helper, StateDir: *stateDir, NoFail2ban: *noF2B, NoSockets: *noSock, NoFirewall: *noFW, NoHost: *noHost, Probe: *probe})
	if err != nil {
		fmt.Fprintln(os.Stderr, "secagent:", err)
		os.Exit(1)
	}
}

// runHelper serves the Fail2ban helper: the only process that touches Fail2ban's socket.
func runHelper(args []string) {
	fs := flag.NewFlagSet("helper", flag.ExitOnError)
	socket := fs.String("socket", "", "Unix socket to listen on (its directory should be a systemd RuntimeDirectory)")
	bin := fs.String("fail2ban-client", "fail2ban-client", "the fail2ban-client to run")
	_ = fs.Parse(args)
	if *socket == "" {
		fmt.Fprintln(os.Stderr, "secagent helper: -socket is required")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	l, err := f2bhelper.Listen(*socket, 0o660)
	if err != nil {
		fmt.Fprintln(os.Stderr, "secagent helper:", err)
		os.Exit(1)
	}
	s := &f2bhelper.Server{Runner: seccollect.ExecRunner{}, Bin: *bin}
	if err := s.Serve(ctx, l); err != nil {
		fmt.Fprintln(os.Stderr, "secagent helper:", err)
		os.Exit(1)
	}
}
