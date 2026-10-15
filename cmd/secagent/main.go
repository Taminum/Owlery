// Command secagent reports a VPS's security state (Fail2ban, listening sockets, firewall rules) to
// RemnaScope. It only reads, listens on nothing, and runs no command the server sends.
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

	"github.com/Taminum/RemnaScope/internal/secagent"
)

var version = "dev"

func main() {
	var (
		server    = flag.String("server", "", "wss:// URL of RemnaScope")
		tokenFile = flag.String("token-file", "", "file holding the agent credential (<agent id>.<secret>)")
		caFile    = flag.String("ca-file", "", "optional PEM bundle to trust in addition to the system roots")
		insecure  = flag.Bool("insecure-ws", false, "allow ws:// (local testing only)")
		interval  = flag.Duration("interval", 30*time.Second, "how often to read and report")
		noF2B     = flag.Bool("no-fail2ban", false, "do not read Fail2ban")
		noSock    = flag.Bool("no-sockets", false, "do not read listening sockets")
		noFW      = flag.Bool("no-firewall", false, "do not read the firewall")
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
		Interval: *interval, Version: version, Log: log, NoFail2ban: *noF2B, NoSockets: *noSock, NoFirewall: *noFW})
	if err != nil {
		fmt.Fprintln(os.Stderr, "secagent:", err)
		os.Exit(1)
	}
}
