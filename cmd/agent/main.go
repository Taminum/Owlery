// remnascope-agent reads an Xray access log and ships it to RemnaScope over WSS.
//
// It only reads. Typical use on a Remnawave node (the log lives inside the container):
//
//	remnascope-agent -server wss://scope.example.com/ingest/v1 -token-file /etc/remnascope/agent.token \
//	  -state-dir /var/lib/remnascope-agent -exec "/usr/bin/docker exec remnanode tail -n 0 -F /var/log/xray/current"
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Taminum/RemnaScope/internal/agent"
)

var version = "0.1.0"

func main() {
	var (
		server    = flag.String("server", "", "wss:// URL of the RemnaScope ingest endpoint")
		tokenFile = flag.String("token-file", "", "file holding the agent credential (<agent id>.<secret>)")
		caFile    = flag.String("ca-file", "", "optional PEM bundle to trust in addition to the system roots")
		insecure  = flag.Bool("insecure-ws", false, "allow ws:// (local testing only)")
		stateDir  = flag.String("state-dir", "", "directory for the spool and state (must be writable, private)")
		spoolMB   = flag.Int64("spool-max-mb", 256, "most disk the spool may use; beyond it lines are dropped and the gap is reported")
		file      = flag.String("file", "", "follow this log file")
		execCmd   = flag.String("exec", "", "run this command (no shell) and read the log from its output")
		clashURL  = flag.String("clash-url", "", "router mode: base URL of the sing-box Clash API, e.g. http://192.168.1.1:9090")
		leases    = flag.String("leases-file", "", "router mode: dnsmasq leases file, to name devices (e.g. /tmp/dhcp.leases)")
		awgExec   = flag.String("awg-exec", "", "AmneziaWG mode: the helper command that prints interface counters (run without a shell)")
		awgManage = flag.String("awg-manage", "", "AmneziaWG mode: the management helper command. Without it the server cannot add or revoke devices")
		awgSensor = flag.String("awg-sensor-socket", "", "AmneziaWG mode: Unix socket the traffic sensors report to (without it no sensor reports are accepted)")
		awgSensed = flag.String("awg-sensor-containers", "", "AmneziaWG mode: comma separated containers the sensor watches")
		awgEvery  = flag.Duration("awg-every", time.Minute, "AmneziaWG mode: how often to read the counters")
		fromStart = flag.Bool("from-start", false, "with -file and no saved position: read the existing content too")
		batch     = flag.Int("batch-lines", 500, "lines per batch")
		wait      = flag.Duration("batch-wait", 2*time.Second, "longest wait to fill a batch")
		sourceID  = flag.String("source-id", "", "label describing the log (default: the file or command)")
		showVer   = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()
	if *showVer {
		fmt.Println(version)
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	fail := func(msg string) {
		fmt.Fprintln(os.Stderr, "remnascope-agent:", msg)
		os.Exit(2)
	}
	if *server == "" || *tokenFile == "" || *stateDir == "" {
		fail("-server, -token-file and -state-dir are required")
	}
	n := 0
	for _, v := range []string{*file, *execCmd, *clashURL, *awgExec} {
		if v != "" {
			n++
		}
	}
	if n != 1 {
		fail("give exactly one of -file, -exec, -clash-url or -awg-exec")
	}
	cfg := agent.Config{ServerURL: *server, TokenFile: *tokenFile, CAFile: *caFile, AllowInsecure: *insecure, StateDir: *stateDir,
		SpoolMaxBytes: *spoolMB << 20, BatchLines: *batch, BatchWait: *wait, FromStart: *fromStart, Version: version, SourceID: *sourceID, Log: log}
	if *awgExec != "" {
		cfg.Kind, cfg.AWGArgv, cfg.AWGEvery = agent.SourceAWG, strings.Fields(*awgExec), *awgEvery
		if *awgManage == "" {
			*awgManage = os.Getenv("REMNASCOPE_AWG_MANAGE") // set by a systemd drop-in: removing it switches management off
		}
		cfg.AWGManage = strings.Fields(*awgManage)
		if *awgSensor == "" {
			*awgSensor = os.Getenv("REMNASCOPE_AWG_SENSOR_SOCKET")
		}
		if *awgSensed == "" {
			*awgSensed = os.Getenv("REMNASCOPE_AWG_SENSOR_CONTAINERS")
		}
		cfg.AWGSensorSock = strings.TrimSpace(*awgSensor)
		for _, c := range strings.Split(*awgSensed, ",") {
			if c = strings.TrimSpace(c); c != "" {
				cfg.AWGSensorOf = append(cfg.AWGSensorOf, c)
			}
		}
		if cfg.SourceID == "" {
			cfg.SourceID = "awg:" + strings.Join(cfg.AWGArgv[min(len(cfg.AWGArgv), 1):], " ")
		}
	} else if *clashURL != "" {
		cfg.Kind, cfg.ClashURL, cfg.LeasesFile = agent.SourceClash, *clashURL, *leases
		if cfg.SourceID == "" {
			cfg.SourceID = "clash:" + *clashURL
		}
	} else if *file != "" {
		cfg.Kind, cfg.Path = agent.SourceFile, *file
		if cfg.SourceID == "" {
			cfg.SourceID = "file:" + *file
		}
	} else {
		cfg.Kind, cfg.Argv = agent.SourceExec, strings.Fields(*execCmd)
		if cfg.SourceID == "" {
			cfg.SourceID = "exec:" + strings.Join(cfg.Argv[min(len(cfg.Argv), 1):], " ")
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("agent starting", "version", version, "source", cfg.SourceID)
	if err := agent.Run(ctx, cfg); err != nil {
		log.Error("agent stopped", "err", err)
		os.Exit(1)
	}
}
