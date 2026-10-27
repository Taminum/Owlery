package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Taminum/RemnaScope/internal/alerts"
	"github.com/Taminum/RemnaScope/internal/asn"
	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/autoclassify"
	"github.com/Taminum/RemnaScope/internal/awglimits"
	"github.com/Taminum/RemnaScope/internal/awgops"
	"github.com/Taminum/RemnaScope/internal/config"
	"github.com/Taminum/RemnaScope/internal/demo"
	"github.com/Taminum/RemnaScope/internal/dnsworker"
	"github.com/Taminum/RemnaScope/internal/gemini"
	"github.com/Taminum/RemnaScope/internal/geoip"
	"github.com/Taminum/RemnaScope/internal/httpapi"
	"github.com/Taminum/RemnaScope/internal/ingest"
	"github.com/Taminum/RemnaScope/internal/keyrotate"
	"github.com/Taminum/RemnaScope/internal/live"
	"github.com/Taminum/RemnaScope/internal/netintel"
	"github.com/Taminum/RemnaScope/internal/notify"
	"github.com/Taminum/RemnaScope/internal/probe"
	"github.com/Taminum/RemnaScope/internal/remnawave"
	"github.com/Taminum/RemnaScope/internal/safehttp"
	"github.com/Taminum/RemnaScope/internal/secchecks"
	"github.com/Taminum/RemnaScope/internal/secingest"
	"github.com/Taminum/RemnaScope/internal/secops"
	"github.com/Taminum/RemnaScope/internal/secrets"
	"github.com/Taminum/RemnaScope/internal/store"
	"github.com/Taminum/RemnaScope/internal/syncer"
	"github.com/Taminum/RemnaScope/migrations"
)

const usage = `usage: api [serve]
       api create-owner -username NAME (-password-file FILE | -generate-to FILE)
       api rotate-keys
       api gen-key [-version N]`

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(log)
	case "create-owner":
		err = createOwner(args)
	case "rotate-keys":
		err = rotateKeys()
	case "gen-key":
		err = genKey(args)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Error(cmd+" failed", "err", err)
		os.Exit(1)
	}
}

func connect(ctx context.Context, c config.Config) (*pgxpool.Pool, *store.Store, error) {
	pool, err := pgxpool.New(ctx, c.DatabaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("database config: %w", err)
	}
	if err := store.Migrate(ctx, pool, migrations.FS); err != nil {
		pool.Close()
		return nil, nil, err
	}
	return pool, store.New(pool), nil
}

func serve(log *slog.Logger) error {
	c, err := config.FromEnv()
	if err != nil {
		return err
	}
	if err := c.Require(); err != nil {
		return err
	}
	ring, err := secrets.LoadKeyringFile(c.MasterKeyFile, c.ActiveKeyVersion)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, st, err := connect(ctx, c)
	if err != nil {
		return err
	}
	defer pool.Close()

	if c.SeedDemo {
		if err := demo.Seed(ctx, st); err != nil {
			return fmt.Errorf("seed demo: %w", err)
		}
		log.Warn("demo panels are enabled: synthetic data only; do not use SEED_DEMO in production")
	}
	if err := bootstrapOwner(ctx, st, c, log); err != nil {
		return err
	}

	policy := safehttp.Policy{AllowedPorts: c.AllowedPorts, AllowedPrivateHosts: c.AllowPrivateHosts}
	if c.TrustedCAFile != "" {
		pem, err := os.ReadFile(c.TrustedCAFile)
		if err != nil {
			return fmt.Errorf("TRUSTED_CA_FILE: %w", err)
		}
		if err := safehttp.ValidateCAPEM(pem); err != nil {
			return fmt.Errorf("TRUSTED_CA_FILE: %w", err)
		}
		policy.ExtraCAPEM = pem
	}

	sy := syncer.New(st, ring,
		func(p store.Panel, token string, g remnawave.Getter) (remnawave.PanelAdapter, error) {
			return remnawave.NewV3(p.BaseURL, token, g), nil
		},
		func(p store.Panel) remnawave.Getter { return safehttp.New(policy, p.UseCustomCA) },
		syncer.DefaultConfig(), log)

	srv := &httpapi.Server{Store: st, Ring: ring, Probe: httpapi.NewProbeFactory(policy), Sync: sy, Log: log,
		CookieSecure: c.CookieSecure, Trusted: c.TrustedProxies, CustomCA: len(policy.ExtraCAPEM) > 0,
		SessionTTL: c.SessionTTL, IdleTTL: c.IdleTTL}

	srv.Live = live.New()
	srv.Gemini = &gemini.Client{KeyFile: c.GeminiKeyFile}
	// Lookups for the owner go through their own client: https only, public addresses only, no
	// private hosts approved (unlike the panels' client).
	srv.Intel = &netintel.Tool{Fetch: safehttp.New(safehttp.Policy{Timeout: 25 * time.Second, MaxBody: 16 << 20}, false), ASN: asn.Default(), Geo: geoip.Default()}
	srv.Auto = &autoclassify.Runner{Store: st, Client: srv.Gemini, Log: log}
	_ = st.FailStaleDryRuns(ctx)
	go (&autoclassify.Worker{R: srv.Auto}).Run(ctx)
	srv.AWGOps = awgops.New()
	go func() { // the hourly sums of where AmneziaWG devices connect to are kept for 30 days
		for {
			if n, err := st.PruneAWGFlows(ctx, 30*24*time.Hour); err != nil {
				log.Error("pruning awg flows", "err", err)
			} else if n > 0 {
				log.Info("pruned old awg flow sums", "rows", n)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(6 * time.Hour):
			}
		}
	}()
	secChecker := secchecks.New(st, log)
	dnsWorker := dnsworker.New(st, log, srv.Intel)
	srv.DNSWorker = dnsWorker
	secHub := secops.New()
	srv.SecOps = secHub
	secChecker.Probes = secHub // a security agent set up as a checker can run the external checks
	srv.SecChecks = secChecker
	srv.SecIngest = (&secingest.Server{Store: st, Log: log, Limiter: auth.NewLimiter(1, 10), ClientIP: srv.ClientAddr, Ops: secHub}).Handler()
	srv.Ingest = (&ingest.Server{Store: st, Log: log, Limiter: auth.NewLimiter(1, 10), ClientIP: srv.ClientAddr, Live: srv.Live, Ops: srv.AWGOps}).Handler()

	hs := &http.Server{
		Addr:              c.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      90 * time.Second, // a connection test can take up to a minute
		IdleTimeout:       60 * time.Second,
	}

	if c.SyncEnabled {
		go sy.Run(ctx)
		srv.Pulse = syncer.NewPulse()
		go sy.RunPulse(ctx, srv.Pulse, 15*time.Second)
	}
	go alerts.Run(ctx, st, time.Minute, log)
	go srv.WarmAnalytics(ctx)
	go secChecker.Run(ctx)
	go (&notify.Worker{Store: st, Ring: ring, Log: log}).Run(ctx)
	go (&notify.Bot{Store: st, Ring: ring, Log: log}).Run(ctx)
	go (&awglimits.Worker{Store: st, Ops: srv.AWGOps, Log: log}).Run(ctx)
	go dnsWorker.Run(ctx)
	go probe.Run(ctx, st, time.Minute, log)
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = st.PurgeExpiredSessions(ctx)
				_ = st.PurgeExpiredMFAChallenges(ctx, time.Now().UTC())
				if n, err := st.PurgeExpiredEvents(ctx, time.Now().UTC()); err != nil {
					log.Error("retention purge failed", "err", err)
				} else if n > 0 {
					log.Info("retention purge", "events_deleted", n)
				}
				if n, err := st.PurgeExpiredTraffic(ctx, time.Now().UTC()); err != nil {
					log.Error("traffic retention purge failed", "err", err)
				} else if n > 0 {
					log.Info("retention purge", "traffic_samples_deleted", n)
				}
				if n, err := st.PurgeDNS(ctx, time.Now().UTC()); err != nil {
					log.Error("dns retention purge failed", "err", err)
				} else if n > 0 {
					log.Info("retention purge", "dns_rows_deleted", n)
				}
				if n, err := st.PurgeSecurity(ctx, time.Now().UTC()); err != nil {
					log.Error("security retention purge failed", "err", err)
				} else if n > 0 {
					log.Info("retention purge", "security_rows_deleted", n)
				}
				if n, err := st.PurgeExpiredDevices(ctx, time.Now().UTC()); err != nil {
					log.Error("device retention purge failed", "err", err)
				} else if n > 0 {
					log.Info("retention purge", "device_connections_deleted", n)
				}
			}
		}
	}()
	go func() { // rows from before the country column existed
		if n, err := st.BackfillCountries(ctx); err != nil {
			log.Error("country backfill failed", "err", err)
		} else if n > 0 {
			log.Info("country backfill", "rows", n)
		}
	}()
	go func() { // rows from before the site column existed
		if n, err := st.BackfillSites(ctx); err != nil {
			log.Error("site backfill failed", "err", err)
		} else if n > 0 {
			log.Info("site backfill", "rows", n)
		}
	}()
	go func() {
		log.Info("api listening", "addr", c.ListenAddr, "cookie_secure", c.CookieSecure, "sync", c.SyncEnabled, "demo", c.SeedDemo)
		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen", "err", err)
			stop()
		}
	}()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return hs.Shutdown(shutdown)
}

// bootstrapOwner creates the first owner from a password file, once, when no account exists.
func bootstrapOwner(ctx context.Context, st *store.Store, c config.Config, log *slog.Logger) error {
	if c.BootstrapOwner == "" {
		return nil
	}
	n, err := st.CountAccounts(ctx)
	if err != nil || n > 0 {
		return err
	}
	pw, err := os.ReadFile(c.BootstrapPassFile)
	if err != nil {
		return fmt.Errorf("BOOTSTRAP_PASSWORD_FILE: %w", err)
	}
	if err := createAccount(ctx, st, c.BootstrapOwner, strings.TrimSpace(string(pw))); err != nil {
		return err
	}
	log.Info("first owner created from bootstrap file", "username", c.BootstrapOwner)
	return nil
}

func createAccount(ctx context.Context, st *store.Store, username, password string) error {
	if err := auth.ValidatePassword(username, password); err != nil {
		return err
	}
	h, err := auth.HashPassword(password, auth.DefaultParams)
	if err != nil {
		return err
	}
	_, err = st.CreateAccount(ctx, username, h, true)
	return err
}

func createOwner(args []string) error {
	fs := flag.NewFlagSet("create-owner", flag.ContinueOnError)
	username := fs.String("username", "", "owner username")
	passFile := fs.String("password-file", "", "read the password from this file")
	genTo := fs.String("generate-to", "", "generate a random password and write it to this file (mode 0600)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" || (*passFile == "") == (*genTo == "") {
		return errors.New("pass -username and exactly one of -password-file or -generate-to")
	}
	c, err := config.FromEnv()
	if err != nil {
		return err
	}
	if c.DatabaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	var password string
	if *passFile != "" {
		b, err := os.ReadFile(*passFile)
		if err != nil {
			return err
		}
		password = strings.TrimSpace(string(b))
	} else {
		if password, err = auth.NewToken(); err != nil {
			return err
		}
		// Written to a file so it never appears in a terminal, a log or chat.
		if err := os.WriteFile(*genTo, []byte(password+"\n"), 0o600); err != nil {
			return err
		}
	}
	ctx := context.Background()
	pool, st, err := connect(ctx, c)
	if err != nil {
		return err
	}
	defer pool.Close()
	return createAccount(ctx, st, *username, password)
}

func rotateKeys() error {
	c, err := config.FromEnv()
	if err != nil {
		return err
	}
	if err := c.Require(); err != nil {
		return err
	}
	ring, err := secrets.LoadKeyringFile(c.MasterKeyFile, c.ActiveKeyVersion)
	if err != nil {
		return err
	}
	ctx := context.Background()
	pool, st, err := connect(ctx, c)
	if err != nil {
		return err
	}
	defer pool.Close()
	res, err := keyrotate.Run(ctx, st, ring)
	fmt.Printf("rotated=%d already_current=%d raced=%d active_key=v%d\n", res.Rotated, res.Current, res.Raced, ring.ActiveVersion())
	return err
}

func genKey(args []string) error {
	fs := flag.NewFlagSet("gen-key", flag.ContinueOnError)
	version := fs.Int("version", 1, "key version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	line, err := secrets.GenerateKeyLine(*version)
	if err != nil {
		return err
	}
	fmt.Println(line)
	return nil
}
