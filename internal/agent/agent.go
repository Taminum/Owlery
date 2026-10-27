package agent

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Taminum/Owlery/internal/ingestproto"
)

type SourceKind string

const (
	SourceFile  SourceKind = "file"
	SourceExec  SourceKind = "exec"
	SourceClash SourceKind = "clash" // router: sing-box Clash API
	SourceAWG   SourceKind = "awg"   // AmneziaWG host: counters through a fixed helper
)

type Config struct {
	ServerURL     string
	TokenFile     string
	CAFile        string
	AllowInsecure bool
	StateDir      string
	SpoolMaxBytes int64
	Kind          SourceKind
	Path          string   // file source
	Argv          []string // exec source
	ClashURL      string   // clash source: base URL of the router's Clash API
	LeasesFile    string   // clash source: dnsmasq leases, for device names
	AWGArgv       []string // awg source: the helper command
	AWGEvery      time.Duration
	AWGManage     []string // awg source: the management helper; empty = devices cannot be added or revoked
	AWGContainer  []string // awg source: the helper that creates and removes containers; empty = the host did not opt in
	AWGSensorSock string   // awg source: Unix socket the traffic sensors report to; empty = no sensor
	AWGSensorOf   []string // awg source: the containers whose reports are accepted
	AWGSensorConf string   // awg source: the helper configuration whose SENSE list is accepted as well
	FromStart     bool
	BatchLines    int
	BatchBytes    int
	BatchWait     time.Duration
	Poll          time.Duration
	Version       string
	SourceID      string
	Log           *slog.Logger
}

// emitter turns source output into spool records and counts what cannot be stored.
type emitter struct {
	spool    *Spool
	counters *Counters
	log      *slog.Logger
	mu       sync.Mutex
}

func (e *emitter) Line(s string) {
	if len(s) > ingestproto.MaxLineBytes {
		e.counters.Drop("line_too_long", 1)
		return
	}
	if _, err := e.spool.Append(s); err != nil {
		if errors.Is(err, ErrSpoolFull) {
			e.counters.Drop("spool_full", 1)
			return
		}
		e.counters.Drop("spool_error", 1)
		e.log.Error("spool write failed", "err", err)
	}
}

func (e *emitter) Gap(reason string) { e.counters.Drop(reason, 0) }

// Run starts the agent and blocks until ctx is cancelled or something unrecoverable happens.
func Run(ctx context.Context, cfg Config) error {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	if cfg.Kind == SourceAWG {
		return runAWG(ctx, cfg, log)
	}
	st, fresh, err := LoadState(cfg.StateDir)
	if err != nil {
		return err
	}
	spoolDir := filepath.Join(cfg.StateDir, "spool")
	if fresh { // numbering restarts with a new epoch, so anything left in an old spool must not be replayed under it
		_ = os.RemoveAll(spoolDir)
		log.Info("starting with a new epoch", "epoch", st.Epoch)
	}
	maxBytes := cfg.SpoolMaxBytes
	if maxBytes <= 0 {
		maxBytes = 256 << 20
	}
	spool, err := OpenSpool(spoolDir, maxBytes, st.NextSeq)
	if err != nil {
		return err
	}
	defer spool.Close()
	counters := &Counters{}
	if !fresh {
		counters.Load(st.PendingDropped, st.PendingGaps)
	}
	if fresh {
		if err := st.Save(cfg.StateDir); err != nil {
			return err
		}
	}

	var cpMu sync.Mutex
	pending := Checkpoint{Offset: st.Offset, HeadHash: st.HeadHash}
	checkpointed := pending
	saveState := func() {
		_ = spool.Sync() // the checkpoint may only get ahead of the spool once the spool is on disk
		cpMu.Lock()
		cp := pending
		cpMu.Unlock()
		st.NextSeq = spool.NextSeq()
		snap := counters.Snapshot()
		st.PendingDropped, st.PendingGaps = snap.dropped, snap.gaps
		if cfg.Kind == SourceFile {
			st.Path, st.Offset, st.HeadHash = cfg.Path, cp.Offset, cp.HeadHash
		}
		if err := st.Save(cfg.StateDir); err != nil {
			log.Error("saving state failed", "err", err)
			return
		}
		checkpointed = cp
	}

	ship := &Shipper{URL: cfg.ServerURL, TokenFile: cfg.TokenFile, CAFile: cfg.CAFile, AllowInsecure: cfg.AllowInsecure,
		Spool: spool, Counters: counters, Epoch: st.Epoch, SourceID: cfg.SourceID, Version: cfg.Version,
		BatchLines: cfg.BatchLines, BatchBytes: cfg.BatchBytes, BatchWait: cfg.BatchWait, Log: log}

	em := &emitter{spool: spool, counters: counters, log: log}
	var src interface {
		Run(context.Context, Emitter) error
	}
	switch cfg.Kind {
	case SourceFile:
		fs := &FileSource{Path: cfg.Path, Poll: cfg.Poll, FromStart: cfg.FromStart, OnProgress: func(c Checkpoint) {
			cpMu.Lock()
			pending = c
			cpMu.Unlock()
		}}
		if st.Path == cfg.Path && (st.Offset > 0 || st.HeadHash != "") && !fresh {
			fs.Resume = &Checkpoint{Offset: st.Offset, HeadHash: st.HeadHash}
		}
		src = fs
	case SourceExec:
		src = &ExecSource{Argv: cfg.Argv}
	case SourceClash:
		liveCh := make(chan ingestproto.Live, 4)
		ship.Live = liveCh
		src = &ClashSource{URL: cfg.ClashURL, LeasesFile: cfg.LeasesFile, Live: func(f ingestproto.Live) {
			select {
			case liveCh <- f:
			default: // the channel is full: drop the oldest, keep the newest
				select {
				case <-liveCh:
				default:
				}
				select {
				case liveCh <- f:
				default:
				}
			}
		}}
	default:
		return errors.New("agent: unknown source kind")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 2)
	go func() { errc <- src.Run(ctx, em) }()
	go func() { errc <- ship.Run(ctx) }()

	lastHadLoss := false
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			cpMu.Lock()
			dirty := pending != checkpointed
			cpMu.Unlock()
			if dirty || spool.Pending() || counters.Pending() || lastHadLoss {
				lastHadLoss = counters.Pending() // one more save after the loss is confirmed, to clear it on disk
				saveState()
			}
		case err := <-errc:
			cancel()
			saveState()
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		case <-ctx.Done():
			saveState()
			return nil
		}
	}
}

// runAWG is the whole of an AmneziaWG agent: a snapshot source and a link, with no spool and no state.
func runAWG(ctx context.Context, cfg Config, log *slog.Logger) error {
	snaps := make(chan ingestproto.AWG, 2)
	src := &AWGSource{Argv: cfg.AWGArgv, Every: cfg.AWGEvery, Log: func(m string) { log.Warn(m) }, Emit: func(f ingestproto.AWG) {
		select {
		case snaps <- f:
		default:
			select {
			case <-snaps:
			default:
			}
			select {
			case snaps <- f:
			default:
			}
		}
	}}
	link := &AWGLink{URL: cfg.ServerURL, TokenFile: cfg.TokenFile, CAFile: cfg.CAFile, AllowInsecure: cfg.AllowInsecure, Version: cfg.Version, SourceID: cfg.SourceID,
		Snapshots: snaps, ManageArgv: cfg.AWGManage, ContainerArgv: cfg.AWGContainer, Log: log}
	if cfg.AWGSensorSock != "" && (len(cfg.AWGSensorOf) > 0 || cfg.AWGSensorConf != "") {
		flows := make(chan ingestproto.AWGFlows, 8)
		link.Flows = flows
		sensor := &AWGSensorSource{Socket: cfg.AWGSensorSock, Containers: cfg.AWGSensorOf, ConfPath: cfg.AWGSensorConf, Log: func(m string) { log.Warn(m) }, Emit: func(f ingestproto.AWGFlows) {
			select {
			case flows <- f:
			default: // the link is behind: this minute is lost, the next one is not
			}
		}}
		go sensor.Run(ctx)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 2)
	go func() { errc <- src.Run(ctx, nil) }()
	go func() { errc <- link.Run(ctx) }()
	err := <-errc
	cancel()
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
