package secagent

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/selfupdate"
)

// updateReady says whether this agent may be updated from the server card: the machine allowed it, it has a place to keep
// the new release, and it is a release itself (a development build is never replaced).
func (a *agent) updateReady() bool {
	return a.cfg.AllowUpdate && a.cfg.UpdateDir != "" && selfupdate.ValidVersion(a.cfg.Version)
}

func shorten(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// update fetches the release the server named, checks it against the release key, and hands it on to be installed. The
// server names only a version: the address is the project's own, and the hash comes from the signed list of the release.
func (a *agent) update(ctx context.Context, req secproto.UpdateReq) secproto.UpdateResult {
	res := secproto.UpdateResult{Type: "update_result", ID: req.ID}
	fail := func(msg string) secproto.UpdateResult {
		res.Error = shorten(msg)
		return res
	}
	if !a.updateReady() {
		return fail("not_allowed")
	}
	if !selfupdate.ValidVersion(req.Version) {
		return fail("bad_version")
	}
	if !selfupdate.Newer(req.Version, a.cfg.Version) {
		return fail("up_to_date")
	}
	if !a.updating.CompareAndSwap(false, true) {
		return fail("busy")
	}
	defer a.updating.Store(false)
	fctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	f := a.cfg.UpdateFetcher
	if f == nil {
		f = &selfupdate.Fetcher{}
	}
	staged := filepath.Join(a.cfg.UpdateDir, selfupdate.DirStaged)
	if err := os.MkdirAll(a.cfg.UpdateDir, 0o700); err != nil {
		return fail("cannot keep the release: " + err.Error())
	}
	if err := f.Fetch(fctx, req.Version, runtime.GOOS, runtime.GOARCH, staged); err != nil {
		a.cfg.Log.Warn("update: the release was refused", "version", req.Version, "err", err)
		return fail(err.Error())
	}
	if err := a.applyStaged(req.Version); err != nil {
		a.cfg.Log.Warn("update: could not install", "version", req.Version, "err", err)
		return fail(err.Error())
	}
	a.cfg.Log.Info("update: the release is checked and on its way in", "version", req.Version)
	res.OK = true
	return res
}

// onConnected is what the agent does once the server has accepted it. It tells whoever is watching an update that this version
// is up and connected: on Linux the root helper waits for that file, and on Windows it ends the trial of a new program.
func (a *agent) onConnected() {
	if a.cfg.UpdateDir == "" {
		return
	}
	if err := os.MkdirAll(a.cfg.UpdateDir, 0o700); err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(a.cfg.UpdateDir, selfupdate.FileHealthy), []byte(strings.TrimSpace(a.cfg.Version)+"\n"), 0o600)
	a.updateConnected()
}
