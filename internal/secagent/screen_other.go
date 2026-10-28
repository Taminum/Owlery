//go:build !windows

package secagent

import "github.com/Taminum/Owlery/internal/secproto"

// Screen sharing exists only on Windows: it needs the system account to launch a helper into the signed-in session.
// remoteReady already returns false off Windows (the helper files are never there), so this is only a safety net.
func (a *agent) openScreen(secproto.RemoteOpen) {
	a.cfg.Log.Warn("screen sharing is only available on Windows")
}
