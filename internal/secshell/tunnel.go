package secshell

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/coder/websocket"

	"github.com/Taminum/Owlery/internal/secproto"
)

// Tunnel carries one TCP connection to a local port (the machine's own RDP or VNC) over a connection back to Owlery.
// Nothing listens: the agent dials out to Owlery and to 127.0.0.1, so the desktop port need not be open to anyone.
func Tunnel(ctx context.Context, dial func(ctx context.Context, path, id string) (*websocket.Conn, error), req secproto.TunnelOpen) error {
	if !secproto.DesktopPorts[req.Port] {
		return errors.New("tunnel refused: not a desktop port")
	}
	return dialAndRelay(ctx, dial, secproto.TunnelPath, req.ID, req.Port, nil)
}

// RemoteTunnel carries one session to the machine's remote-control helper: a second, user-session process that shows
// the signed-in person's own screen and takes mouse and keyboard, for machines the agent's own session (a system
// service, invisible to any desktop) cannot reach directly. secretFile holds the token the helper requires as the
// first bytes of a connection, written when the helper was installed, so no other local process can drive it.
func RemoteTunnel(ctx context.Context, dial func(ctx context.Context, path, id string) (*websocket.Conn, error), secretFile string, req secproto.RemoteOpen) error {
	secret, err := os.ReadFile(secretFile)
	if err != nil {
		return fmt.Errorf("remote control is not set up on this machine: %w", err)
	}
	return dialAndRelay(ctx, dial, secproto.RemotePath, req.ID, secproto.RemoteHelperPort, secret)
}

// dialAndRelay dials 127.0.0.1:port and the matching session back to Owlery, sends `lead` first on the local
// connection when given (the remote-control helper's shared secret), tells Owlery whether the local port answered,
// and then carries bytes both ways until either side ends.
func dialAndRelay(ctx context.Context, dial func(ctx context.Context, path, id string) (*websocket.Conn, error), path, id string, port int, lead []byte) error {
	var d net.Dialer
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	local, lerr := d.DialContext(lctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	cancel()
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	c, err := dial(dctx, path, id)
	cancel()
	if err != nil {
		if local != nil {
			local.Close()
		}
		return err
	}
	c.SetReadLimit(4 << 20)
	defer c.CloseNow()
	// The first frame says whether the local port answered, so Owlery can tell the person at once.
	if lerr != nil {
		_ = c.Write(ctx, websocket.MessageText, []byte(secproto.TunnelPortClosed))
		c.Close(websocket.StatusNormalClosure, "")
		return lerr
	}
	defer local.Close()
	if len(lead) > 0 {
		if _, err := local.Write(lead); err != nil {
			return err
		}
	}
	if err := c.Write(ctx, websocket.MessageText, []byte(secproto.TunnelReady)); err != nil {
		return err
	}
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		defer stop()
		buf := make([]byte, 64<<10)
		for {
			n, err := local.Read(buf)
			if n > 0 && c.Write(ctx, websocket.MessageBinary, buf[:n]) != nil {
				return
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		_, b, err := c.Read(ctx)
		if err != nil {
			return nil
		}
		if _, err := local.Write(b); err != nil {
			return err
		}
	}
}
