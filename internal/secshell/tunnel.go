package secshell

import (
	"context"
	"errors"
	"net"
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
	var d net.Dialer
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	local, lerr := d.DialContext(lctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(req.Port)))
	cancel()
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	c, err := dial(dctx, secproto.TunnelPath, req.ID)
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
