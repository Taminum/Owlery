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
	local, err := d.DialContext(lctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(req.Port)))
	cancel()
	if err != nil {
		return err
	}
	defer local.Close()
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	c, err := dial(dctx, secproto.TunnelPath, req.ID)
	cancel()
	if err != nil {
		return err
	}
	c.SetReadLimit(4 << 20)
	defer c.CloseNow()
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
