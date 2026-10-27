package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/guac"
	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/store"
)

// A remote desktop goes browser → Owlery → guacd → Owlery → the machine's agent → 127.0.0.1:3389 on the machine.
// guacd speaks RDP or VNC but can only dial an address; Owlery gives it a one-off port on itself that leads into the
// agent's tunnel, so the machine's desktop port is never open to the network.
//
// The login and password are not kept: the page sends them once to get a ticket that is good for one connection
// within a minute, so they never travel in a URL.

const ticketTTL = time.Minute

type desktopTicket struct {
	account, vps               string
	protocol                   string
	username, password, domain string
	expires                    time.Time
}

type ticketBox struct {
	mu sync.Mutex
	m  map[string]desktopTicket
}

func (b *ticketBox) put(t desktopTicket) string {
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	id := hex.EncodeToString(raw)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.m == nil {
		b.m = map[string]desktopTicket{}
	}
	now := time.Now()
	for k, v := range b.m {
		if now.After(v.expires) {
			delete(b.m, k)
		}
	}
	b.m[id] = t
	return id
}

// take hands a ticket out once, to the account and server it was made for.
func (b *ticketBox) take(id, account, vps string) (desktopTicket, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ok := b.m[id]
	delete(b.m, id)
	if !ok || t.account != account || t.vps != vps || time.Now().After(t.expires) {
		return desktopTicket{}, false
	}
	return t, true
}

// desktopAgent finds the connected agent of a server the caller may open, and checks the machine allows a desktop.
func (s *Server) desktopAgent(w http.ResponseWriter, r *http.Request, a auth.Actor) (store.VPS, store.SecAgent, bool) {
	v, err := s.Store.GetVPS(r.Context(), a.Scope(), r.PathValue("id"))
	if err != nil {
		s.vpsNotFound(w, r)
		return v, store.SecAgent{}, false
	}
	if !vpsCanEdit(a, v) {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "an administrator of a linked panel is required")
		return v, store.SecAgent{}, false
	}
	if s.GuacdAddr == "" {
		s.writeErr(w, r, http.StatusServiceUnavailable, "desktop_off", "remote desktops are not set up on this server (GUACD_ADDR)")
		return v, store.SecAgent{}, false
	}
	agent, err := s.Store.SecAgentOf(r.Context(), v.ID)
	if err != nil || s.SecOps == nil || !s.SecOps.Online(agent.ID) {
		s.writeErr(w, r, http.StatusConflict, "agent_offline", "the machine's agent is not connected")
		return v, agent, false
	}
	if !slices.Contains(agent.Capabilities, secproto.CapDesktop) {
		s.writeErr(w, r, http.StatusConflict, "desktop_not_allowed", "this machine does not allow its desktop to be reached")
		return v, agent, false
	}
	return v, agent, true
}

// desktopTicket takes the login for one connection and answers with a ticket for the WebSocket.
func (s *Server) desktopTicket(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	v, _, ok := s.desktopAgent(w, r, a)
	if !ok {
		return
	}
	var in struct {
		Protocol string `json:"protocol"`
		Username string `json:"username"`
		Password string `json:"password"`
		Domain   string `json:"domain"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if in.Protocol != "rdp" && in.Protocol != "vnc" {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_protocol", "protocol must be rdp or vnc")
		return
	}
	if len(in.Username) > 256 || len(in.Password) > 256 || len(in.Domain) > 256 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_login", "the login is too long")
		return
	}
	id := s.tickets.put(desktopTicket{account: a.AccountID, vps: v.ID, protocol: in.Protocol, username: in.Username, password: in.Password,
		domain: in.Domain, expires: time.Now().Add(ticketTTL)})
	writeJSON(w, http.StatusOK, map[string]string{"ticket": id})
}

// desktop is the WebSocket the browser's Guacamole client talks to.
func (s *Server) desktop(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !sameOrigin(r) {
		s.writeErr(w, r, http.StatusForbidden, "cross_origin", "cross-origin request refused")
		return
	}
	v, agent, ok := s.desktopAgent(w, r, a)
	if !ok {
		return
	}
	q := r.URL.Query()
	t, ok := s.tickets.take(q.Get("ticket"), a.AccountID, v.ID)
	if !ok {
		s.writeErr(w, r, http.StatusForbidden, "bad_ticket", "the desktop ticket is unknown, used or expired")
		return
	}
	b, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// The browser library asks for this subprotocol and drops the connection if it is not chosen.
		Subprotocols: []string{"guacamole"},
		// The picture is compressed already; a second pass only costs processor.
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	defer b.CloseNow()
	b.SetReadLimit(1 << 20)
	ctx := r.Context()
	fail := func(msg string) {
		_ = b.Write(ctx, websocket.MessageText, []byte(guac.New("error", msg, "519").String()))
		b.Close(websocket.StatusNormalClosure, "")
	}

	// The browser library gives up after 15 seconds without a message; opening a desktop can take longer.
	waiting, stopWaiting := context.WithCancel(ctx)
	go func() {
		tick := time.NewTicker(3 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-waiting.Done():
				return
			case <-tick.C:
				_ = b.Write(waiting, websocket.MessageText, []byte(guac.New("nop").String()))
			}
		}
	}()
	defer stopWaiting()
	port := 3389
	if t.protocol == "vnc" {
		port = 5900
	}
	octx, cancel := context.WithTimeout(ctx, 20*time.Second)
	m, release, err := s.SecOps.OpenTunnel(octx, agent.ID, port)
	cancel()
	if err != nil {
		fail("Машина не ответила: агент не открыл туннель к рабочему столу.")
		return
	}
	defer release()
	defer m.CloseNow()
	fctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	typ, first, err := m.Read(fctx)
	cancel()
	if err != nil || typ != websocket.MessageText || string(first) != secproto.TunnelReady {
		fail(map[string]string{"rdp": "На машине не включён удалённый рабочий стол: на порту 3389 никто не отвечает.", "vnc": "На машине не отвечает VNC-сервер (порт 5900)."}[t.protocol])
		return
	}

	// A port on Owlery for guacd to dial, that leads into the tunnel. Only guacd's own address is let in, once.
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		fail("Owlery не смог открыть порт для рабочего стола.")
		return
	}
	defer l.Close()
	inner := make(chan net.Conn, 1)
	go s.acceptGuacd(l, inner)

	values := map[string]string{"hostname": s.DesktopHost, "port": strconv.Itoa(l.Addr().(*net.TCPAddr).Port)}
	if t.protocol == "rdp" {
		values["username"], values["password"], values["domain"] = t.username, t.password, t.domain
		values["security"], values["ignore-cert"] = "any", "true"
		values["resize-method"] = "display-update"
		values["enable-font-smoothing"] = "true"
		values["disable-audio"] = "true"
	} else {
		values["password"] = t.password
	}
	w0, h0, dpi := atoiBound(q.Get("width"), 1280), atoiBound(q.Get("height"), 800), atoiBound(q.Get("dpi"), 96)

	// guacd dials our port while the handshake is in progress, so the tunnel is wired up as soon as it does.
	go func() {
		select {
		case c := <-inner:
			relayTCP(ctx, c, m)
		case <-ctx.Done():
		}
	}()
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	gc, err := guac.Dial(dctx, s.GuacdAddr, guac.Params{Protocol: t.protocol, Values: values, Width: w0, Height: h0, DPI: dpi})
	cancel()
	if err != nil {
		s.Log.Warn("desktop did not open", "server", v.Name, "err", err)
		fail("Рабочий стол не открылся: " + err.Error())
		return
	}
	defer gc.Close()

	stopWaiting()
	started := s.Now().UTC()
	s.audit(r, a, "", "desktop.open", "server", v.ID, map[string]any{"name": v.Name, "protocol": t.protocol, "user": t.username})
	// The first message, with an empty opcode, is how the browser library learns the tunnel is open.
	if b.Write(ctx, websocket.MessageText, []byte(guac.New("", gc.UUID()).String())) == nil {
		pipeDesktop(ctx, b, gc)
	}
	s.audit(r, a, "", "desktop.close", "server", v.ID, map[string]any{"name": v.Name, "protocol": t.protocol,
		"seconds": int(s.Now().UTC().Sub(started).Seconds())})
}

// acceptGuacd takes the first connection that comes from guacd and refuses anything else.
func (s *Server) acceptGuacd(l net.Listener, out chan<- net.Conn) {
	want := map[string]bool{}
	if host, _, err := net.SplitHostPort(s.GuacdAddr); err == nil {
		if ips, err := net.LookupHost(host); err == nil {
			for _, ip := range ips {
				want[ip] = true
			}
		}
	}
	if tl, ok := l.(*net.TCPListener); ok {
		_ = tl.SetDeadline(time.Now().Add(45 * time.Second))
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		if len(want) > 0 && !want[host] {
			c.Close()
			continue
		}
		out <- c
		return
	}
}

// relayTCP carries bytes between guacd's connection and the agent's tunnel until either ends.
func relayTCP(ctx context.Context, c net.Conn, m *websocket.Conn) {
	defer c.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		defer cancel()
		buf := make([]byte, 64<<10)
		for {
			n, err := c.Read(buf)
			if n > 0 && m.Write(ctx, websocket.MessageBinary, buf[:n]) != nil {
				return
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		_, data, err := m.Read(ctx)
		if err != nil {
			return
		}
		if _, err := c.Write(data); err != nil {
			return
		}
	}
}

// pipeDesktop carries instructions both ways while both sides live. What the browser sends is parsed: its library
// sends its own pings with an empty opcode, meant for the tunnel and unknown to guacd.
func pipeDesktop(ctx context.Context, b *websocket.Conn, gc *guac.Conn) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		defer cancel()
		for {
			i, err := gc.Read()
			if err != nil {
				return
			}
			if b.Write(ctx, websocket.MessageText, []byte(i.String())) != nil {
				return
			}
		}
	}()
	for {
		_, data, err := b.Read(ctx)
		if err != nil {
			return
		}
		r := guac.NewReader(bytes.NewReader(data))
		for {
			i, err := r.Read()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					break // a malformed instruction from the page is dropped, the desktop stays
				}
				break
			}
			if i.Opcode == "" {
				continue
			}
			if gc.Send(i) != nil {
				return
			}
		}
	}
}

func atoiBound(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > 8000 {
		return def
	}
	return n
}
