// Package guac talks to guacd, the daemon that turns RDP and VNC into a stream of drawing instructions a browser can
// show. Writing an RDP client is years of work; guacd's own protocol is simple enough to speak directly, without the
// Java web application that usually sits in front of it.
//
// An instruction is an opcode and its arguments, each written as "<length>.<value>", separated by commas and ended
// by a semicolon: "5.error,11.no access,3.519;". The length counts Unicode characters, not bytes: counting bytes
// works for Latin text and breaks silently on the first Cyrillic user name.
//
// The package came from Owlery V2 (the earlier, separate attempt at a fleet console).
package guac

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Instruction struct {
	Opcode string
	Args   []string
}

func New(opcode string, args ...string) Instruction { return Instruction{Opcode: opcode, Args: args} }

func (i Instruction) String() string {
	var b strings.Builder
	put := func(s string) {
		b.WriteString(strconv.Itoa(utf8.RuneCountInString(s)))
		b.WriteByte('.')
		b.WriteString(s)
	}
	put(i.Opcode)
	for _, a := range i.Args {
		b.WriteByte(',')
		put(a)
	}
	b.WriteByte(';')
	return b.String()
}

// Arg is the n-th argument, or "" when there is none: guacd may send shorter instructions than expected.
func (i Instruction) Arg(n int) string {
	if n < 0 || n >= len(i.Args) {
		return ""
	}
	return i.Args[n]
}

var ErrMalformed = errors.New("guac: malformed instruction")

// maxArg bounds one argument. Screen updates come as their own instructions and can be large, but not without end.
const maxArg = 16 << 20

type Reader struct{ src *bufio.Reader }

func NewReader(r io.Reader) *Reader { return &Reader{src: bufio.NewReaderSize(r, 64<<10)} }

// Read reads one whole instruction.
func (r *Reader) Read() (Instruction, error) {
	var out Instruction
	first := true
	for {
		ls, err := r.src.ReadString('.')
		if err != nil {
			return out, err
		}
		n, err := strconv.Atoi(strings.TrimSuffix(ls, "."))
		if err != nil || n < 0 || n > maxArg {
			return out, fmt.Errorf("%w: length %q", ErrMalformed, ls)
		}
		var b strings.Builder
		for i := 0; i < n; i++ {
			c, _, err := r.src.ReadRune()
			if err != nil {
				return out, err
			}
			b.WriteRune(c)
		}
		if first {
			out.Opcode, first = b.String(), false
		} else {
			out.Args = append(out.Args, b.String())
		}
		sep, err := r.src.ReadByte()
		if err != nil {
			return out, err
		}
		switch sep {
		case ';':
			return out, nil
		case ',':
		default:
			return out, fmt.Errorf("%w: separator %q", ErrMalformed, sep)
		}
	}
}

// Params are what a connection is opened with. Values are the connection's settings by name: guacd asks for the
// ones it knows, in its own order, and only those are sent.
type Params struct {
	Protocol           string // rdp | vnc
	Values             map[string]string
	Width, Height, DPI int
}

// Conn is a connection to guacd past its handshake.
type Conn struct {
	nc   net.Conn
	r    *Reader
	uuid string
}

// Dial connects to guacd and completes the handshake: select the protocol, read the settings guacd asks for, send
// the screen size and what the browser can show, then the values in exactly the order guacd listed them. The order
// is taken from guacd, never assumed: RDP's settings change between guacd versions, and a fixed list would one day
// send the password as the domain.
func Dial(ctx context.Context, addr string, p Params) (*Conn, error) {
	d := net.Dialer{Timeout: 15 * time.Second}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("guacd is not reachable: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = nc.SetDeadline(dl)
	} else {
		_ = nc.SetDeadline(time.Now().Add(30 * time.Second))
	}
	c := &Conn{nc: nc, r: NewReader(nc)}
	if err := c.handshake(p); err != nil {
		nc.Close()
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	return c, nil
}

func (c *Conn) handshake(p Params) error {
	if err := c.Send(New("select", p.Protocol)); err != nil {
		return err
	}
	args, err := c.r.Read()
	if err != nil {
		return fmt.Errorf("guacd did not list its settings: %w", err)
	}
	if args.Opcode != "args" {
		return fmt.Errorf("guacd answered %q instead of args", args.Opcode)
	}
	w, h, dpi := p.Width, p.Height, p.DPI
	if w <= 0 {
		w = 1280
	}
	if h <= 0 {
		h = 800
	}
	if dpi <= 0 {
		dpi = 96
	}
	for _, i := range []Instruction{New("size", strconv.Itoa(w), strconv.Itoa(h), strconv.Itoa(dpi)), New("audio"), New("video"), New("image", "image/png", "image/jpeg", "image/webp")} {
		if err := c.Send(i); err != nil {
			return err
		}
	}
	values := make([]string, 0, len(args.Args))
	for i, name := range args.Args {
		// The first item is the protocol version, sent back as it is.
		if i == 0 && strings.HasPrefix(name, "VERSION_") {
			values = append(values, name)
			continue
		}
		values = append(values, p.Values[name])
	}
	if err := c.Send(New("connect", values...)); err != nil {
		return err
	}
	ready, err := c.r.Read()
	if err != nil {
		return fmt.Errorf("guacd did not confirm the connection: %w", err)
	}
	if ready.Opcode == "error" {
		return fmt.Errorf("guacd refused: %s", ready.Arg(0))
	}
	if ready.Opcode != "ready" {
		return fmt.Errorf("guacd answered %q instead of ready", ready.Opcode)
	}
	c.uuid = ready.Arg(0)
	return nil
}

func (c *Conn) UUID() string               { return c.uuid }
func (c *Conn) Read() (Instruction, error) { return c.r.Read() }
func (c *Conn) Send(i Instruction) error {
	_, err := io.WriteString(c.nc, i.String())
	return err
}
func (c *Conn) Close() error { return c.nc.Close() }
