//go:build windows

package remotehelper

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"image/jpeg"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

// videoFPS is how often the screen is captured and handed to the encoder. Full uncompressed frames are copied to
// ffmpeg, so this trades smoothness against the processor and the pipe; 15 is a sensible middle on a desktop machine.
const videoFPS = 15

// frameInterval and jpegQuality are the still-picture fallback used when there is no encoder.
const frameInterval = 140 * time.Millisecond

const jpegQuality = 55

// Run starts the helper: the tray icon and the local server the agent hands sessions to. It blocks until ctx ends.
func Run(ctx context.Context, secretFile string, log *slog.Logger) error {
	makeDPIAware()
	secret, err := os.ReadFile(secretFile)
	if err != nil {
		return fmt.Errorf("remotehelper: reading the secret: %w", err)
	}
	h := &helper{secret: secret, log: log, ffmpeg: findFFmpeg(filepath.Dir(secretFile))}
	if h.ffmpeg == "" {
		log.Warn("ffmpeg.exe not found next to the helper: the screen goes as still pictures, not video")
	}
	h.tray, err = newTray(h.endActiveSession)
	if err != nil {
		return err
	}
	defer h.tray.close()

	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", secproto.RemoteHelperPort))
	if err != nil {
		return fmt.Errorf("remotehelper: listening: %w", err)
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	log.Info("remote-control helper ready")
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go h.handle(ctx, c)
	}
}

// stoppedByPerson is set when the session ends because of the tray menu rather than because the browser left.
var stoppedByPerson atomic.Bool

// lockedConn serialises writes: frames and the final notice come from different goroutines.
type lockedConn struct {
	net.Conn
	mu sync.Mutex
}

func (c *lockedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.Write(p)
}

type helper struct {
	secret []byte
	tray   *tray
	log    *slog.Logger
	ffmpeg string // empty: no video encoder, the screen goes as JPEG pictures

	mu     sync.Mutex
	cancel context.CancelFunc // of the one session currently running, nil when none
}

// endActiveSession is what the tray menu's "Прекратить показ" calls.
func (h *helper) endActiveSession() {
	stoppedByPerson.Store(true)
	h.mu.Lock()
	cancel := h.cancel
	h.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (h *helper) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	lead := make([]byte, len(h.secret))
	if _, err := fullRead(c, lead); err != nil || subtle.ConstantTimeCompare(lead, h.secret) != 1 {
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	h.mu.Lock()
	if h.cancel != nil {
		h.mu.Unlock()
		_ = writeError(c, "на этой машине уже идёт другая сессия")
		return
	}
	sessCtx, cancel := context.WithCancel(ctx)
	h.cancel = cancel
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		h.cancel = nil
		h.mu.Unlock()
		cancel()
		h.tray.hide()
	}()

	stoppedByPerson.Store(false)
	h.tray.show("Owlery: ваш экран смотрят")
	h.log.Info("remote session started")
	runSession(sessCtx, c, h.ffmpeg, h.log)
	h.log.Info("remote session ended")
}

func fullRead(c net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := c.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// runSession captures the screen and applies input until the connection breaks or the session is cancelled (from
// the tray, or because the browser disconnected).
func runSession(ctx context.Context, conn net.Conn, ffmpeg string, log *slog.Logger) {
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	c := &lockedConn{Conn: conn}
	// Whatever ends the session (the tray menu, the browser leaving, shutdown) wakes the reader below by closing
	// the connection; when it was the person's button, the browser is told so first.
	go func() {
		<-ctx.Done()
		if stoppedByPerson.Load() {
			_ = writeMsg(c, msgEnd, nil)
		}
		c.Conn.Close()
	}()

	if ffmpeg != "" {
		go func() {
			defer stop()
			if err := streamVideo(ctx, c, ffmpeg); err != nil && ctx.Err() == nil {
				log.Warn("video stream ended", "err", err)
				_ = writeError(c, "не удалось запустить видео: "+err.Error())
			}
		}()
	} else {
		go stillPictures(ctx, stop, c)
	}

	// Input is injected from this one thread, locked and kept on the desktop that is receiving input, so a click lands
	// on a UAC prompt or the lock screen as readily as on an ordinary window.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var foll follower
	defer foll.close()
	var prevButtons uint8
	for {
		typ, payload, err := readMsg(c)
		if err != nil {
			stop()
			return
		}
		foll.bindInput()
		switch typ {
		case msgMouse:
			if ev, ok := parseMouse(payload); ok {
				applyMouse(ev, prevButtons)
				prevButtons = ev.Buttons
			}
		case msgKey:
			if ev, ok := parseKey(payload); ok {
				applyKey(ev)
			}
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// stillPictures is the fallback without a video encoder: JPEG pictures, only when the screen changed. It too follows
// the input desktop, so even without ffmpeg a UAC prompt is seen.
func stillPictures(ctx context.Context, stop context.CancelFunc, c net.Conn) {
	defer stop()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var foll follower
	defer foll.close()
	tick := time.NewTicker(frameInterval)
	defer tick.Stop()
	var prev []byte
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		foll.bindCapture()
		img, err := captureScreen()
		if err != nil {
			continue // a single failed capture is not worth ending the session over
		}
		if bytes.Equal(prev, img.Pix) {
			continue // nothing moved on the screen: nothing to send
		}
		prev = append(prev[:0], img.Pix...)
		var buf bytes.Buffer
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: jpegQuality}); err != nil {
			continue
		}
		b := img.Bounds()
		if writeFrame(c, b.Dx(), b.Dy(), buf.Bytes()) != nil {
			return
		}
	}
}

// streamVideo captures the screen on a thread it keeps on the input desktop and feeds every frame to ffmpeg, restarting
// the encoder when the screen's size changes (a resolution change, or a different-sized secure desktop). ffmpeg's H.264
// is read back and sent to the browser by pumpEncoder.
func streamVideo(ctx context.Context, c net.Conn, ffmpeg string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var foll follower
	defer foll.close()

	var cmd *exec.Cmd
	var stdin io.WriteCloser
	var curW, curH int
	stopEncoder := func() {
		if cmd != nil {
			_ = stdin.Close()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			cmd = nil
		}
	}
	defer stopEncoder()

	tick := time.NewTicker(time.Second / videoFPS)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		foll.bindCapture()
		raw, w, h, err := captureRaw()
		if err != nil || w == 0 || h == 0 {
			continue // a single failed capture is not worth ending the session over
		}
		if cmd == nil || w != curW || h != curH {
			stopEncoder()
			var stdout io.ReadCloser
			cmd, stdin, stdout, err = startEncoder(ctx, ffmpeg, w, h, videoFPS)
			if err != nil {
				return err
			}
			curW, curH = w, h
			go pumpEncoder(ctx, c, stdout)
		}
		if _, err := stdin.Write(raw); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("the encoder stopped (check ffmpeg.exe)")
		}
	}
}

// pumpEncoder carries one encoder's H.264 pictures to the browser. A slow link must not make the picture lag further
// and further behind, so pictures wait in a short queue and, when it is full, the rest of that group is dropped: the
// picture jumps forward at the next one a decoder can start from instead of sliding into the past.
func pumpEncoder(ctx context.Context, c net.Conn, stdout io.ReadCloser) {
	type unit struct {
		data []byte
		key  bool
	}
	queue := make(chan unit, 12)
	go func() {
		skipping := false
		_ = splitAccessUnits(stdout, func(u []byte, key bool) bool {
			if key {
				skipping = false
			}
			if skipping {
				return ctx.Err() == nil
			}
			select {
			case queue <- unit{u, key}:
			default:
				skipping = true
			}
			return ctx.Err() == nil
		})
		close(queue)
	}()
	for u := range queue {
		flag := byte(0)
		if u.key {
			flag = 1
		}
		if writeMsg(c, msgVideo, append([]byte{flag}, u.data...)) != nil {
			return
		}
	}
}
