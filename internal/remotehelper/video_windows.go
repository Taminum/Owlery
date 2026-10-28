//go:build windows

package remotehelper

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
)

// msgVideo is one H.264 picture for the browser's decoder: a flag byte (bit 0: a picture the decoder can start from)
// followed by the picture in Annex B form.
const msgVideo = 0x06

// findFFmpeg looks for ffmpeg.exe next to the helper's own files (where the installer puts it), then on the path.
func findFFmpeg(dir string) string {
	if p := filepath.Join(dir, "ffmpeg.exe"); fileExists(p) {
		return p
	}
	if p, err := exec.LookPath("ffmpeg.exe"); err == nil {
		return p
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// startEncoder runs ffmpeg as a plain encoder: raw BGRA frames of a fixed size come in on its standard input (this
// process captures them, so ffmpeg itself needs no access to the screen or the desktop), low-latency H.264 goes out on
// its standard output. The picture is capped at 1920 wide and made even-sided as the encoder requires; a one-second
// group of pictures with headers repeated on every key picture lets a browser that joins or recovers start quickly, and
// an access-unit delimiter before each picture lets the stream be cut back into pictures.
func startEncoder(ctx context.Context, ffmpeg string, w, h, fps int) (*exec.Cmd, io.WriteCloser, io.ReadCloser, error) {
	cmd := exec.CommandContext(ctx, ffmpeg, "-hide_banner", "-loglevel", "error",
		"-f", "rawvideo", "-pixel_format", "bgra", "-video_size", fmt.Sprintf("%dx%d", w, h), "-framerate", strconv.Itoa(fps), "-i", "pipe:0",
		"-vf", "scale='trunc(min(1920,iw)/2)*2':-2:flags=fast_bilinear",
		"-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency", "-profile:v", "baseline", "-pix_fmt", "yuv420p",
		"-g", strconv.Itoa(fps), "-x264-params", "aud=1:repeat-headers=1:bframes=0:sliced-threads=0",
		"-flush_packets", "1", "-f", "h264", "pipe:1")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, fmt.Errorf("ffmpeg did not start: %w", err)
	}
	return cmd, stdin, stdout, nil
}
