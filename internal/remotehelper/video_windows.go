//go:build windows

package remotehelper

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
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

// startVideo runs ffmpeg to grab the whole desktop and encode it as low-latency H.264, written to its standard output.
// The picture is capped at 1920 pixels wide and made even-sided, as the encoder requires; a short group of pictures (one
// second) lets a browser that joins or recovers start soon, and each picture is preceded by a delimiter so the stream can
// be cut into pictures again.
func startVideo(ctx context.Context, ffmpeg string) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, ffmpeg, "-hide_banner", "-loglevel", "error",
		"-f", "gdigrab", "-framerate", "30", "-draw_mouse", "1", "-i", "desktop",
		"-vf", "scale='trunc(min(1920,iw)/2)*2':-2:flags=fast_bilinear",
		"-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency", "-profile:v", "baseline", "-pix_fmt", "yuv420p",
		"-g", "30", "-x264-params", "aud=1:repeat-headers=1:bframes=0:sliced-threads=0",
		"-flush_packets", "1", "-f", "h264", "pipe:1")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	return cmd, nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
