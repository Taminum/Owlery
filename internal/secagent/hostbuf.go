package secagent

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

// hostBuffer keeps, on disk, the readings of the host taken while the server could not be reached, one a minute at most and
// at most a day's worth, so that a break in the connection is not a hole in the charts or in the availability. The
// process lists are left out: only the numbers a chart needs.
type hostBuffer struct {
	mu   sync.Mutex
	path string
}

const (
	hostBufferMax = 1440
	hostBufferGap = 55 * time.Second
)

func newHostBuffer(stateDir string) *hostBuffer {
	if stateDir == "" {
		return nil
	}
	return &hostBuffer{path: filepath.Join(stateDir, "host-buffer.jsonl")}
}

func (b *hostBuffer) readAll() []secproto.Host {
	f, err := os.Open(b.path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []secproto.Host
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 256<<10)
	for sc.Scan() {
		var h secproto.Host
		if json.Unmarshal(sc.Bytes(), &h) == nil && !h.At.IsZero() {
			out = append(out, h)
		}
	}
	return out
}

func (b *hostBuffer) write(items []secproto.Host) error {
	if len(items) == 0 {
		if err := os.Remove(b.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	tmp := b.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, h := range items {
		if err := enc.Encode(h); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, b.path)
}

// Add keeps one reading, unless the last one is less than a minute old, and drops the oldest beyond a day.
func (b *hostBuffer) Add(h secproto.Host) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	items := b.readAll()
	if n := len(items); n > 0 && h.At.Sub(items[n-1].At) < hostBufferGap {
		return nil
	}
	h.Procs, h.Units = nil, nil
	items = append(items, h)
	if len(items) > hostBufferMax {
		items = items[len(items)-hostBufferMax:]
	}
	return b.write(items)
}

// Take hands over everything kept, oldest first, in pieces of at most n, and forgets it only when send has accepted every piece.
func (b *hostBuffer) Take(n int, send func([]secproto.Host) error) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	items := b.readAll()
	for len(items) > 0 {
		k := min(n, len(items))
		if err := send(items[:k]); err != nil {
			return b.write(items) // what was not sent stays
		}
		items = items[k:]
	}
	return b.write(nil)
}
