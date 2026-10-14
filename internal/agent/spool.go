// Package agent reads an Xray access log and ships it to RemnaScope.
//
// It never touches the Xray config or the Docker engine beyond the single read-only command
// it is told to run, keeps unsent lines in a bounded on-disk spool, and counts and reports
// everything it could not deliver instead of dropping it silently.
package agent

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ErrSpoolFull is returned by Append when the spool is at capacity. The caller counts the line
// as dropped and reports the gap.
var ErrSpoolFull = errors.New("agent: spool is full")

const (
	segmentMax = 4 << 20
	recHeader  = 12 // 4 bytes length + 8 bytes sequence
)

type segment struct {
	first, last int64
	size        int64
	path        string
}

type Item struct {
	Seq  int64
	Line string
}

// Spool is an append-only, segmented, crash-tolerant queue of lines keyed by sequence number.
// Writes reach the OS immediately (a process crash loses nothing); Sync forces them to disk
// (a power cut can lose at most what was written since the last Sync).
type Spool struct {
	mu       sync.Mutex
	dir      string
	max      int64
	segs     []*segment
	cur      *os.File
	curBuf   *bufio.Writer
	total    int64
	next     int64 // next sequence to assign
	acked    int64
	notEmpty chan struct{}
}

// OpenSpool opens or creates a spool. startSeq is used only when the spool is empty; it lets a
// restarted agent keep numbering where it left off.
func OpenSpool(dir string, maxBytes, startSeq int64) (*Spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Spool{dir: dir, max: maxBytes, notEmpty: make(chan struct{}, 1)}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		name := e.Name()
		if !strings.HasPrefix(name, "seg-") || !strings.HasSuffix(name, ".log") {
			continue
		}
		first, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(name, "seg-"), ".log"), 10, 64)
		if err != nil {
			continue
		}
		sg := &segment{first: first, path: filepath.Join(dir, name)}
		if err := scanSegment(sg); err != nil {
			return nil, err
		}
		if sg.last < sg.first { // empty after trimming a torn record
			_ = os.Remove(sg.path)
			continue
		}
		s.segs = append(s.segs, sg)
		s.total += sg.size
	}
	sort.Slice(s.segs, func(i, j int) bool { return s.segs[i].first < s.segs[j].first })
	switch {
	case len(s.segs) > 0:
		s.next = s.segs[len(s.segs)-1].last + 1
	default:
		s.next = startSeq
		if s.next < 1 {
			s.next = 1
		}
	}
	s.acked = s.next - 1
	if len(s.segs) > 0 {
		s.acked = s.segs[0].first - 1
	}
	if len(s.segs) > 0 {
		s.signal()
	}
	return s, nil
}

// scanSegment finds the last whole record, truncating a torn tail left by a crash mid-write.
func scanSegment(sg *segment) error {
	f, err := os.OpenFile(sg.path, os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<16)
	var off int64
	sg.last = sg.first - 1
	hdr := make([]byte, recHeader)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			break
		}
		n := int64(binary.BigEndian.Uint32(hdr[:4]))
		seq := int64(binary.BigEndian.Uint64(hdr[4:]))
		if n > 1<<20 || (sg.last >= sg.first && seq != sg.last+1) || (sg.last < sg.first && seq != sg.first) {
			break
		}
		if _, err := io.CopyN(io.Discard, r, n); err != nil {
			break
		}
		off += recHeader + n
		sg.last = seq
	}
	sg.size = off
	if st, err := f.Stat(); err == nil && st.Size() != off {
		return f.Truncate(off)
	}
	return nil
}

func (s *Spool) signal() {
	select {
	case s.notEmpty <- struct{}{}:
	default:
	}
}

// Ready is signalled when there may be unsent lines.
func (s *Spool) Ready() <-chan struct{} { return s.notEmpty }

func (s *Spool) Bytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total
}

// NextSeq is the sequence the next appended line will get.
func (s *Spool) NextSeq() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.next
}

// Pending reports whether lines beyond the acknowledged point exist.
func (s *Spool) Pending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.next-1 > s.acked
}

// Append stores a line and returns its sequence number.
func (s *Spool) Append(line string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := int64(recHeader + len(line))
	if s.total+rec > s.max {
		return 0, ErrSpoolFull
	}
	if s.cur == nil || s.segs[len(s.segs)-1].size+rec > segmentMax {
		if err := s.rotateLocked(); err != nil {
			return 0, err
		}
	}
	sg := s.segs[len(s.segs)-1]
	seq := s.next
	hdr := make([]byte, recHeader)
	binary.BigEndian.PutUint32(hdr[:4], uint32(len(line)))
	binary.BigEndian.PutUint64(hdr[4:], uint64(seq))
	if _, err := s.curBuf.Write(hdr); err != nil {
		return 0, err
	}
	if _, err := s.curBuf.WriteString(line); err != nil {
		return 0, err
	}
	sg.size += rec
	sg.last = seq
	s.total += rec
	s.next++
	s.signal()
	return seq, nil
}

func (s *Spool) rotateLocked() error {
	if s.cur != nil {
		_ = s.curBuf.Flush()
		_ = s.cur.Sync()
		_ = s.cur.Close()
		s.cur = nil
	}
	path := filepath.Join(s.dir, fmt.Sprintf("seg-%020d.log", s.next))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	s.cur, s.curBuf = f, bufio.NewWriterSize(f, 1<<16)
	s.segs = append(s.segs, &segment{first: s.next, last: s.next - 1, path: path})
	return nil
}

// Flush pushes buffered writes to the OS. Reads call it first, so a shipper never misses lines.
func (s *Spool) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.curBuf == nil {
		return nil
	}
	return s.curBuf.Flush()
}

// Sync flushes and fsyncs the current segment.
func (s *Spool) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return nil
	}
	if err := s.curBuf.Flush(); err != nil {
		return err
	}
	return s.cur.Sync()
}

// ReadFrom returns up to maxItems lines (and about maxBytes) starting at sequence from.
func (s *Spool) ReadFrom(from int64, maxItems, maxBytes int) ([]Item, error) {
	s.mu.Lock()
	if s.curBuf != nil {
		_ = s.curBuf.Flush()
	}
	var segs []segment
	for _, sg := range s.segs {
		if sg.last >= from {
			segs = append(segs, *sg)
		}
	}
	s.mu.Unlock()

	var out []Item
	bytes := 0
	for _, sg := range segs {
		f, err := os.Open(sg.path)
		if err != nil {
			return nil, err
		}
		r := bufio.NewReaderSize(f, 1<<16)
		hdr := make([]byte, recHeader)
		var read int64
		for read < sg.size {
			if _, err := io.ReadFull(r, hdr); err != nil {
				break
			}
			n := int(binary.BigEndian.Uint32(hdr[:4]))
			seq := int64(binary.BigEndian.Uint64(hdr[4:]))
			buf := make([]byte, n)
			if _, err := io.ReadFull(r, buf); err != nil {
				break
			}
			read += int64(recHeader + n)
			if seq < from {
				continue
			}
			out = append(out, Item{Seq: seq, Line: string(buf)})
			bytes += n
			if len(out) >= maxItems || bytes >= maxBytes {
				f.Close()
				return out, nil
			}
		}
		f.Close()
	}
	return out, nil
}

// Ack records that everything up to and including seq is safely stored on the server and
// deletes segments that are now entirely acknowledged.
func (s *Spool) Ack(seq int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq > s.acked {
		s.acked = seq
	}
	keep := s.segs[:0]
	for i, sg := range s.segs {
		isCurrent := i == len(s.segs)-1 && s.cur != nil
		if sg.last <= s.acked && sg.last >= sg.first && !isCurrent {
			s.total -= sg.size
			if err := os.Remove(sg.path); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		keep = append(keep, sg)
	}
	s.segs = keep
	// A fully acknowledged current segment is closed and removed as well, so the spool empties.
	if n := len(s.segs); n > 0 && s.cur != nil && s.segs[n-1].last <= s.acked {
		sg := s.segs[n-1]
		_ = s.curBuf.Flush()
		_ = s.cur.Close()
		s.cur, s.curBuf = nil, nil
		s.total -= sg.size
		_ = os.Remove(sg.path)
		s.segs = s.segs[:n-1]
	}
	return nil
}

func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return nil
	}
	_ = s.curBuf.Flush()
	_ = s.cur.Sync()
	err := s.cur.Close()
	s.cur, s.curBuf = nil, nil
	return err
}
