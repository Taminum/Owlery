package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Emitter receives what a source produces. Gap is called when lines may have been missed.
type Emitter interface {
	Line(s string)
	Gap(reason string)
}

// Checkpoint is a position in a file source: enough to tell "the same file, further on" from
// "a new file".
type Checkpoint struct {
	Offset   int64
	HeadHash string
}

const headLen = 64

func headHash(f *os.File) (string, error) {
	buf := make([]byte, headLen)
	n, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if n < headLen {
		return "", nil // too short to identify yet; trusted by offset alone
	}
	h := sha256.Sum256(buf[:n])
	return hex.EncodeToString(h[:8]), nil
}

// FileSource follows a log file that is rotated by renaming (s6-log writes "current" and keeps
// finished files as "@<timestamp>.s" beside it). It opens the file for each pass instead of
// holding it, identifies files by the hash of their first bytes, and when it sees that the file
// was replaced it first finishes the rotated one, so no lines are lost at a rotation.
type FileSource struct {
	Path       string
	Poll       time.Duration
	FromStart  bool        // with no checkpoint: read the existing content instead of starting at the end
	Resume     *Checkpoint // where the previous run stopped, if known
	OnProgress func(Checkpoint)
}

func (fs *FileSource) poll() time.Duration {
	if fs.Poll > 0 {
		return fs.Poll
	}
	return 250 * time.Millisecond
}

func (fs *FileSource) Run(ctx context.Context, em Emitter) error {
	var cp Checkpoint
	started := false
	if fs.Resume != nil {
		cp = *fs.Resume
		started = true
	}
	var carry []byte // an incomplete last line
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		progressed, next, err := fs.pass(em, cp, started, &carry)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil {
			cp, started = next, true
			if progressed && fs.OnProgress != nil {
				fs.OnProgress(cp)
			}
		}
		if progressed {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(fs.poll()):
		}
	}
}

// pass reads whatever is new and reports whether it read anything.
func (fs *FileSource) pass(em Emitter, cp Checkpoint, started bool, carry *[]byte) (bool, Checkpoint, error) {
	f, err := os.Open(fs.Path)
	if err != nil {
		return false, cp, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return false, cp, err
	}
	hash, err := headHash(f)
	if err != nil {
		return false, cp, err
	}

	if !started { // first ever run
		if fs.FromStart {
			return fs.readFrom(f, em, Checkpoint{HeadHash: hash}, carry)
		}
		return false, Checkpoint{Offset: st.Size(), HeadHash: hash}, nil
	}

	sameFile := cp.HeadHash == "" || hash == "" || cp.HeadHash == hash
	switch {
	case sameFile && st.Size() >= cp.Offset:
		if cp.HeadHash == "" {
			cp.HeadHash = hash
		}
		return fs.readFrom(f, em, cp, carry)
	case sameFile: // shorter than where we were: truncated in place
		em.Gap("truncated")
		*carry = nil
		return fs.readFrom(f, em, Checkpoint{HeadHash: hash}, carry)
	}

	// The file at Path is a different one: it was rotated. Finish the old one first.
	if old := fs.findRotated(cp.HeadHash); old != "" {
		if of, err := os.Open(old); err == nil {
			_, _, _ = fs.readFrom(of, em, cp, carry)
			of.Close()
		}
		if len(*carry) > 0 { // a finished file ends on a line boundary; anything left is a torn line
			em.Gap("torn_line")
			*carry = nil
		}
	} else {
		em.Gap("rotated_unseen")
		*carry = nil
	}
	return fs.readFrom(f, em, Checkpoint{HeadHash: hash}, carry)
}

func (fs *FileSource) findRotated(want string) string {
	dir := filepath.Dir(fs.Path)
	var cands []string
	for _, pat := range []string{"@*.s", "@*.u"} {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		cands = append(cands, m...)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(cands)))
	for _, c := range cands {
		f, err := os.Open(c)
		if err != nil {
			continue
		}
		h, err := headHash(f)
		f.Close()
		if err == nil && h != "" && h == want {
			return c
		}
	}
	return ""
}

func (fs *FileSource) readFrom(f *os.File, em Emitter, cp Checkpoint, carry *[]byte) (bool, Checkpoint, error) {
	if _, err := f.Seek(cp.Offset, io.SeekStart); err != nil {
		return false, cp, err
	}
	r := bufio.NewReaderSize(f, 1<<16)
	progressed := false
	for {
		chunk, err := r.ReadSlice('\n')
		cp.Offset += int64(len(chunk))
		if len(chunk) > 0 {
			progressed = true
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			*carry = append(*carry, chunk...)
			if len(*carry) > 1<<20 {
				em.Gap("line_too_long")
				*carry = nil
			}
			continue
		}
		*carry = append(*carry, chunk...)
		if err != nil { // EOF: a partial line waits for its newline
			return progressed, cp, nil
		}
		line := strings.TrimRight(string(bytes.TrimRight(*carry, "\r\n")), "\r\n")
		*carry = (*carry)[:0]
		if line != "" {
			em.Line(line)
		}
	}
}

// ExecSource runs a command that prints the log (for the Docker case: a fixed
// "docker exec <container> tail -n 0 -F <file>") and restarts it, with backoff, if it exits.
// There is no shell: Argv is executed directly.
type ExecSource struct {
	Argv    []string
	Backoff time.Duration // first restart delay; doubles up to 30 s
	OnStart func()        // called each time the command is started (for logs/tests)
}

func (es *ExecSource) Run(ctx context.Context, em Emitter) error {
	if len(es.Argv) == 0 {
		return errors.New("agent: empty source command")
	}
	delay := es.Backoff
	if delay <= 0 {
		delay = time.Second
	}
	first := delay
	for {
		start := time.Now()
		if es.OnStart != nil {
			es.OnStart()
		}
		cmd := exec.CommandContext(ctx, es.Argv[0], es.Argv[1:]...)
		out, err := cmd.StdoutPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err == nil {
			r := bufio.NewReaderSize(out, 1<<16)
			for {
				chunk, rerr := r.ReadSlice('\n')
				if errors.Is(rerr, bufio.ErrBufferFull) {
					for errors.Is(rerr, bufio.ErrBufferFull) { // skip the rest of an absurdly long line
						_, rerr = r.ReadSlice('\n')
					}
					em.Gap("line_too_long")
					continue
				}
				if len(chunk) > 0 && rerr == nil {
					if line := strings.TrimRight(string(chunk), "\r\n"); line != "" {
						em.Line(line)
					}
				}
				if rerr != nil {
					break
				}
			}
			_ = cmd.Wait()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		em.Gap("source_restart") // whatever the log held while the command was down is not seen
		if time.Since(start) > 30*time.Second {
			delay = first
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay *= 2; delay > 30*time.Second {
			delay = 30 * time.Second
		}
	}
}
