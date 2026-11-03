//go:build windows

package remotehelper

import (
	"archive/zip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// A folder is sent as one zip packed while it goes: nothing is written to the disk, and the browser receives the same
// chunks as for a file. The limits keep one click from emptying a disk into the browser's memory (the page holds a
// download until it is complete).
const (
	zipMaxFiles = 20000
	zipMaxBytes = 2 << 30 // total size of the files before compression
)

type zipItem struct {
	path string // on disk
	name string // inside the zip, with forward slashes
	info fs.FileInfo
}

// zipWalk lists what goes into the archive. Links and other irregular entries (junctions, mount points) are skipped,
// never followed: a link could lead out of the folder, or around in a circle. Files that cannot be read are skipped too
// and named in the archive itself, so the person can see what is missing.
func zipWalk(root string) (items []zipItem, total int64, skipped []string, err error) {
	base := filepath.Base(root)
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			skipped = append(skipped, p)
			return nil
		}
		if p == root {
			return nil
		}
		if d.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			skipped = append(skipped, p+" (ссылка)")
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			skipped = append(skipped, p)
			return nil
		}
		if !d.IsDir() && !info.Mode().IsRegular() {
			skipped = append(skipped, p+" (не обычный файл)")
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		items = append(items, zipItem{p, base + "/" + filepath.ToSlash(rel), info})
		if !d.IsDir() {
			total += info.Size()
		}
		if len(items) > zipMaxFiles {
			return errTooMany
		}
		if total > zipMaxBytes {
			return errTooBig
		}
		return nil
	})
	return
}

var (
	errTooMany = errors.New("в папке больше 20 000 файлов: скачайте её частями")
	errTooBig  = errors.New("папка больше 2 ГБ: скачайте её частями")
)

// zipFolder sends the folder p as a zip: the answer carries the size before compression (for the progress), then the
// archive follows in chunks.
func (s *fsSession) zipFolder(r fsRequest, p string) {
	items, total, skipped, err := zipWalk(p)
	if err != nil {
		s.reply(msgFsResult, fail(r.ID, err))
		return
	}
	s.reply(msgFsResult, fsResult{ID: r.ID, OK: true, Size: total, Path: p})
	w := &chunkWriter{s: s, id: r.ID, buf: make([]byte, 4, 4+fsChunk)}
	binary.BigEndian.PutUint32(w.buf, r.ID)
	zw := zip.NewWriter(w)
	err = writeZip(zw, items, skipped)
	if err == nil {
		err = zw.Close()
	}
	if err == nil {
		err = w.flush()
	}
	switch {
	case errors.Is(err, errStopped):
		s.reply(msgFsEnd, fsResult{ID: r.ID, Error: "остановлено"})
	case err != nil:
		s.reply(msgFsEnd, fail(r.ID, err))
	default:
		s.reply(msgFsEnd, fsResult{ID: r.ID, OK: true})
	}
}

func writeZip(zw *zip.Writer, items []zipItem, skipped []string) error {
	for _, it := range items {
		hdr, err := zip.FileInfoHeader(it.info)
		if err != nil {
			continue
		}
		hdr.Name = it.name
		if it.info.IsDir() {
			hdr.Name += "/"
			hdr.Method = zip.Store
			if _, err := zw.CreateHeader(hdr); err != nil {
				return err
			}
			continue
		}
		hdr.Method = zip.Deflate
		f, err := os.Open(it.path)
		if err != nil {
			skipped = append(skipped, it.path)
			continue
		}
		fw, err := zw.CreateHeader(hdr)
		if err == nil {
			_, err = io.Copy(fw, f)
		}
		f.Close()
		if err != nil {
			return err
		}
	}
	if len(skipped) > 0 {
		fw, err := zw.Create("owlery-пропущено.txt")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(fw, "Эти файлы не вошли в архив:\r\n%s\r\n", strings.Join(skipped, "\r\n"))
		return err
	}
	return nil
}

var errStopped = errors.New("stopped")

// chunkWriter turns the zip stream into the transfer's data messages, and stops when the browser cancels.
type chunkWriter struct {
	s   *fsSession
	id  uint32
	buf []byte // [4 bytes id][data]
}

func (w *chunkWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		room := 4 + fsChunk - len(w.buf)
		k := min(room, len(p))
		w.buf = append(w.buf, p[:k]...)
		p = p[k:]
		if len(w.buf) == 4+fsChunk {
			if err := w.flush(); err != nil {
				return 0, err
			}
		}
	}
	return n, nil
}

func (w *chunkWriter) flush() error {
	w.s.mu.Lock()
	stopped := w.s.stop[w.id]
	delete(w.s.stop, w.id)
	w.s.mu.Unlock()
	if stopped {
		return errStopped
	}
	if len(w.buf) > 4 {
		if err := writeMsg(w.s.c, msgFsData, w.buf); err != nil {
			return err
		}
		w.buf = w.buf[:4]
	}
	return nil
}
