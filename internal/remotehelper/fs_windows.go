//go:build windows

package remotehelper

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

// Files go over the same channel as the screen, so they are available only while a session is open (and the tray icon
// says so), and they are reached with the helper's own rights — the system account's, like the terminal's. Every
// request carries an id chosen by the browser so that several can be in flight; a download streams in chunks.
const (
	msgFsList     = 0x0C // browser -> helper: JSON {"id","path"}; an empty path lists the drives
	msgFsGet      = 0x0D // browser -> helper: JSON {"id","path"}: send this file
	msgFsPutBegin = 0x0E // browser -> helper: JSON {"id","path","size","overwrite"}: receive a file
	msgFsPutData  = 0x0F // browser -> helper: [4 bytes id][file bytes]
	msgFsPutEnd   = 0x10 // browser -> helper: JSON {"id"}: the file is complete
	msgFsCancel   = 0x11 // browser -> helper: JSON {"id"}: stop this upload or download
	msgFsResult   = 0x12 // helper -> browser: JSON, the answer to a list, the start of a download or of an upload
	msgFsData     = 0x13 // helper -> browser: [4 bytes id][file bytes]
	msgFsEnd      = 0x14 // helper -> browser: JSON {"id","ok","error"}: the download or the upload is over
)

const (
	fsChunk      = 48 << 10
	fsMaxEntries = 5000
	fsMaxFile    = 4 << 30 // refuse anything bigger than 4 GB either way
)

type fsRequest struct {
	ID        uint32 `json:"id"`
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	Overwrite bool   `json:"overwrite"`
}

type fsEntry struct {
	Name string `json:"n"`
	Dir  bool   `json:"d,omitempty"`
	Size int64  `json:"s,omitempty"`
	Time int64  `json:"t,omitempty"` // modification time, Unix seconds
}

type fsResult struct {
	ID      uint32    `json:"id"`
	OK      bool      `json:"ok"`
	Error   string    `json:"error,omitempty"`
	Path    string    `json:"path,omitempty"`
	Home    string    `json:"home,omitempty"` // the signed-in person's Downloads folder, for a default upload target
	Entries []fsEntry `json:"entries,omitempty"`
	Size    int64     `json:"size,omitempty"`
}

// fsSession is the state of one screen session's file transfers.
type fsSession struct {
	c    net.Conn
	mu   sync.Mutex
	puts map[uint32]*put
	stop map[uint32]bool // downloads asked to stop
}

type put struct {
	f        *os.File
	tmp, dst string
	want     int64
	got      int64
}

func newFS(c net.Conn) *fsSession {
	return &fsSession{c: c, puts: map[uint32]*put{}, stop: map[uint32]bool{}}
}

// close drops the half-written uploads of a session that ended.
func (s *fsSession) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, p := range s.puts {
		p.f.Close()
		_ = os.Remove(p.tmp)
		delete(s.puts, id)
	}
}

func (s *fsSession) reply(typ byte, v any) {
	b, err := json.Marshal(v)
	if err == nil {
		_ = writeMsg(s.c, typ, b)
	}
}

func fail(id uint32, err error) fsResult { return fsResult{ID: id, Error: friendly(err)} }

// friendly turns a file error into a short message for the person, without the machine's full paths repeated.
func friendly(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "нет такого файла или папки"
	case errors.Is(err, os.ErrPermission):
		return "нет доступа"
	case errors.Is(err, os.ErrExist):
		return "файл уже есть"
	}
	return err.Error()
}

// handle takes one file message from the browser. Anything slow runs apart so that the mouse and keyboard keep going.
func (s *fsSession) handle(typ byte, payload []byte) {
	if typ == msgFsPutData {
		s.putData(payload)
		return
	}
	var r fsRequest
	if json.Unmarshal(payload, &r) != nil {
		return
	}
	switch typ {
	case msgFsList:
		go s.list(r)
	case msgFsGet:
		go s.get(r)
	case msgFsPutBegin:
		s.putBegin(r)
	case msgFsPutEnd:
		s.putEnd(r.ID)
	case msgFsCancel:
		s.mu.Lock()
		s.stop[r.ID] = true
		if p := s.puts[r.ID]; p != nil {
			p.f.Close()
			_ = os.Remove(p.tmp)
			delete(s.puts, r.ID)
		}
		s.mu.Unlock()
	}
}

// userDownloads is the signed-in person's Downloads folder, found through the console session's own token because the
// helper's profile is the system account's.
func userDownloads() string {
	var tok windows.Token
	if err := windows.WTSQueryUserToken(windows.WTSGetActiveConsoleSessionId(), &tok); err != nil {
		return ""
	}
	defer tok.Close()
	home, err := tok.GetUserProfileDirectory()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "Downloads")
}

func (s *fsSession) list(r fsRequest) {
	res := fsResult{ID: r.ID, Home: userDownloads()}
	if r.Path == "" {
		mask, _ := windows.GetLogicalDrives()
		for i := 0; i < 26; i++ {
			if mask&(1<<i) != 0 {
				res.Entries = append(res.Entries, fsEntry{Name: fmt.Sprintf("%c:\\", 'A'+i), Dir: true})
			}
		}
		res.OK = true
		s.reply(msgFsResult, res)
		return
	}
	p, err := cleanPath(r.Path)
	if err != nil {
		s.reply(msgFsResult, fail(r.ID, err))
		return
	}
	des, err := os.ReadDir(p)
	if err != nil {
		s.reply(msgFsResult, fail(r.ID, err))
		return
	}
	for _, de := range des {
		if len(res.Entries) >= fsMaxEntries {
			break
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		res.Entries = append(res.Entries, fsEntry{Name: de.Name(), Dir: de.IsDir(), Size: info.Size(), Time: info.ModTime().Unix()})
	}
	// Folders first, then by name.
	sort.SliceStable(res.Entries, func(i, j int) bool {
		a, b := res.Entries[i], res.Entries[j]
		if a.Dir != b.Dir {
			return a.Dir
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	res.Path, res.OK = p, true
	s.reply(msgFsResult, res)
}

// cleanPath accepts only an absolute Windows path, cleaned.
func cleanPath(p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", errors.New("нужен полный путь")
	}
	return filepath.Clean(p), nil
}

func (s *fsSession) get(r fsRequest) {
	p, err := cleanPath(r.Path)
	if err != nil {
		s.reply(msgFsResult, fail(r.ID, err))
		return
	}
	f, err := os.Open(p)
	if err != nil {
		s.reply(msgFsResult, fail(r.ID, err))
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		s.reply(msgFsResult, fail(r.ID, errors.New("это папка")))
		return
	}
	if st.Size() > fsMaxFile {
		s.reply(msgFsResult, fail(r.ID, errors.New("файл больше 4 ГБ")))
		return
	}
	s.reply(msgFsResult, fsResult{ID: r.ID, OK: true, Size: st.Size(), Path: p})
	buf := make([]byte, 4+fsChunk)
	binary.BigEndian.PutUint32(buf, r.ID)
	for {
		s.mu.Lock()
		stopped := s.stop[r.ID]
		delete(s.stop, r.ID)
		s.mu.Unlock()
		if stopped {
			s.reply(msgFsEnd, fsResult{ID: r.ID, Error: "остановлено"})
			return
		}
		n, err := f.Read(buf[4:])
		if n > 0 {
			if writeMsg(s.c, msgFsData, buf[:4+n]) != nil {
				return
			}
		}
		if err == io.EOF {
			s.reply(msgFsEnd, fsResult{ID: r.ID, OK: true})
			return
		}
		if err != nil {
			s.reply(msgFsEnd, fail(r.ID, err))
			return
		}
	}
}

func (s *fsSession) putBegin(r fsRequest) {
	p, err := cleanPath(r.Path)
	if err != nil {
		s.reply(msgFsResult, fail(r.ID, err))
		return
	}
	if r.Size < 0 || r.Size > fsMaxFile {
		s.reply(msgFsResult, fail(r.ID, errors.New("файл больше 4 ГБ")))
		return
	}
	if _, err := os.Stat(p); err == nil && !r.Overwrite {
		s.reply(msgFsResult, fail(r.ID, os.ErrExist))
		return
	}
	tmp := p + ".owlery-part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		s.reply(msgFsResult, fail(r.ID, err))
		return
	}
	s.mu.Lock()
	s.puts[r.ID] = &put{f: f, tmp: tmp, dst: p, want: r.Size}
	s.mu.Unlock()
	s.reply(msgFsResult, fsResult{ID: r.ID, OK: true, Path: p})
}

func (s *fsSession) putData(payload []byte) {
	if len(payload) < 4 {
		return
	}
	id := binary.BigEndian.Uint32(payload)
	s.mu.Lock()
	p := s.puts[id]
	s.mu.Unlock()
	if p == nil {
		return
	}
	n, err := p.f.Write(payload[4:])
	p.got += int64(n)
	if err != nil || p.got > p.want {
		p.f.Close()
		_ = os.Remove(p.tmp)
		s.mu.Lock()
		delete(s.puts, id)
		s.mu.Unlock()
		s.reply(msgFsEnd, fail(id, errors.New("не удалось записать файл")))
	}
}

func (s *fsSession) putEnd(id uint32) {
	s.mu.Lock()
	p := s.puts[id]
	delete(s.puts, id)
	s.mu.Unlock()
	if p == nil {
		return
	}
	if err := p.f.Close(); err != nil || p.got != p.want {
		_ = os.Remove(p.tmp)
		s.reply(msgFsEnd, fail(id, errors.New("файл пришёл не целиком")))
		return
	}
	_ = os.Remove(p.dst) // an overwrite was agreed to when the upload began
	if err := os.Rename(p.tmp, p.dst); err != nil {
		_ = os.Remove(p.tmp)
		s.reply(msgFsEnd, fail(id, err))
		return
	}
	s.reply(msgFsEnd, fsResult{ID: id, OK: true, Path: p.dst})
}
