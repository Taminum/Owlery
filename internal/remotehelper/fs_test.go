//go:build windows

package remotehelper

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// reader pulls the helper's messages off the other end of the pipe.
func next(t *testing.T, c net.Conn) (byte, []byte) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	typ, p, err := readMsg(c)
	if err != nil {
		t.Fatal(err)
	}
	return typ, p
}

func TestUploadThenDownloadRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s := newFS(a)
	defer s.close()
	dir := t.TempDir()
	dst := filepath.Join(dir, "x.bin")
	data := bytes.Repeat([]byte("owlery"), 20000) // more than one chunk

	req := func(id uint32, extra map[string]any) []byte {
		m := map[string]any{"id": id}
		for k, v := range extra {
			m[k] = v
		}
		j, _ := json.Marshal(m)
		return j
	}
	go s.handle(msgFsPutBegin, req(1, map[string]any{"path": dst, "size": len(data)}))
	if typ, p := next(t, b); typ != msgFsResult || !bytes.Contains(p, []byte(`"ok":true`)) {
		t.Fatalf("begin: %d %s", typ, p)
	}
	for off := 0; off < len(data); off += fsChunk {
		end := min(off+fsChunk, len(data))
		chunk := append(binary.BigEndian.AppendUint32(nil, 1), data[off:end]...)
		s.handle(msgFsPutData, chunk)
	}
	go s.handle(msgFsPutEnd, req(1, nil))
	if typ, p := next(t, b); typ != msgFsEnd || !bytes.Contains(p, []byte(`"ok":true`)) {
		t.Fatalf("end: %d %s", typ, p)
	}
	if got, _ := os.ReadFile(dst); !bytes.Equal(got, data) {
		t.Fatal("the uploaded file differs")
	}
	// A second upload to the same name is refused unless it is allowed to overwrite.
	go s.handle(msgFsPutBegin, req(2, map[string]any{"path": dst, "size": 1}))
	if _, p := next(t, b); !bytes.Contains(p, []byte("уже есть")) {
		t.Fatalf("overwrite was not refused: %s", p)
	}
	// Download it back.
	go s.handle(msgFsGet, req(3, map[string]any{"path": dst}))
	if typ, p := next(t, b); typ != msgFsResult || !bytes.Contains(p, []byte(`"ok":true`)) {
		t.Fatalf("get: %d %s", typ, p)
	}
	var back []byte
	for {
		typ, p := next(t, b)
		if typ == msgFsData {
			back = append(back, p[4:]...)
			continue
		}
		if typ == msgFsEnd {
			break
		}
		t.Fatalf("unexpected message %d", typ)
	}
	if !bytes.Equal(back, data) {
		t.Fatal("the downloaded file differs")
	}
}

func TestListRefusesRelativePathsAndListsFoldersFirst(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s := newFS(a)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x"), 0o644)
	_ = os.Mkdir(filepath.Join(dir, "zdir"), 0o755)
	j, _ := json.Marshal(map[string]any{"id": 1, "path": "relative/path"})
	go s.handle(msgFsList, j)
	if _, p := next(t, b); !bytes.Contains(p, []byte("полный путь")) {
		t.Fatalf("%s", p)
	}
	j, _ = json.Marshal(map[string]any{"id": 2, "path": dir})
	go s.handle(msgFsList, j)
	_, p := next(t, b)
	var res fsResult
	if err := json.Unmarshal(p, &res); err != nil || len(res.Entries) != 2 || !res.Entries[0].Dir || res.Entries[1].Name != "a.txt" {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestFolderDownloadsAsZip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s := newFS(a)
	root := filepath.Join(t.TempDir(), "docs")
	_ = os.MkdirAll(filepath.Join(root, "sub"), 0o755)
	big := bytes.Repeat([]byte("owlery"), 30000)
	_ = os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "sub", "big.bin"), big, 0o644)
	j, _ := json.Marshal(map[string]any{"id": 7, "path": root, "zip": true})
	go s.handle(msgFsGet, j)
	if typ, p := next(t, b); typ != msgFsResult || !bytes.Contains(p, []byte(`"ok":true`)) {
		t.Fatalf("get: %d %s", typ, p)
	}
	var out []byte
	for {
		typ, p := next(t, b)
		if typ == msgFsData {
			out = append(out, p[4:]...)
			continue
		}
		if typ == msgFsEnd && bytes.Contains(p, []byte(`"ok":true`)) {
			break
		}
		t.Fatalf("unexpected message %d %s", typ, p)
	}
	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		got[f.Name], _ = io.ReadAll(rc)
		rc.Close()
	}
	if string(got["docs/a.txt"]) != "hello" || !bytes.Equal(got["docs/sub/big.bin"], big) {
		t.Fatalf("archive content is wrong: %d entries", len(got))
	}
	// Without the zip flag a folder is still refused.
	j, _ = json.Marshal(map[string]any{"id": 8, "path": root})
	go s.handle(msgFsGet, j)
	if _, p := next(t, b); !bytes.Contains(p, []byte("папка")) {
		t.Fatalf("%s", p)
	}
}
