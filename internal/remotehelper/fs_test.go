//go:build windows

package remotehelper

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
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
