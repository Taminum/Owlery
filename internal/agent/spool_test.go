package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustOpen(t *testing.T, dir string, max, start int64) *Spool {
	t.Helper()
	s, err := OpenSpool(dir, max, start)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestAppendReadAckRoundTrip(t *testing.T) {
	s := mustOpen(t, t.TempDir(), 1<<20, 1)
	for i := 1; i <= 5; i++ {
		seq, err := s.Append(fmt.Sprintf("line %d", i))
		if err != nil || seq != int64(i) {
			t.Fatalf("%d %v", seq, err)
		}
	}
	items, err := s.ReadFrom(1, 100, 1<<20)
	if err != nil || len(items) != 5 || items[0].Line != "line 1" || items[4].Seq != 5 {
		t.Fatalf("%+v %v", items, err)
	}
	items, _ = s.ReadFrom(3, 2, 1<<20)
	if len(items) != 2 || items[0].Seq != 3 || items[1].Seq != 4 {
		t.Fatalf("a bounded read from the middle: %+v", items)
	}
	if !s.Pending() {
		t.Fatal("unacked lines are pending")
	}
	_ = s.Ack(5)
	if s.Pending() || s.Bytes() != 0 {
		t.Fatalf("a fully acked spool is empty: pending=%v bytes=%d", s.Pending(), s.Bytes())
	}
	if seq, _ := s.Append("after"); seq != 6 {
		t.Fatalf("numbering continues after an ack: %d", seq)
	}
}

func TestNumberingAndContentSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir, 1<<20, 1)
	for i := 1; i <= 10; i++ {
		_, _ = s.Append(fmt.Sprintf("l%d", i))
	}
	_ = s.Ack(4)
	_ = s.Close()

	s2 := mustOpen(t, dir, 1<<20, 1)
	if s2.NextSeq() != 11 {
		t.Fatalf("next %d", s2.NextSeq())
	}
	items, _ := s2.ReadFrom(5, 100, 1<<20)
	if len(items) != 6 || items[0].Line != "l5" || items[5].Line != "l10" {
		t.Fatalf("%+v", items)
	}
	if seq, _ := s2.Append("l11"); seq != 11 {
		t.Fatalf("%d", seq)
	}
}

func TestTornTailFromACrashIsTrimmedNotTrusted(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir, 1<<20, 1)
	for i := 1; i <= 3; i++ {
		_, _ = s.Append(fmt.Sprintf("complete %d", i))
	}
	_ = s.Close()
	files, _ := filepath.Glob(filepath.Join(dir, "seg-*.log"))
	f, _ := os.OpenFile(files[0], os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.Write([]byte{0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 4, 'h', 'a', 'l', 'f'}) // header promises 50 bytes, 4 arrive
	_ = f.Close()

	s2 := mustOpen(t, dir, 1<<20, 1)
	items, _ := s2.ReadFrom(1, 100, 1<<20)
	if len(items) != 3 {
		t.Fatalf("only the 3 whole records may survive: %+v", items)
	}
	if seq, _ := s2.Append("fresh"); seq != 4 {
		t.Fatalf("numbering resumes right after the last whole record: %d", seq)
	}
	items, _ = s2.ReadFrom(4, 100, 1<<20)
	if len(items) != 1 || items[0].Line != "fresh" {
		t.Fatalf("%+v", items)
	}
}

func TestBoundedAndFailsLoudlyWhenFull(t *testing.T) {
	s := mustOpen(t, t.TempDir(), 400, 1)
	var stored int
	for i := 0; i < 50; i++ {
		if _, err := s.Append(strings.Repeat("x", 40)); err == nil {
			stored++
		} else if err != ErrSpoolFull {
			t.Fatal(err)
		}
	}
	if stored == 0 || stored >= 50 || s.Bytes() > 400 {
		t.Fatalf("stored %d, bytes %d: the cap must hold", stored, s.Bytes())
	}
	_ = s.Ack(int64(stored))
	if _, err := s.Append("room again"); err != nil {
		t.Fatalf("acknowledging frees space: %v", err)
	}
}

func TestSegmentsRotateAndAreDeletedOnlyWhenFullyAcked(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir, 64<<20, 1)
	big := strings.Repeat("y", 100_000)
	for i := 0; i < 120; i++ { // ~12 MB: several 4 MB segments
		if _, err := s.Append(big); err != nil {
			t.Fatal(err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(dir, "seg-*.log"))
	if len(files) < 3 {
		t.Fatalf("expected rotation, got %d segment(s)", len(files))
	}
	_ = s.Ack(50)
	after, _ := filepath.Glob(filepath.Join(dir, "seg-*.log"))
	if len(after) >= len(files) || len(after) == 0 {
		t.Fatalf("old segments go once acked: %d -> %d", len(files), len(after))
	}
	items, _ := s.ReadFrom(51, 1000, 1<<30)
	if len(items) != 70 || items[0].Seq != 51 {
		t.Fatalf("unacked lines must all remain readable: %d starting at %d", len(items), items[0].Seq)
	}
}

func TestReadWorksWhileWritingAndStartSeqIsUsedWhenEmpty(t *testing.T) {
	s := mustOpen(t, t.TempDir(), 1<<20, 500)
	if seq, _ := s.Append("a"); seq != 500 {
		t.Fatalf("an empty spool starts at the saved sequence: %d", seq)
	}
	items, _ := s.ReadFrom(500, 10, 1<<20) // unflushed data must still be visible to the shipper
	if len(items) != 1 || items[0].Line != "a" {
		t.Fatalf("%+v", items)
	}
}

func TestStateIsAtomicAndDamageMeansNewEpoch(t *testing.T) {
	dir := t.TempDir()
	st, fresh, err := LoadState(dir)
	if err != nil || !fresh || st.NextSeq != 1 || st.Epoch == "" {
		t.Fatalf("%+v %v %v", st, fresh, err)
	}
	st.NextSeq, st.Path, st.Offset = 42, "/var/log/xray/current", 1000
	if err := st.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, fresh, _ := LoadState(dir)
	if fresh || got.Epoch != st.Epoch || got.NextSeq != st.NextSeq || got.Path != st.Path || got.Offset != st.Offset {
		t.Fatalf("%+v vs %+v fresh=%v", got, st, fresh)
	}
	_ = os.WriteFile(filepath.Join(dir, "state.json"), []byte("{broken"), 0o600)
	again, fresh, err := LoadState(dir)
	if err != nil || !fresh || again.Epoch == st.Epoch {
		t.Fatalf("a damaged state must not be trusted: %+v fresh=%v", again, fresh)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json.tmp")); err == nil {
		t.Fatal("no temp file may be left behind")
	}
}

func TestPendingLossIsPersistedAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	st, _, _ := LoadState(dir)
	c := &Counters{}
	c.Drop("spool_full", 120)
	c.Drop("source_restart", 0)
	snap := c.Snapshot()
	st.PendingDropped, st.PendingGaps = snap.dropped, snap.gaps
	if err := st.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, fresh, _ := LoadState(dir)
	c2 := &Counters{}
	c2.Load(got.PendingDropped, got.PendingGaps)
	s2 := c2.Snapshot()
	if fresh || s2.dropped != 120 || len(s2.gaps) != 2 || s2.gaps[0].Reason != "spool_full" || s2.gaps[0].Lines != 120 {
		t.Fatalf("loss must survive a restart: %+v", s2)
	}
	c2.Confirm(s2)
	if c2.Pending() {
		t.Fatal("confirmed loss is cleared")
	}
}
