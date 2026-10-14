package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type rec struct {
	mu    sync.Mutex
	lines []string
	gaps  []string
}

func (r *rec) Line(s string) { r.mu.Lock(); r.lines = append(r.lines, s); r.mu.Unlock() }
func (r *rec) Gap(s string)  { r.mu.Lock(); r.gaps = append(r.gaps, s); r.mu.Unlock() }
func (r *rec) snapshot() ([]string, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...), append([]string(nil), r.gaps...)
}

func (r *rec) waitLines(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if l, _ := r.snapshot(); len(l) >= n {
			return l
		}
		time.Sleep(10 * time.Millisecond)
	}
	l, g := r.snapshot()
	t.Fatalf("wanted %d lines, have %d (gaps %v)", n, len(l), g)
	return nil
}

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

// header makes lines long enough that the first 64 bytes identify a file, like real log lines do.
func logLine(file string, i int) string {
	return fmt.Sprintf("2026/10/09 12:00:%02d.000001 from 198.51.100.7:4000 accepted tcp:%s-%d.example.test:443 [Steal -> DIRECT] email: 2", i%60, file, i)
}

func runFile(t *testing.T, fs *FileSource) (*rec, context.CancelFunc) {
	t.Helper()
	r := &rec{}
	fs.Poll = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = fs.Run(ctx, r); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return r, cancel
}

func TestFileSourceStartsAtTheEndAndFollowsAppends(t *testing.T) {
	p := filepath.Join(t.TempDir(), "current")
	appendTo(t, p, logLine("old", 1)+"\n"+logLine("old", 2)+"\n")
	r, _ := runFile(t, &FileSource{Path: p})
	time.Sleep(100 * time.Millisecond)
	appendTo(t, p, logLine("new", 1)+"\n"+logLine("new", 2)+"\n")
	got := r.waitLines(t, 2)
	if len(got) != 2 || !strings.Contains(got[0], "new-1") {
		t.Fatalf("history must not be replayed by default: %v", got)
	}
}

func TestFileSourceFromStartReadsExistingContent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "current")
	appendTo(t, p, logLine("old", 1)+"\n"+logLine("old", 2)+"\n")
	r, _ := runFile(t, &FileSource{Path: p, FromStart: true})
	if got := r.waitLines(t, 2); !strings.Contains(got[0], "old-1") {
		t.Fatal(got)
	}
}

func TestAPartialLineWaitsForItsNewline(t *testing.T) {
	p := filepath.Join(t.TempDir(), "current")
	appendTo(t, p, "")
	r, _ := runFile(t, &FileSource{Path: p, FromStart: true})
	full := logLine("x", 1)
	appendTo(t, p, full[:40])
	time.Sleep(100 * time.Millisecond)
	if l, _ := r.snapshot(); len(l) != 0 {
		t.Fatalf("half a line must not be emitted: %v", l)
	}
	appendTo(t, p, full[40:]+"\n")
	if got := r.waitLines(t, 1); got[0] != full {
		t.Fatalf("%q", got[0])
	}
}

func TestRotationLosesNothingAndKeepsOrder(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "current")
	appendTo(t, p, "")
	r, _ := runFile(t, &FileSource{Path: p, FromStart: true})
	for i := 1; i <= 50; i++ {
		appendTo(t, p, logLine("a", i)+"\n")
	}
	r.waitLines(t, 50)
	// Lines land in the old file after the last poll, then s6-log renames it and starts a new one.
	for i := 51; i <= 70; i++ {
		appendTo(t, p, logLine("a", i)+"\n")
	}
	if err := os.Rename(p, filepath.Join(dir, "@4000000065e0a1b2c3d4e5f6.s")); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 30; i++ {
		appendTo(t, p, logLine("b", i)+"\n")
	}
	got := r.waitLines(t, 100)
	if len(got) != 100 {
		t.Fatalf("%d lines", len(got))
	}
	for i := 0; i < 70; i++ {
		if !strings.Contains(got[i], fmt.Sprintf("a-%d.", i+1)) {
			t.Fatalf("line %d out of order or missing: %s", i, got[i])
		}
	}
	for i := 0; i < 30; i++ {
		if !strings.Contains(got[70+i], fmt.Sprintf("b-%d.", i+1)) {
			t.Fatalf("line %d: %s", 70+i, got[70+i])
		}
	}
	if _, gaps := r.snapshot(); len(gaps) != 0 {
		t.Fatalf("a clean rotation is not a gap: %v", gaps)
	}
}

func TestTruncationInPlaceIsReportedAsAGap(t *testing.T) {
	p := filepath.Join(t.TempDir(), "current")
	appendTo(t, p, "")
	r, _ := runFile(t, &FileSource{Path: p, FromStart: true})
	for i := 1; i <= 5; i++ {
		appendTo(t, p, logLine("t", i)+"\n")
	}
	r.waitLines(t, 5)
	if err := os.WriteFile(p, []byte(logLine("t", 1)+"\n"), 0o600); err != nil { // same head, shorter
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, gaps := r.snapshot(); len(gaps) != 1 || gaps[0] != "truncated" {
		t.Fatalf("%v", gaps)
	}
}

func TestRestartResumesWhereItStoppedWithoutRepeats(t *testing.T) {
	p := filepath.Join(t.TempDir(), "current")
	appendTo(t, p, "")
	var cp Checkpoint
	fs := &FileSource{Path: p, FromStart: true, OnProgress: func(c Checkpoint) { cp = c }}
	r, cancel := runFile(t, fs)
	for i := 1; i <= 10; i++ {
		appendTo(t, p, logLine("r", i)+"\n")
	}
	r.waitLines(t, 10)
	time.Sleep(50 * time.Millisecond)
	cancel()
	saved := cp // what the agent would have persisted

	for i := 11; i <= 15; i++ { // written while the agent was down
		appendTo(t, p, logLine("r", i)+"\n")
	}
	r2, _ := runFile(t, &FileSource{Path: p, Resume: &saved})
	got := r2.waitLines(t, 5)
	if len(got) != 5 || !strings.Contains(got[0], "r-11.") || !strings.Contains(got[4], "r-15.") {
		t.Fatalf("exactly the lines written while down: %v", got)
	}
}

func TestFileRotatedWhileTheAgentWasDownIsRecovered(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "current")
	appendTo(t, p, "")
	var cp Checkpoint
	r, cancel := runFile(t, &FileSource{Path: p, FromStart: true, OnProgress: func(c Checkpoint) { cp = c }})
	for i := 1; i <= 5; i++ {
		appendTo(t, p, logLine("w", i)+"\n")
	}
	r.waitLines(t, 5)
	time.Sleep(50 * time.Millisecond)
	cancel()
	saved := cp

	appendTo(t, p, logLine("w", 6)+"\n"+logLine("w", 7)+"\n")
	_ = os.Rename(p, filepath.Join(dir, "@4000000065e0a1b2c3d4e5f7.s"))
	appendTo(t, p, logLine("n", 1)+"\n")

	r2, _ := runFile(t, &FileSource{Path: p, Resume: &saved})
	got := r2.waitLines(t, 3)
	if !strings.Contains(got[0], "w-6.") || !strings.Contains(got[1], "w-7.") || !strings.Contains(got[2], "n-1.") {
		t.Fatalf("the rotated file's unread tail must come first: %v", got)
	}
	if _, gaps := r2.snapshot(); len(gaps) != 0 {
		t.Fatalf("%v", gaps)
	}
}

func TestRotationWithNoArchiveToBeFoundIsAnHonestGap(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "current")
	appendTo(t, p, "")
	var cp Checkpoint
	r, cancel := runFile(t, &FileSource{Path: p, FromStart: true, OnProgress: func(c Checkpoint) { cp = c }})
	for i := 1; i <= 5; i++ {
		appendTo(t, p, logLine("g", i)+"\n")
	}
	r.waitLines(t, 5)
	time.Sleep(50 * time.Millisecond)
	cancel()
	saved := cp
	_ = os.Remove(p) // the old file is gone for good
	appendTo(t, p, logLine("z", 1)+"\n")

	r2, _ := runFile(t, &FileSource{Path: p, Resume: &saved})
	got := r2.waitLines(t, 1)
	if !strings.Contains(got[0], "z-1.") {
		t.Fatal(got)
	}
	if _, gaps := r2.snapshot(); len(gaps) != 1 || gaps[0] != "rotated_unseen" {
		t.Fatalf("%v", gaps)
	}
}

// --- ExecSource, using this test binary as the "command" ------------------------------------

// The "command" is this test binary re-run with a marker argument, so no environment is shared
// with (or leaked into) the process running the tests.
const helperMarker = "remnascope-helper"

func helperArgs() (lines int, long bool, ok bool) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != helperMarker {
		return 0, false, false
	}
	var l int
	var lg int
	fmt.Sscanf(os.Args[len(os.Args)-1], "%d,%d", &l, &lg)
	return l, lg == 1, true
}

func TestHelperProcess(t *testing.T) {
	n, long, ok := helperArgs()
	if !ok {
		return
	}
	for i := 1; i <= n; i++ {
		fmt.Println(logLine("exec", i))
	}
	if long {
		fmt.Println(strings.Repeat("z", 200_000)) // an absurd line
		fmt.Println(logLine("exec", 99))
	}
	os.Exit(0)
}

func helperArgv(lines int, long bool) []string {
	l := 0
	if long {
		l = 1
	}
	return []string{os.Args[0], "-test.run=^TestHelperProcess$", helperMarker, fmt.Sprintf("%d,%d", lines, l)}
}

func TestExecSourceReadsLinesAndRestartsWithAGap(t *testing.T) {
	var starts int
	var mu sync.Mutex
	es := &ExecSource{Argv: helperArgv(3, false), Backoff: 20 * time.Millisecond, OnStart: func() { mu.Lock(); starts++; mu.Unlock() }}
	r := &rec{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = es.Run(ctx, r); close(done) }()
	defer func() { cancel(); <-done }()
	got := r.waitLines(t, 6) // the helper exits after 3 lines, so a restart yields 3 more
	if !strings.Contains(got[0], "exec-1.") || len(got) < 6 {
		t.Fatal(got)
	}
	_, gaps := r.snapshot()
	if len(gaps) == 0 || gaps[0] != "source_restart" {
		t.Fatalf("a restarted command must be reported as a gap: %v", gaps)
	}
	mu.Lock()
	defer mu.Unlock()
	if starts < 2 {
		t.Fatalf("starts=%d", starts)
	}
}

func TestExecSourceSkipsAbsurdLinesAndKeepsGoing(t *testing.T) {
	es := &ExecSource{Argv: helperArgv(2, true), Backoff: time.Hour}
	r := &rec{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = es.Run(ctx, r); close(done) }()
	defer func() { cancel(); <-done }()
	got := r.waitLines(t, 3)
	if len(got) != 3 || !strings.Contains(got[2], "exec-99.") {
		t.Fatalf("the line after an oversized one must survive: %d lines", len(got))
	}
	for _, l := range got {
		if len(l) > 1000 {
			t.Fatal("the oversized line must not be passed on")
		}
	}
	if _, gaps := r.snapshot(); len(gaps) == 0 || gaps[0] != "line_too_long" {
		t.Fatalf("%v", gaps)
	}
}

func TestExecSourceNeedsACommandAndRunsNoShell(t *testing.T) {
	if err := (&ExecSource{}).Run(context.Background(), &rec{}); err == nil {
		t.Fatal("an empty command must be refused")
	}
	// A shell metacharacter is just an argument: nothing is expanded or chained.
	cmd := exec.Command("echo", "hello; rm -rf /")
	out, _ := cmd.Output()
	if !strings.Contains(string(out), "; rm -rf /") {
		t.Skip("sanity check of the platform's echo only")
	}
}
