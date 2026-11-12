package secagent

import (
	"errors"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

func TestHostBufferKeepsOneAMinuteAndSendsOldestFirstUntilAccepted(t *testing.T) {
	b := newHostBuffer(t.TempDir())
	t0 := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ { // thirty seconds apart: every second one is kept
		h := secproto.Host{Type: "host", At: t0.Add(time.Duration(i) * 30 * time.Second), Procs: []secproto.HostProc{{Name: "x", Count: 1}}}
		if err := b.Add(h); err != nil {
			t.Fatal(err)
		}
	}
	var got [][]secproto.Host
	fail := true
	err := b.Take(2, func(p []secproto.Host) error {
		if fail && len(got) == 1 {
			return errors.New("connection lost")
		}
		got = append(got, p)
		return nil
	})
	if err != nil || len(got) != 1 || len(got[0]) != 2 {
		t.Fatalf("%v %+v", err, got)
	}
	if got[0][0].Procs != nil || !got[0][0].At.Equal(t0) {
		t.Fatalf("the process list is left out and the oldest comes first: %+v", got[0][0])
	}
	fail = false
	got = nil
	if err := b.Take(10, func(p []secproto.Host) error { got = append(got, p); return nil }); err != nil || len(got) != 1 || len(got[0]) != 1 {
		t.Fatalf("what was not accepted must still be there: %v %+v", err, got)
	}
	if err := b.Take(10, func([]secproto.Host) error { t.Fatal("empty after a full send"); return nil }); err != nil {
		t.Fatal(err)
	}
}
