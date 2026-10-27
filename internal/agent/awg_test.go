package agent

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/ingestproto"
)

func TestParseAWGSnapshotReadsFactsAndIgnoresJunk(t *testing.T) {
	out := "I\tc1\tawg0\t49587\tJc,S3,S4,H1\n" +
		"P\tc1\tKEYA\t1760400000\t1000\t2000\t10.8.1.2/32\n" +
		"P\tc1\tKEYB\t0\t0\t0\t10.8.1.18/32,fd00::2/128\n" +
		"P\tc1\tKEYC\tnotanumber\t1\t2\t10.8.1.3/32\n" + // bad number: skipped
		"P\tunknown\tKEYD\t0\t0\t0\t-\n" + // peer of an instance that was not announced: skipped
		"N\tc1\tKEYA\tRouterOne\n" +
		"garbage line\n" +
		"X\tfoo\tbar\n"
	s := ParseAWGSnapshot(out)
	if s.Type != "awg" || len(s.Instances) != 1 {
		t.Fatalf("%+v", s)
	}
	in := s.Instances[0]
	if in.Container != "c1" || in.Interface != "awg0" || in.Port != 49587 || len(in.Fields) != 4 || len(in.Peers) != 2 {
		t.Fatalf("%+v", in)
	}
	a, b := in.Peers[0], in.Peers[1]
	if a.Key != "KEYA" || a.Name != "RouterOne" || a.RX != 1000 || a.TX != 2000 || a.Handshake != 1760400000 || a.IP != "10.8.1.2/32" {
		t.Fatalf("%+v", a)
	}
	if b.Name != "" || b.Handshake != 0 || b.IP != "10.8.1.18/32" {
		t.Fatalf("%+v", b)
	}
}

func TestParseAWGSnapshotOfNothingHasNoInstances(t *testing.T) {
	if s := ParseAWGSnapshot(""); len(s.Instances) != 0 {
		t.Fatal(s)
	}
}

func TestAWGSourceRunsTheHelperAndEmitsASnapshot(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	got := make(chan ingestproto.AWG, 1)
	src := &AWGSource{Argv: []string{sh, "-c", `printf 'I\tc1\tawg0\t1\tJc\nP\tc1\tKEYA\t0\t5\t6\t10.8.1.2/32\n'`}, Every: time.Hour,
		Emit: func(s ingestproto.AWG) { got <- s }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = src.Run(ctx, nil) }()
	select {
	case s := <-got:
		if len(s.Instances) != 1 || s.Instances[0].Peers[0].TX != 6 {
			t.Fatalf("%+v", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no snapshot")
	}
}

func TestAWGSourceStaysQuietWhenTheHelperFails(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	emitted := false
	src := &AWGSource{Argv: []string{sh, "-c", "exit 3"}, Emit: func(ingestproto.AWG) { emitted = true }}
	src.once(context.Background())
	if emitted {
		t.Fatal("a failing helper produced a snapshot")
	}
}

func TestParseAWGSnapshotCarriesWhatTheAmneziaPanelRecorded(t *testing.T) {
	out := "I\tc1\tawg0\t1\tJc\t1791353419\n" +
		"P\tc1\tKEYA\t0\t5\t6\t10.8.1.2/32\n" +
		"P\tc1\tKEYB\t0\t0\t0\t10.8.1.3/32\n" +
		"T\tc1\t1759400700\n" +
		"L\tc1\tKEYA\t106.76 GiB\t49.27 GiB\t4d, 3h, 14m, 18s ago\n" +
		"L\tc1\tKEYB\t\t\tNone\n"
	s := ParseAWGSnapshot(out)
	in := s.Instances[0]
	if in.Started != 1791353419 || in.LegacyAt != 1759400700 {
		t.Fatalf("%+v", in)
	}
	a := in.Peers[0]
	if a.LegacyDown != scaled(106.76, 1<<30) || a.LegacyUp != scaled(49.27, 1<<30) || a.LegacyHS != 1759400700-(4*86400+3*3600+14*60+18) {
		t.Fatalf("%+v", a)
	}
	if b := in.Peers[1]; b.LegacyDown != 0 || b.LegacyHS != 0 {
		t.Fatalf("a client the panel knew nothing about: %+v", b)
	}
}

func TestPanelTextsAreReadStrictly(t *testing.T) {
	for in, want := range map[string]int64{"1 KiB": 1024, "792.61 MiB": scaled(792.61, 1<<20), "2 GB": 2e9, "": 0, "None": 0, "x GiB": 0, "5 parsecs": 0, "-1 GiB": 0} {
		if got := parseSize(in); got != want {
			t.Errorf("size %q = %d, want %d", in, got, want)
		}
	}
	for in, want := range map[string]int64{"15s ago": 15, "4d, 3h, 14m, 18s ago": 4*86400 + 3*3600 + 14*60 + 18, "33d, 15h, 12m, 22s ago": 33*86400 + 15*3600 + 12*60 + 22, "None": -1, "": -1, "soon": -1, "5x ago": -1} {
		if got := parseAgo(in); got != want {
			t.Errorf("ago %q = %d, want %d", in, got, want)
		}
	}
}

// scaled does the multiplication at run time, as the parser does, so the same rounding applies.
func scaled(v float64, unit float64) int64 { return int64(v * unit) }

func TestParseCreatedReadsBothShapesOfTheOldTable(t *testing.T) {
	for in, want := range map[string]int64{
		"2026-04-03T10:01:05.979470": 1775210465,
		"2026-04-03T10:01:05":        1775210465,
		"Fri Aug 21 18:39:32 2026":   1787337572,
		"Mon Jun  8 14:51:53 2026":   1780930313,
		"":                           0,
		"yesterday":                  0,
	} {
		if got := parseCreated(in); got != want {
			t.Errorf("%q = %d, want %d", in, got, want)
		}
	}
}

func TestParseAWGSnapshotCarriesToolVersionsAndAContainerWithNoInterface(t *testing.T) {
	text := "V\tamnezia-awg2\t1.0.20210914\t3.1.20260812\nD\tamnezia-awg2\nV\tamnezia-awg3\t3.1.20260812\t3.1.20260812\n" +
		"I\tamnezia-awg3\tawg0\t55424\tJc,S3\t1760000000\n" +
		"V\tbad\tx; rm -rf /\t\n"
	snap := ParseAWGSnapshot(text)
	if len(snap.Containers) != 3 {
		t.Fatalf("%+v", snap.Containers)
	}
	c2, c3, bad := snap.Containers[0], snap.Containers[1], snap.Containers[2]
	if c2.Name != "amnezia-awg2" || c2.Tools != "1.0.20210914" || c2.Module != "3.1.20260812" || !c2.Down {
		t.Fatalf("%+v", c2)
	}
	if c3.Down || c3.Tools != c3.Module {
		t.Fatalf("a container with an interface is not down: %+v", c3)
	}
	if bad.Tools != "" || bad.Module != "" {
		t.Fatalf("a version that is not a version is dropped: %+v", bad)
	}
}
