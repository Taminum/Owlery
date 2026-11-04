package seccollect

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

// winScript answers wevtutil and PowerShell the way a Windows machine would, from what a test put in it.
type winScript struct {
	logs   map[string][]string // log name -> events as XML, oldest first
	status string              // what the Defender script prints
	deny   bool
	calls  int
}

func evXML(id int, rec int64, at string, data map[string]string) string {
	var d strings.Builder
	for k, v := range data {
		fmt.Fprintf(&d, `<Data Name="%s">%s</Data>`, k, v)
	}
	return fmt.Sprintf(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>%d</EventID><TimeCreated SystemTime="%s"/><EventRecordID>%d</EventRecordID></System><EventData>%s</EventData></Event>`, id, at, rec, d.String())
}

func (s *winScript) Run(_ context.Context, name string, args ...string) Result {
	s.calls++
	if name == "powershell.exe" {
		return Result{Stdout: s.status}
	}
	if s.deny {
		return Result{ExitCode: 5, Stderr: "Отказано в доступе."}
	}
	log := args[1]
	events, ok := s.logs[log]
	if !ok {
		return Result{ExitCode: 15007, Stderr: "The specified channel could not be found."}
	}
	var min int64
	newest := false
	for _, a := range args {
		if a == "/rd:true" {
			newest = true
		}
		if i := strings.Index(a, "EventRecordID>"); i >= 0 {
			fmt.Sscanf(strings.TrimRight(a[i+len("EventRecordID>"):], "]"), "%d", &min)
		}
	}
	var out []string
	for _, e := range events {
		var rec int64
		fmt.Sscanf(e[strings.Index(e, "<EventRecordID>")+len("<EventRecordID>"):], "%d", &rec)
		if rec > min {
			out = append(out, e)
		}
	}
	if newest {
		if len(events) == 0 {
			return Result{}
		}
		return Result{Stdout: events[len(events)-1]}
	}
	return Result{Stdout: strings.Join(out, "\n")}
}

func TestWinsecCountsRemoteSignInsAndLeavesTheRestAlone(t *testing.T) {
	s := &winScript{logs: map[string][]string{
		secLog: {evXML(100, 100, "2026-11-03T10:00:00Z", map[string]string{"LogonType": "2", "IpAddress": "-"})},
		defLog: {evXML(1000, 1000, "2026-11-03T10:00:00Z", nil)},
	}, status: `{"e":true,"r":true,"a":1}`}
	w := NewWinsec(s)
	w.now = func() time.Time { return time.Date(2026, 11, 3, 10, 5, 0, 0, time.UTC) }

	// The first read only finds where "now" is: what was already in the log is not counted.
	snap := w.Collect(context.Background())
	got := snap.Data.(secproto.Winsec)
	if snap.Status != secproto.StatusOK || got.RemoteFailed != 0 || got.RemoteOK != 0 || !got.Defender.Present || !got.Defender.Realtime || got.Defender.SignatureDays != 1 {
		t.Fatalf("first: %s %+v", snap.Status, got)
	}

	s.logs[secLog] = append(s.logs[secLog],
		evXML(4625, 101, "2026-11-03T10:01:00Z", map[string]string{"LogonType": "3", "IpAddress": "198.51.100.7", "TargetUserName": "admin"}),
		evXML(4625, 102, "2026-11-03T10:01:01Z", map[string]string{"LogonType": "10", "IpAddress": "198.51.100.7"}),
		evXML(4625, 103, "2026-11-03T10:01:02Z", map[string]string{"LogonType": "3", "IpAddress": "203.0.113.9"}),
		evXML(4625, 104, "2026-11-03T10:01:03Z", map[string]string{"LogonType": "2", "IpAddress": "198.51.100.8"}), // at the keyboard
		evXML(4625, 105, "2026-11-03T10:01:04Z", map[string]string{"LogonType": "3", "IpAddress": "-"}),            // no address
		evXML(4625, 106, "2026-11-03T10:01:05Z", map[string]string{"LogonType": "3", "IpAddress": "::1"}),          // this machine
		evXML(4624, 107, "2026-11-03T10:02:00Z", map[string]string{"LogonType": "10", "IpAddress": "198.51.100.20", "TargetUserName": "Administrator"}),
		evXML(4624, 108, "2026-11-03T10:02:01Z", map[string]string{"LogonType": "3", "IpAddress": "198.51.100.21", "TargetUserName": "bob"}),    // a network sign-in is not remote desktop
		evXML(4624, 109, "2026-11-03T10:02:02Z", map[string]string{"LogonType": "10", "IpAddress": "198.51.100.22", "TargetUserName": "WS01$"}), // a machine account
	)
	s.logs[defLog] = append(s.logs[defLog],
		evXML(1116, 1001, "2026-11-03T10:03:00Z", map[string]string{"Threat Name": "Trojan:Win32/Test", "Severity Name": "Severe", "Path": `C:\x.exe`}),
		evXML(1117, 1002, "2026-11-03T10:03:01Z", nil))
	snap = w.Collect(context.Background())
	got = snap.Data.(secproto.Winsec)
	if got.RemoteFailed != 3 || got.RemoteOK != 1 {
		t.Fatalf("counts: failed %d ok %d", got.RemoteFailed, got.RemoteOK)
	}
	if len(got.Sources) != 2 || got.Sources[0].IP != "198.51.100.7" || got.Sources[0].Failed != 2 {
		t.Errorf("sources: %+v", got.Sources)
	}
	if len(got.RecentOK) != 1 || got.RecentOK[0].User != "Administrator" || got.RecentOK[0].IP != "198.51.100.20" {
		t.Errorf("recent: %+v", got.RecentOK)
	}
	if got.ThreatsTotal != 1 || len(got.Threats) != 1 || got.Threats[0].Name != "Trojan:Win32/Test" || got.Threats[0].Severity != "Severe" {
		t.Errorf("threats: %+v", got.Threats)
	}

	// Nothing new: the counters stay put and an old event is not counted twice.
	snap = w.Collect(context.Background())
	if again := snap.Data.(secproto.Winsec); again.RemoteFailed != 3 || again.ThreatsTotal != 1 {
		t.Errorf("repeat: %+v", again)
	}
}

func TestWinsecSaysWhenItMayNotReadTheLogAndWhenDefenderIsNotThere(t *testing.T) {
	denied := NewWinsec(&winScript{deny: true})
	if snap := denied.Collect(context.Background()); snap.Status != secproto.StatusPermissionDenied || snap.Data != nil {
		t.Errorf("denied: %s %v", snap.Status, snap.Data)
	}

	// Another antivirus: the Defender log is not there and the status command prints "none".
	w := NewWinsec(&winScript{logs: map[string][]string{secLog: {evXML(1, 1, "2026-11-03T10:00:00Z", nil)}}, status: "none"})
	snap := w.Collect(context.Background())
	if d := snap.Data.(secproto.Winsec).Defender; snap.Status != secproto.StatusOK || d.Present {
		t.Errorf("no defender: %s %+v", snap.Status, d)
	}
}
