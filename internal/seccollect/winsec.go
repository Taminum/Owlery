package seccollect

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/consoletext"
	"github.com/Taminum/Owlery/internal/ipblock"
	"github.com/Taminum/Owlery/internal/secproto"
)

// Winsec reads what Windows says about sign-ins from other machines (the Security log) and about Defender (its
// status and its detections). It only reads, through wevtutil and PowerShell started without a shell. The counters
// count from the moment it was made, so a snapshot is only meaningful next to the one before it: the server subtracts.
type Winsec struct {
	run  Runner
	now  func() time.Time
	secN int64 // newest Security event already counted; 0 until the first read
	defN int64 // the same for Defender's log
	idle int

	failed, ok, threatsTotal int64
	sources                  map[string]int
	recentOK                 []secproto.WinLogon
	threats                  []secproto.WinThreat
	defender                 secproto.WinDefender
	defAt                    time.Time
	defOK                    bool // the Defender log exists on this machine
	block                    *ipblock.Engine
}

const (
	secLog           = "Security"
	defLog           = "Microsoft-Windows-Windows Defender/Operational"
	maxEventsPerRead = 500
	defenderEvery    = 5 * time.Minute
	maxSources       = 2000
)

// SetBlocker gives the reader an address blocker to feed with what it sees in the log. Without one it only counts.
func (w *Winsec) SetBlocker(b *ipblock.Engine) { w.block = b }

// NewWinsec makes a reader that runs commands through r. Tests give it a scripted one.
func NewWinsec(r Runner) *Winsec {
	return &Winsec{run: r, now: time.Now, sources: map[string]int{}, defender: secproto.WinDefender{SignatureDays: -1}, defOK: true}
}

type winEvent struct {
	ID   int
	Rec  int64
	At   time.Time
	Data map[string]string
}

type winEventXML struct {
	System struct {
		ID   int `xml:"EventID"`
		Time struct {
			At string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Rec int64 `xml:"EventRecordID"`
	} `xml:"System"`
	Data []struct {
		Name string `xml:"Name,attr"`
		V    string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

// parseEvents reads the XML wevtutil prints: a run of <Event> elements with no root around them.
func parseEvents(out string) []winEvent {
	var wrapped struct {
		Events []winEventXML `xml:"Event"`
	}
	if err := xml.Unmarshal([]byte("<Events>"+toUTF8(out)+"</Events>"), &wrapped); err != nil {
		return nil
	}
	evs := make([]winEvent, 0, len(wrapped.Events))
	for _, e := range wrapped.Events {
		ev := winEvent{ID: e.System.ID, Rec: e.System.Rec, Data: map[string]string{}}
		ev.At, _ = time.Parse(time.RFC3339Nano, e.System.Time.At)
		for _, d := range e.Data {
			ev.Data[d.Name] = strings.TrimSpace(d.V)
		}
		evs = append(evs, ev)
	}
	return evs
}

// toUTF8 makes what wevtutil printed fit for an XML parser (see consoletext).
func toUTF8(s string) string { return consoletext.ToUTF8(s) }

var recordIDRe = regexp.MustCompile(`<EventRecordID>(\d+)</EventRecordID>`)

// highestRecord finds the biggest record number in text that could not be parsed, so a bad batch is skipped over
// instead of being read again forever.
func highestRecord(out string) int64 {
	var hi int64
	for _, m := range recordIDRe.FindAllStringSubmatch(out, -1) {
		if n, err := strconv.ParseInt(m[1], 10, 64); err == nil && n > hi {
			hi = n
		}
	}
	return hi
}

// remoteAddr says whether s is the address of another machine: empty, "-", loopback and unspecified are not.
func remoteAddr(s string) (string, bool) {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() {
		return "", false
	}
	return ip.String(), true
}

func (w *Winsec) query(ctx context.Context, log, filter string, count int) (Result, []winEvent) {
	args := []string{"qe", log, "/f:xml", "/c:" + strconv.Itoa(count)}
	if filter != "" {
		args = append(args, "/q:"+filter)
	}
	res := w.run.Run(ctx, "wevtutil", args...)
	if res.Err != nil || res.ExitCode != 0 {
		return res, nil
	}
	return res, parseEvents(res.Stdout)
}

// newest asks for the latest event of a log, whatever it is, to know where "now" is.
func (w *Winsec) newest(ctx context.Context, log string) (int64, Result) {
	res := w.run.Run(ctx, "wevtutil", "qe", log, "/f:xml", "/c:1", "/rd:true")
	if res.Err != nil || res.ExitCode != 0 {
		return 0, res
	}
	evs := parseEvents(res.Stdout)
	if len(evs) == 0 {
		return 1, res // an empty log: anything that comes later has a higher number
	}
	return evs[0].Rec, res
}

func (w *Winsec) readSecurity(ctx context.Context) (denied bool, failed bool) {
	if w.secN == 0 {
		n, res := w.newest(ctx, secLog)
		if n == 0 {
			return winDenied(res), true
		}
		w.secN = n
		return false, false
	}
	filter := "*[System[(EventID=4625 or EventID=4624) and EventRecordID>" + strconv.FormatInt(w.secN, 10) + "]]"
	res, evs := w.query(ctx, secLog, filter, maxEventsPerRead)
	if res.Err != nil || res.ExitCode != 0 {
		return winDenied(res), true
	}
	for _, e := range evs {
		if e.Rec > w.secN {
			w.secN = e.Rec
		}
		w.count(ctx, e)
	}
	// Text came back but nothing could be read from it: step over it rather than meet the same batch every time.
	if len(evs) == 0 && strings.TrimSpace(res.Stdout) != "" {
		if hi := highestRecord(res.Stdout); hi > w.secN {
			w.secN = hi
		}
	}
	// A cleared log starts numbering again; when nothing new came for a while, check that our place still exists.
	if len(evs) == 0 {
		if w.idle++; w.idle >= 20 {
			w.idle = 0
			if n, _ := w.newest(ctx, secLog); n > 0 && n < w.secN {
				w.secN = n
			}
		}
	} else {
		w.idle = 0
	}
	return false, false
}

func (w *Winsec) count(ctx context.Context, e winEvent) {
	lt := e.Data["LogonType"]
	ip, remote := remoteAddr(e.Data["IpAddress"])
	switch e.ID {
	case 4625:
		if !remote || (lt != "3" && lt != "10") {
			return
		}
		w.failed++
		w.sources[ip]++
		if len(w.sources) > maxSources {
			w.trimSources()
		}
		if w.block != nil {
			w.block.Fail(ctx, ip, e.At)
		}
	case 4624:
		user := e.Data["TargetUserName"]
		if !remote || user == "" || strings.HasSuffix(user, "$") || strings.EqualFold(user, "ANONYMOUS LOGON") {
			return
		}
		// Somebody really signed in from there, over the network or remote desktop: that address is a person's.
		if w.block != nil && (lt == "3" || lt == "10") {
			w.block.OK(ip, e.At)
		}
		if lt != "10" {
			return
		}
		w.ok++
		w.recentOK = append([]secproto.WinLogon{{ID: e.Rec, User: user, IP: ip, At: e.At}}, w.recentOK...)
		if len(w.recentOK) > secproto.MaxWinsecRecent {
			w.recentOK = w.recentOK[:secproto.MaxWinsecRecent]
		}
	}
}

func (w *Winsec) trimSources() {
	type kv struct {
		ip string
		n  int
	}
	all := make([]kv, 0, len(w.sources))
	for ip, n := range w.sources {
		all = append(all, kv{ip, n})
	}
	sort.Slice(all, func(a, b int) bool { return all[a].n > all[b].n || (all[a].n == all[b].n && all[a].ip < all[b].ip) })
	w.sources = map[string]int{}
	for _, x := range all[:maxSources/2] {
		w.sources[x.ip] = x.n
	}
}

func (w *Winsec) readDefenderLog(ctx context.Context) {
	if !w.defOK {
		return
	}
	if w.defN == 0 {
		n, res := w.newest(ctx, defLog)
		if n == 0 {
			if res.Err != nil || res.ExitCode != 0 {
				w.defOK = false // no such log here: Defender is not in use
			}
			return
		}
		w.defN = n
		return
	}
	filter := "*[System[(EventID=1116 or EventID=1117) and EventRecordID>" + strconv.FormatInt(w.defN, 10) + "]]"
	res, evs := w.query(ctx, defLog, filter, 100)
	if res.Err != nil || res.ExitCode != 0 {
		return
	}
	for _, e := range evs {
		if e.Rec > w.defN {
			w.defN = e.Rec
		}
		if e.ID != 1116 { // 1116 is "found", 1117 is "acted"; one entry per find is enough
			continue
		}
		w.threatsTotal++
		w.threats = append([]secproto.WinThreat{{ID: e.Rec, Name: cut(e.Data["Threat Name"], 120), Severity: cut(e.Data["Severity Name"], 32), Path: cut(e.Data["Path"], 200), At: e.At}}, w.threats...)
		if len(w.threats) > secproto.MaxWinsecRecent {
			w.threats = w.threats[:secproto.MaxWinsecRecent]
		}
	}
}

func cut(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

const defenderScript = `[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); try { $s = Get-MpComputerStatus -ErrorAction Stop; ConvertTo-Json -Compress @{ e = [bool]$s.AntivirusEnabled; r = [bool]$s.RealTimeProtectionEnabled; a = [int]$s.AntivirusSignatureAge } } catch { 'none' }`

func (w *Winsec) readDefenderStatus(ctx context.Context, now time.Time) {
	if !w.defAt.IsZero() && now.Sub(w.defAt) < defenderEvery {
		return
	}
	w.defAt = now
	res := w.run.Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", defenderScript)
	if res.Err != nil || res.ExitCode != 0 {
		return // keep what was known
	}
	var v struct {
		E bool `json:"e"`
		R bool `json:"r"`
		A int  `json:"a"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(res.Stdout)), &v); err != nil {
		w.defender = secproto.WinDefender{SignatureDays: -1} // "none", or something unreadable: not in use here
		return
	}
	w.defender = secproto.WinDefender{Present: true, Enabled: v.E, Realtime: v.R, SignatureDays: v.A}
}

// Collect reads everything new and returns the snapshot.
func (w *Winsec) Collect(ctx context.Context) Snapshot {
	snap := Snapshot{Category: secproto.CatWinsec}
	if denied, failed := w.readSecurity(ctx); failed {
		snap.Status = secproto.StatusError
		if denied {
			snap.Status = secproto.StatusPermissionDenied
		}
		return snap
	}
	now := w.now()
	if w.block != nil {
		w.block.Tick(ctx)
	}
	w.readDefenderLog(ctx)
	w.readDefenderStatus(ctx, now)

	src := make([]secproto.WinSource, 0, len(w.sources))
	for ip, n := range w.sources {
		src = append(src, secproto.WinSource{IP: ip, Failed: n})
	}
	sort.Slice(src, func(a, b int) bool {
		return src[a].Failed > src[b].Failed || (src[a].Failed == src[b].Failed && src[a].IP < src[b].IP)
	})
	if len(src) > secproto.MaxWinsecSources {
		src = src[:secproto.MaxWinsecSources]
	}
	snap.Status = secproto.StatusOK
	snap.Data = secproto.Winsec{
		RemoteFailed: w.failed, RemoteOK: w.ok, Sources: src, RecentOK: append([]secproto.WinLogon{}, w.recentOK...),
		Defender: w.defender, Threats: append([]secproto.WinThreat{}, w.threats...), ThreatsTotal: w.threatsTotal,
	}
	if w.block != nil {
		d := snap.Data.(secproto.Winsec)
		d.Block = w.block.Snapshot()
		snap.Data = d
	}
	return snap
}

// winDenied: wevtutil exits with 5 (ERROR_ACCESS_DENIED) whatever language its message is in.
func winDenied(r Result) bool {
	return r.ExitCode == 5 || r.denied() || strings.Contains(strings.ToLower(r.Stderr+r.Stdout), "access is denied")
}
