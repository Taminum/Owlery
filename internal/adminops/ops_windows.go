//go:build windows

package adminops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/Taminum/Owlery/internal/secproto"
)

// ownService is the agent's own service: stopping, restarting or disabling it would cut the very connection that asked.
const ownService = "OwlerySecAgent"

// protected are processes whose end would crash or lock the machine; a request to kill one is refused.
var protected = map[string]bool{
	"system": true, "registry": true, "smss.exe": true, "csrss.exe": true, "wininit.exe": true, "winlogon.exe": true,
	"services.exe": true, "lsass.exe": true, "memory compression": true,
}

func run(ctx context.Context, op string, args json.RawMessage) (any, error) {
	switch op {
	case secproto.AdminProcs:
		return listProcs(ctx)
	case secproto.AdminProcKill:
		var a struct {
			PID int32 `json:"pid"`
		}
		if err := need(args, &a); err != nil {
			return nil, err
		}
		return nil, killProc(a.PID)
	case secproto.AdminConns:
		return listConns(ctx)
	case secproto.AdminServices:
		return listServices()
	case secproto.AdminSvcStart, secproto.AdminSvcStop, secproto.AdminSvcRestart:
		var a struct {
			Name string `json:"name"`
		}
		if err := need(args, &a); err != nil {
			return nil, err
		}
		return nil, controlService(ctx, op, a.Name)
	case secproto.AdminSvcStartup:
		var a struct {
			Name  string `json:"name"`
			Start string `json:"start"` // auto | manual | disabled
		}
		if err := need(args, &a); err != nil {
			return nil, err
		}
		return nil, setServiceStartup(a.Name, a.Start)
	case secproto.AdminStartup:
		return listStartup()
	case secproto.AdminStartupRemove:
		var a startupRef
		if err := need(args, &a); err != nil {
			return nil, err
		}
		return nil, removeStartup(a)
	case secproto.AdminStartupAdd:
		var a struct {
			Name    string `json:"name"`
			Command string `json:"command"`
		}
		if err := need(args, &a); err != nil {
			return nil, err
		}
		return nil, addStartup(a.Name, a.Command)
	case secproto.AdminSessions:
		return listSessions()
	case secproto.AdminSessionLogoff, secproto.AdminSessionDisconn:
		var a struct {
			ID uint32 `json:"id"`
		}
		if err := need(args, &a); err != nil {
			return nil, err
		}
		return nil, endSession(op, a.ID)
	case secproto.AdminEvents:
		var a eventQuery
		if len(args) > 0 {
			if err := json.Unmarshal(args, &a); err != nil {
				return nil, err
			}
		}
		return listEvents(ctx, a)
	}
	return nil, fmt.Errorf("неизвестное действие %q", op)
}

// --- processes -------------------------------------------------------------------------------------

type procInfo struct {
	PID     int32   `json:"pid"`
	PPID    int32   `json:"ppid"`
	Name    string  `json:"name"`
	User    string  `json:"user,omitempty"`
	RSS     uint64  `json:"rss"`
	CPU     float64 `json:"cpu"` // percent of the whole machine over a short sample
	Started int64   `json:"started,omitempty"`
	Path    string  `json:"path,omitempty"`
}

func listProcs(ctx context.Context) (any, error) {
	ps, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}
	// CPU use needs two readings of each process's time a moment apart.
	first := map[int32]float64{}
	for _, p := range ps {
		if t, err := p.TimesWithContext(ctx); err == nil {
			first[p.Pid] = t.User + t.System
		}
	}
	started := time.Now()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(600 * time.Millisecond):
	}
	elapsed := time.Since(started).Seconds()
	cpus := float64(runtime.NumCPU())
	out := make([]procInfo, 0, len(ps))
	for _, p := range ps {
		if len(out) >= maxProcs {
			break
		}
		info := procInfo{PID: p.Pid}
		info.Name, _ = p.NameWithContext(ctx)
		info.PPID, _ = p.PpidWithContext(ctx)
		info.User, _ = p.UsernameWithContext(ctx)
		info.Path, _ = p.ExeWithContext(ctx)
		if ms, err := p.MemoryInfoWithContext(ctx); err == nil && ms != nil {
			info.RSS = ms.RSS
		}
		if ct, err := p.CreateTimeWithContext(ctx); err == nil {
			info.Started = ct / 1000
		}
		if t, err := p.TimesWithContext(ctx); err == nil {
			if before, ok := first[p.Pid]; ok && elapsed > 0 {
				info.CPU = max(0, ((t.User+t.System)-before)/elapsed/cpus*100)
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CPU > out[j].CPU })
	return out, nil
}

func killProc(pid int32) error {
	if pid <= 4 || int(pid) == os.Getpid() {
		return errors.New("этот процесс трогать нельзя")
	}
	p, err := process.NewProcess(pid)
	if err != nil {
		return errors.New("такого процесса уже нет")
	}
	name, _ := p.Name()
	if protected[strings.ToLower(name)] {
		return fmt.Errorf("%s нельзя завершать: Windows после этого падает", name)
	}
	if err := p.Kill(); err != nil {
		return fmt.Errorf("не удалось завершить: %w", err)
	}
	return nil
}

// --- network connections ---------------------------------------------------------------------------

type connInfo struct {
	Proto  string `json:"proto"`
	Local  string `json:"local"`
	Remote string `json:"remote,omitempty"`
	State  string `json:"state,omitempty"`
	PID    int32  `json:"pid"`
	Name   string `json:"name,omitempty"`
}

func listConns(ctx context.Context) (any, error) {
	cs, err := net.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return nil, err
	}
	names := map[int32]string{}
	if ps, err := process.ProcessesWithContext(ctx); err == nil {
		for _, p := range ps {
			if n, err := p.NameWithContext(ctx); err == nil {
				names[p.Pid] = n
			}
		}
	}
	out := make([]connInfo, 0, len(cs))
	for _, c := range cs {
		if len(out) >= maxConns {
			break
		}
		proto := "tcp"
		if c.Type == 2 { // SOCK_DGRAM
			proto = "udp"
		}
		ci := connInfo{Proto: proto, Local: fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port), State: c.Status, PID: c.Pid, Name: names[c.Pid]}
		if c.Raddr.Port != 0 || c.Raddr.IP != "" {
			ci.Remote = fmt.Sprintf("%s:%d", c.Raddr.IP, c.Raddr.Port)
		}
		out = append(out, ci)
	}
	return out, nil
}
