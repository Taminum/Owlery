package agent

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Taminum/RemnaScope/internal/ingestproto"
)

// AWGSensorSource receives the traffic sensor's reports. The sensor is a separate, root-started service with a
// narrow sandbox of its own (it has to enter a container's network namespace and open a packet socket, which
// this agent's sandbox forbids); it connects to a Unix socket this agent listens on and writes its reports as
// text. This side only reads text, from the sensors it expects.
type AWGSensorSource struct {
	Socket     string   // path of the Unix socket to listen on
	Containers []string // containers whose reports are accepted; a report for any other is ignored
	// ConfPath is the host's helper configuration. Containers listed in its SENSE are accepted as well, so a
	// container created after the agent started is heard without restarting the agent.
	ConfPath string
	Emit     func(ingestproto.AWGFlows)
	Log      func(msg string)

	mu     sync.Mutex
	read   time.Time
	cached []string
}

func (s *AWGSensorSource) allowed(c string) bool {
	for _, a := range s.Containers {
		if a == c {
			return true
		}
	}
	for _, a := range s.fromConf() {
		if a == c {
			return true
		}
	}
	return false
}

// fromConf reads SENSE from the helper configuration, at most every ten seconds.
func (s *AWGSensorSource) fromConf() []string {
	if s.ConfPath == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.read) < 10*time.Second {
		return s.cached
	}
	s.read = time.Now()
	s.cached = nil
	b, err := os.ReadFile(s.ConfPath)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "SENSE=\""); ok {
			s.cached = strings.Fields(strings.TrimSuffix(v, "\""))
		}
	}
	return s.cached
}

// Run listens until ctx ends.
func (s *AWGSensorSource) Run(ctx context.Context) {
	_ = os.Remove(s.Socket) // a socket left by an earlier run
	ln, err := net.Listen("unix", s.Socket)
	if err != nil {
		if s.Log != nil {
			s.Log("could not listen for the traffic sensor")
		}
		return
	}
	_ = os.Chmod(s.Socket, 0o660)
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			s.consume(c)
		}()
	}
}

// consume reads one sensor's stream of reports until it ends.
func (s *AWGSensorSource) consume(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var cur *ingestproto.AWGFlows
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		switch f[0] {
		case "W":
			cur = nil
			if len(f) >= 6 && s.allowed(f[1]) {
				st, _ := strconv.ParseInt(f[2], 10, 64)
				en, _ := strconv.ParseInt(f[3], 10, 64)
				dp, _ := strconv.ParseUint(f[4], 10, 64)
				lf, _ := strconv.ParseUint(f[5], 10, 64)
				cur = &ingestproto.AWGFlows{Type: "awg_flows", Container: f[1], Start: st, End: en, Dropped: dp, Left: lf}
			}
		case "F":
			if cur != nil && len(f) >= 9 && len(cur.Flows) < ingestproto.MaxAWGFlows {
				p, e1 := strconv.ParseUint(f[2], 10, 8)
				port, e2 := strconv.ParseUint(f[4], 10, 16)
				up, e3 := strconv.ParseUint(f[5], 10, 64)
				down, e4 := strconv.ParseUint(f[6], 10, 64)
				if e1 == nil && e2 == nil && e3 == nil && e4 == nil {
					fl := ingestproto.AWGFlow{Client: f[1], Proto: uint8(p), Remote: f[3], Port: uint16(port), Up: up, Down: down, Name: f[7], How: f[8]}
					if len(f) >= 10 && f[9] == "1" {
						fl.New = 1
					}
					cur.Flows = append(cur.Flows, fl)
				}
			}
		case "E":
			if cur != nil && s.Emit != nil {
				s.Emit(*cur)
			}
			cur = nil
		}
	}
}
