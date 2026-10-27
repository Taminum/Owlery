// Package live keeps the last few minutes of router snapshots in memory for the "right now"
// screen. Nothing here is stored: a restart clears it and the next snapshots fill it again.
package live

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/Taminum/Owlery/internal/ingestproto"
)

const (
	Keep    = 5 * time.Minute // how much history a chart can show
	MaxLen  = 400             // hard cap on frames per agent
	FreshTo = 10 * time.Second
)

type Device struct {
	IP   string `json:"ip"`
	Name string `json:"name,omitempty"`
	Up   int64  `json:"up_bps"`
	Down int64  `json:"down_bps"`
	Conn int    `json:"connections"`
}

type Frame struct {
	TS      time.Time
	Conns   int
	Up      int64
	Down    int64
	Devices []Device
}

type Source struct {
	AgentID string
	PanelID string
	Name    string
}

type series struct {
	src    Source
	frames []Frame
}

type Hub struct {
	mu   sync.Mutex
	data map[string]*series // by agent id
	Now  func() time.Time
}

func New() *Hub { return &Hub{data: map[string]*series{}} }

func (h *Hub) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// Put stores a snapshot from an agent after checking it: bounded sizes, non-negative speeds, device
// addresses that are LAN addresses. It returns false if the frame was refused.
func (h *Hub) Put(src Source, f ingestproto.Live) bool {
	if f.Conns < 0 || f.Up < 0 || f.Down < 0 || len(f.Devices) > ingestproto.MaxLiveDevices {
		return false
	}
	fr := Frame{TS: h.now(), Conns: f.Conns, Up: f.Up, Down: f.Down}
	for _, d := range f.Devices {
		ip, err := netip.ParseAddr(d.IP)
		if err != nil || !(ip.IsPrivate() || ip.IsLinkLocalUnicast()) || d.Up < 0 || d.Down < 0 || d.Conn < 0 || len(d.Name) > 64 {
			return false
		}
		fr.Devices = append(fr.Devices, Device{IP: d.IP, Name: d.Name, Up: d.Up, Down: d.Down, Conn: d.Conn})
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.data[src.AgentID]
	if s == nil {
		s = &series{}
		h.data[src.AgentID] = s
	}
	s.src = src
	s.frames = append(s.frames, fr)
	cut := fr.TS.Add(-Keep)
	i := 0
	for i < len(s.frames) && s.frames[i].TS.Before(cut) {
		i++
	}
	if over := len(s.frames) - i - MaxLen; over > 0 {
		i += over
	}
	s.frames = append([]Frame(nil), s.frames[i:]...)
	return true
}

type Point struct {
	TS    int64 `json:"ts"` // Unix milliseconds
	Up    int64 `json:"up_bps"`
	Down  int64 `json:"down_bps"`
	Conns int   `json:"connections"`
}

type View struct {
	Source  Source
	Live    bool
	AgeMS   int64
	Latest  Frame
	Series  []Point
	Devices []Device // busiest first
}

// Views returns what each agent of the given panels last said. An agent that has not spoken for a
// few seconds is reported as not live, and its numbers are not presented as current.
func (h *Hub) Views(panels map[string]bool) []View {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	var out []View
	for _, s := range h.data {
		if !panels[s.src.PanelID] || len(s.frames) == 0 {
			continue
		}
		last := s.frames[len(s.frames)-1]
		v := View{Source: s.src, Latest: last, AgeMS: now.Sub(last.TS).Milliseconds(), Live: now.Sub(last.TS) <= FreshTo}
		for _, f := range s.frames {
			v.Series = append(v.Series, Point{TS: f.TS.UnixMilli(), Up: f.Up, Down: f.Down, Conns: f.Conns})
		}
		if v.Live {
			v.Devices = append(v.Devices, last.Devices...)
			sort.Slice(v.Devices, func(i, j int) bool {
				a, b := v.Devices[i].Up+v.Devices[i].Down, v.Devices[j].Up+v.Devices[j].Down
				if a != b {
					return a > b
				}
				return v.Devices[i].IP < v.Devices[j].IP
			})
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Source.AgentID < out[j].Source.AgentID })
	return out
}

// Forget drops an agent (revoked).
func (h *Hub) Forget(agentID string) {
	h.mu.Lock()
	delete(h.data, agentID)
	h.mu.Unlock()
}
