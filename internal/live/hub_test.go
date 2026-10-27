package live

import (
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/ingestproto"
)

func TestHubKeepsAWindowAndMarksSilenceHonestly(t *testing.T) {
	h := New()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	h.Now = func() time.Time { return now }
	src := Source{AgentID: "a", PanelID: "p", Name: "OpenWrt"}
	dev := func(ip string, up, down int64) ingestproto.LiveDevice {
		return ingestproto.LiveDevice{IP: ip, Up: up, Down: down, Conn: 2}
	}

	if !h.Put(src, ingestproto.Live{Conns: 10, Up: 100, Down: 900, Devices: []ingestproto.LiveDevice{dev("192.168.1.5", 100, 100), dev("192.168.1.9", 10, 800)}}) {
		t.Fatal("a good frame was refused")
	}
	v := h.Views(map[string]bool{"p": true})
	if len(v) != 1 || !v[0].Live || v[0].Latest.Down != 900 || v[0].Devices[0].IP != "192.168.1.9" {
		t.Fatalf("busiest device first: %+v", v)
	}
	if got := h.Views(map[string]bool{"other": true}); len(got) != 0 {
		t.Fatalf("another panel's agent leaked: %+v", got)
	}

	// Silence: after the freshness window the numbers are history, not "now".
	now = now.Add(FreshTo + time.Second)
	v = h.Views(map[string]bool{"p": true})
	if v[0].Live || len(v[0].Devices) != 0 || v[0].AgeMS < 10000 {
		t.Fatalf("a silent agent must not look live: %+v", v[0])
	}

	// Old frames fall out of the window; the cap holds.
	now = now.Add(Keep + time.Minute)
	h.Put(src, ingestproto.Live{Conns: 1})
	if v = h.Views(map[string]bool{"p": true}); len(v[0].Series) != 1 {
		t.Fatalf("window: %d", len(v[0].Series))
	}
	for i := 0; i < MaxLen+50; i++ {
		now = now.Add(time.Millisecond)
		h.Put(src, ingestproto.Live{Conns: i})
	}
	if v = h.Views(map[string]bool{"p": true}); len(v[0].Series) != MaxLen {
		t.Fatalf("cap: %d", len(v[0].Series))
	}
}

func TestHubRefusesBadFrames(t *testing.T) {
	h := New()
	src := Source{AgentID: "a", PanelID: "p"}
	tooMany := make([]ingestproto.LiveDevice, ingestproto.MaxLiveDevices+1)
	for i := range tooMany {
		tooMany[i] = ingestproto.LiveDevice{IP: "192.168.1.1"}
	}
	for name, f := range map[string]ingestproto.Live{
		"negative speed":  {Down: -1},
		"negative conns":  {Conns: -1},
		"public device":   {Devices: []ingestproto.LiveDevice{{IP: "8.8.8.8"}}},
		"not an ip":       {Devices: []ingestproto.LiveDevice{{IP: "nope"}}},
		"negative device": {Devices: []ingestproto.LiveDevice{{IP: "192.168.1.1", Up: -5}}},
		"too many":        {Devices: tooMany},
		"long name":       {Devices: []ingestproto.LiveDevice{{IP: "192.168.1.1", Name: string(make([]byte, 65))}}},
	} {
		if h.Put(src, f) {
			t.Errorf("%s was accepted", name)
		}
	}
	if len(h.Views(map[string]bool{"p": true})) != 0 {
		t.Fatal("a refused frame left something behind")
	}
	h.Put(src, ingestproto.Live{})
	h.Forget("a")
	if len(h.Views(map[string]bool{"p": true})) != 0 {
		t.Fatal("Forget")
	}
}
