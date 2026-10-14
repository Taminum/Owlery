package httpapi

import (
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/ingestproto"
	"github.com/Taminum/RemnaScope/internal/live"
)

type liveResp struct {
	Agents    []liveAgentOut `json:"agents"`
	HasRouter bool           `json:"has_router"`
}

func TestLiveEndpointShowsOnlyVisiblePanelsAndNeverPassesOffStaleAsNow(t *testing.T) {
	w := analyzerWorld(t)
	hub := live.New()
	now := time.Now()
	hub.Now = func() time.Time { return now }
	w.h.srv.Live = hub
	frame := ingestproto.Live{Conns: 9, Up: 500, Down: 7000, Devices: []ingestproto.LiveDevice{{IP: "192.168.1.5", Name: "Home", Up: 500, Down: 7000, Conn: 9}}}
	hub.Put(live.Source{AgentID: "ag-home", PanelID: w.home.ID, Name: "OpenWrt"}, frame)
	hub.Put(live.Source{AgentID: "ag-work", PanelID: w.work.ID, Name: "Office"}, frame)

	_, b := w.owner.get("/api/v1/live")
	r := parse[liveResp](t, b)
	if len(r.Agents) != 2 || !r.Agents[0].Live || r.Agents[0].DownBps != 7000 || len(r.Agents[0].Devices) != 1 || len(r.Agents[0].Series) != 1 {
		t.Fatalf("%+v", r)
	}
	_, b = w.owner.get("/api/v1/live?panel_ids=" + w.home.ID)
	if r := parse[liveResp](t, b); len(r.Agents) != 1 || r.Agents[0].PanelName != "Home" {
		t.Fatalf("panel filter: %+v", r)
	}

	// The Work viewer sees only Work, and cannot ask for Home.
	_, vb := w.viewer.get("/api/v1/live")
	if r := parse[liveResp](t, vb); len(r.Agents) != 1 || r.Agents[0].Name != "Office" {
		t.Fatalf("viewer: %+v", r)
	}
	if st, bd := w.viewer.get("/api/v1/live?panel_ids=" + w.home.ID); st != 403 || errCode(bd) != "panel_forbidden" {
		t.Fatalf("%d %s", st, bd)
	}
	if st, _ := w.h.anon().get("/api/v1/live"); st != 401 {
		t.Fatalf("anonymous: %d", st)
	}

	// An agent that went quiet is marked as such, its speed reads zero and its devices are withheld.
	now = now.Add(time.Minute)
	_, b = w.owner.get("/api/v1/live?panel_ids=" + w.home.ID)
	r = parse[liveResp](t, b)
	if len(r.Agents) != 1 || r.Agents[0].Live || r.Agents[0].DownBps != 0 || len(r.Agents[0].Devices) != 0 || r.Agents[0].AgeMS < 59000 || len(r.Agents[0].Series) != 1 {
		t.Fatalf("stale: %+v", r.Agents)
	}
}
