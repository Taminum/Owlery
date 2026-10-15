// Package demo holds synthetic fixtures for the M0 preview.
// Everything produced here is DEMO data: it is never mixed with real telemetry
// and every API response built from it carries meta.demo = true.
package demo

const Source = "demo_fixture"

type Node struct {
	ID        string
	PanelID   string
	Name      string
	RatePerMn float64 // accepted connections per minute at diurnal peak
	LagSec    int
}

type User struct {
	ID    string
	Label string // raw Xray email as seen in the log; NOT a cross-panel identity
	Note  string // set only where a fixture explicitly maps the identifier
	Share float64
}

type Dest struct {
	Key        string
	Label      string
	Port       int
	Weight     float64 // percent of the panel's accepted connections
	Service    string
	Confidence string
}

type Panel struct {
	ID    string
	Name  string
	Nodes []Node
	Users []User
	Hosts []Dest
	IPs   []Dest
	Ports []Dest
	Svc   []Dest
}

const (
	HomePanelID = "11111111-1111-4111-8111-111111111111"
	WorkPanelID = "22222222-2222-4222-8222-222222222222"
)

// Work-2 loses its agent for a window in the demo so that gap markers and
// coverage indicators have something honest to show.
const GapNodeID = "22222222-aaaa-4222-8222-000000000002"

var Panels = []Panel{
	{
		ID:   HomePanelID,
		Name: "Домашняя (демо)",
		Nodes: []Node{
			{ID: "11111111-aaaa-4111-8111-000000000001", PanelID: HomePanelID, Name: "home-a", RatePerMn: 24, LagSec: 4},
			{ID: "11111111-aaaa-4111-8111-000000000002", PanelID: HomePanelID, Name: "home-b", RatePerMn: 9, LagSec: 7},
			{ID: "11111111-aaaa-4111-8111-000000000003", PanelID: HomePanelID, Name: "home-c", RatePerMn: 3, LagSec: 38},
		},
		Users: []User{
			{ID: "11111111-bbbb-4111-8111-000000000004", Label: "4", Note: "OpenWrt", Share: 0.951},
			{ID: "11111111-bbbb-4111-8111-000000000002", Label: "2", Share: 0.028},
			{ID: "11111111-bbbb-4111-8111-000000000003", Label: "3", Share: 0.019},
		},
		Hosts: []Dest{
			{Key: "www.google.com", Label: "www.google.com", Weight: 1.8},
			{Key: "captive.apple.com", Label: "captive.apple.com", Weight: 1.1},
			{Key: "www.gstatic.com", Label: "www.gstatic.com", Weight: 0.7},
			{Key: "api.telegram.org", Label: "api.telegram.org", Weight: 0.5},
			{Key: "cdn.example-video.test", Label: "cdn.example-video.test", Weight: 0.3},
		},
		IPs: []Dest{
			{Key: "9.9.9.9", Label: "9.9.9.9", Weight: 21.2},
			{Key: "203.0.113.88", Label: "203.0.113.88", Weight: 8.9},
			{Key: "149.154.166.110", Label: "149.154.166.110", Weight: 7.4},
			{Key: "150.241.88.30", Label: "150.241.88.30", Weight: 4.6},
			{Key: "194.242.2.2", Label: "194.242.2.2", Weight: 3.7},
		},
		Ports: []Dest{
			{Key: "443", Label: "443", Weight: 77.7},
			{Key: "80", Label: "80", Weight: 11.4},
			{Key: "21114", Label: "21114", Weight: 3.1},
			{Key: "21116", Label: "21116", Weight: 1.5},
			{Key: "8080", Label: "8080", Weight: 1.4},
		},
		Svc: []Dest{
			{Key: "Telegram", Label: "Telegram", Weight: 16.9, Confidence: "high"},
			{Key: "DNS", Label: "DNS", Weight: 7.3, Confidence: "medium"},
			{Key: "Cloudflare", Label: "Cloudflare", Weight: 2.2, Confidence: "medium"},
			{Key: "Google", Label: "Google", Weight: 1.9, Confidence: "high"},
			{Key: "Apple", Label: "Apple", Weight: 1.1, Confidence: "high"},
		},
	},
	{
		ID:   WorkPanelID,
		Name: "Рабочая (демо)",
		Nodes: []Node{
			{ID: "22222222-aaaa-4222-8222-000000000001", PanelID: WorkPanelID, Name: "work-1", RatePerMn: 11, LagSec: 6},
			{ID: GapNodeID, PanelID: WorkPanelID, Name: "work-2", RatePerMn: 5, LagSec: 9},
		},
		Users: []User{
			// Same raw identifiers as the home panel on purpose: they must stay separate.
			{ID: "22222222-bbbb-4222-8222-000000000002", Label: "2", Share: 0.46},
			{ID: "22222222-bbbb-4222-8222-000000000003", Label: "3", Share: 0.33},
			{ID: "22222222-bbbb-4222-8222-000000000007", Label: "7", Share: 0.21},
		},
		Hosts: []Dest{
			{Key: "teams.example-work.test", Label: "teams.example-work.test", Weight: 14},
			{Key: "git.example-work.test", Label: "git.example-work.test", Weight: 9},
			{Key: "www.google.com", Label: "www.google.com", Weight: 6},
			{Key: "mail.example-work.test", Label: "mail.example-work.test", Weight: 4},
		},
		IPs: []Dest{
			{Key: "10.0.12.4", Label: "10.0.12.4", Weight: 8},
			{Key: "1.1.1.1", Label: "1.1.1.1", Weight: 6},
			{Key: "9.9.9.9", Label: "9.9.9.9", Weight: 3},
		},
		Ports: []Dest{
			{Key: "443", Label: "443", Weight: 81},
			{Key: "22", Label: "22", Weight: 9},
			{Key: "587", Label: "587", Weight: 3},
		},
		Svc: []Dest{
			{Key: "Microsoft", Label: "Microsoft", Weight: 18, Confidence: "high"},
			{Key: "Git hosting", Label: "Git hosting", Weight: 9, Confidence: "medium"},
			{Key: "Google", Label: "Google", Weight: 6, Confidence: "high"},
		},
	},
}

func panelByID(id string) *Panel {
	for i := range Panels {
		if Panels[i].ID == id {
			return &Panels[i]
		}
	}
	return nil
}

func nodePanel(nodeID string) *Panel {
	for i := range Panels {
		for _, n := range Panels[i].Nodes {
			if n.ID == nodeID {
				return &Panels[i]
			}
		}
	}
	return nil
}
