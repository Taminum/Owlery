package store

import (
	"context"
	"time"
)

// OnboardingCounts says what has been set up, for the "getting started" page. They are plain counts: the page
// decides what counts as done.
type OnboardingCounts struct {
	Panels         int `json:"panels"`          // real panels, not the demo
	PanelsSynced   int `json:"panels_synced"`   // of them, with at least one finished sync
	Nodes          int `json:"nodes"`           // nodes the panels reported
	NodeAgents     int `json:"node_agents"`     // log agents of nodes that have reported lately
	SecurityHosts  int `json:"security_hosts"`  // servers added to the security module
	SecurityAgents int `json:"security_agents"` // security agents that have reported lately
	AWGServers     int `json:"awg_servers"`     // AmneziaWG servers that have reported
	NotifyChannels int `json:"notify_channels"`
	Bills          int `json:"bills"`
	DNSMaps        int `json:"dns_maps"`
}

func (s *Store) OnboardingCounts(ctx context.Context, now time.Time) (OnboardingCounts, error) {
	var c OnboardingCounts
	recent := now.Add(-10 * time.Minute)
	err := s.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM panels WHERE deleted_at IS NULL AND NOT demo),
		(SELECT count(*) FROM panels WHERE deleted_at IS NULL AND NOT demo AND last_sync_at IS NOT NULL),
		(SELECT count(*) FROM nodes n JOIN panels p ON p.id = n.panel_id WHERE n.removed_at IS NULL AND p.deleted_at IS NULL AND NOT p.demo),
		(SELECT count(*) FROM agents WHERE status = 'active' AND kind = 'node' AND last_seen > $1),
		(SELECT count(*) FROM security_vps WHERE archived_at IS NULL),
		(SELECT count(*) FROM security_agents WHERE status = 'active' AND last_seen > $1),
		(SELECT count(*) FROM awg_instances WHERE last_report > $1),
		(SELECT count(*) FROM notify_channels),
		(SELECT count(*) FROM bills WHERE archived_at IS NULL),
		(SELECT count(*) FROM dns_maps WHERE archived_at IS NULL)`, recent).
		Scan(&c.Panels, &c.PanelsSynced, &c.Nodes, &c.NodeAgents, &c.SecurityHosts, &c.SecurityAgents, &c.AWGServers, &c.NotifyChannels, &c.Bills, &c.DNSMaps)
	return c, err
}
