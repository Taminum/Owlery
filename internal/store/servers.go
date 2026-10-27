package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// serverAlertMatch ties an alert to the server it is about. Alerts name their subject in different ways: the server
// itself (resources, flood), the server and a disk, its security agent, one of its port or certificate checks, or the
// log agent of a node linked to it.
const serverAlertMatch = `(a.subject = v.id::text OR a.subject LIKE v.id::text || ':%'
	OR a.subject IN (SELECT x.id::text FROM security_agents x WHERE x.vps_id = v.id)
	OR a.subject IN (SELECT x.id::text FROM security_port_endpoints x WHERE x.vps_id = v.id)
	OR a.subject IN (SELECT x.id::text FROM security_tls_endpoints x WHERE x.vps_id = v.id)
	OR a.subject IN (SELECT ag.id::text FROM agents ag JOIN security_vps_links l ON l.node_id = ag.node_id AND l.panel_id = ag.panel_id WHERE l.vps_id = v.id))`

// ServerAlerts returns, per server, its open alerts and those closed since `since`, newest first. Blips shorter than
// AlertGrace are left out, as everywhere else.
func (s *Store) ServerAlerts(ctx context.Context, vpsIDs []string, since time.Time) (map[string][]Alert, error) {
	rs, err := s.pool.Query(ctx, `SELECT v.id, a.id, a.panel_id, a.kind, a.subject, a.label, a.detail, a.opened_at, a.last_seen_at, a.resolved_at
		FROM security_vps v JOIN alerts a ON `+serverAlertMatch+`
		WHERE v.id = ANY($1::uuid[]) AND (a.resolved_at IS NULL OR a.resolved_at >= $2)
		  AND ((a.resolved_at IS NULL AND a.opened_at <= now() - make_interval(secs => $3))
		    OR (a.resolved_at IS NOT NULL AND a.resolved_at - a.opened_at >= make_interval(secs => $3)))
		ORDER BY (a.resolved_at IS NULL) DESC, COALESCE(a.resolved_at, a.opened_at) DESC LIMIT 2000`, uuids(vpsIDs), since, AlertGrace.Seconds())
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := map[string][]Alert{}
	for rs.Next() {
		var vid, id uuid.UUID
		var pid *uuid.UUID
		var a Alert
		if err := rs.Scan(&vid, &id, &pid, &a.Kind, &a.Subject, &a.Label, &a.Detail, &a.OpenedAt, &a.LastSeenAt, &a.ResolvedAt); err != nil {
			return nil, err
		}
		a.ID = id.String()
		if pid != nil {
			a.PanelID = pid.String()
		}
		out[vid.String()] = append(out[vid.String()], a)
	}
	return out, rs.Err()
}

// ServerNode is a Remnawave node linked to a server.
type ServerNode struct {
	PanelID   string `json:"panel_id"`
	PanelName string `json:"panel_name"`
	NodeID    string `json:"node_id"`
	Name      string `json:"name"`
	Xray      string `json:"xray"`
	UsersNow  int    `json:"users_online"`
	Online    bool   `json:"online"`
}

// ServerNodes returns the nodes linked to each server, within the panels the scope can see.
func (s *Store) ServerNodes(ctx context.Context, sc Scope, vpsIDs []string) (map[string][]ServerNode, error) {
	pred, args := sc.predicate("l.panel_id", 1)
	rs, err := s.pool.Query(ctx, `SELECT l.vps_id, p.id, p.name, n.id, n.name, COALESCE(n.xray_version, ''), COALESCE(n.users_online, 0), COALESCE(n.is_connected, false)
		FROM security_vps_links l JOIN nodes n ON n.id = l.node_id AND n.panel_id = l.panel_id JOIN panels p ON p.id = l.panel_id
		WHERE l.vps_id = ANY($1::uuid[]) AND n.removed_at IS NULL AND p.deleted_at IS NULL AND `+pred+`
		ORDER BY lower(n.name)`, append([]any{uuids(vpsIDs)}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := map[string][]ServerNode{}
	for rs.Next() {
		var vid, pid, nid uuid.UUID
		var n ServerNode
		if err := rs.Scan(&vid, &pid, &n.PanelName, &nid, &n.Name, &n.Xray, &n.UsersNow, &n.Online); err != nil {
			return nil, err
		}
		n.PanelID, n.NodeID = pid.String(), nid.String()
		out[vid.String()] = append(out[vid.String()], n)
	}
	return out, rs.Err()
}
