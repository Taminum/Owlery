package store

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// Subject narrows an analysis to one person or device.
//
//	user   : a panel user (ID = user uuid). Includes the router's traffic when this user is the
//	         one the router agent stands for (agents.covers_user).
//	raw    : a panel user id that is not a known user (ID = the id as the node logged it)
//	device : one LAN device seen by a router agent (ID = its IP)
//	path   : one inbound of the nodes (ID = its tag), e.g. the CDN entrance. Node log lines only:
//	         router records have no inbound, and nothing is hidden as a router copy.
//	awg    : AmneziaWG traffic only (ID = a device's tunnel address, or "*" for the whole server)
type Subject struct {
	Kind    string // "" | user | raw | device | path | awg
	PanelID string
	ID      string
}

func (s Subject) Valid() bool { return s.Kind != "" }

// args7 is args() plus the subject, for statements built on eventsCTE.
func (q AnalyticsQuery) args7() []any {
	var panel any
	if q.Subject.Kind != "" {
		if id, err := uuid.Parse(q.Subject.PanelID); err == nil {
			panel = id
		}
	}
	return append(q.args(), q.Subject.Kind, panel, q.Subject.ID)
}

// SessionGap is how long a person may stay away from a site before the next connection counts
// as a new visit. Visits are an estimate built from connections: the logs hold nothing else.
const SessionGap = 30 * time.Minute

// eventsCTE is the one place that decides what "traffic of the selected panels" is. Node log
// lines and router records are unioned; the nodes' copy of what a router agent also saw (the
// user it stands for, from its first record on) is dropped so nothing is counted twice, and the
// subject filter is applied on both sides. Columns: panel_id, host, ip, port, node_id, ukey, uid,
// email, dev, dname, ts, bytes, rtr, site, inb, country, w, src.
//
// w is how many connections a row stands for (1 for a node line or a router record; for AmneziaWG, the
// connections that began in that hour, since its rows are hourly sums, not events) and src says where the
// row came from: node | router | awg. Everything that counts connections sums w; visits are never taken
// from awg rows (an hour of activity is not a visit). AmneziaWG rows are only part of the picture when no
// subject and no node filter is set: they belong to neither a panel user, a LAN device nor an inbound.
//
// Parameters: $1 panels, $2 nodes, $3 from, $4 to, $5 subject kind, $6 subject panel, $7 subject id.
// rt is MATERIALIZED on purpose: it is read from inside a per-event NOT EXISTS, and without it the
// planner re-runs its aggregate over every router record for every node event (minutes on real data).
const eventsCTE = `
rt AS MATERIALIZED (
  SELECT a.panel_id, a.covers_user, min(d.started_at) AS since
  FROM agents a JOIN device_connections d ON d.agent_id = a.id
  WHERE a.kind = 'router' AND a.covers_user IS NOT NULL AND a.panel_id = ANY($1::uuid[]) GROUP BY 1, 2
), ev AS (
  SELECT e.panel_id, e.destination_host AS host, host(e.destination_ip) AS ip, e.destination_port AS port, e.node_id,
         COALESCE(e.user_id::text, 'raw:' || COALESCE(e.xray_email, '-')) AS ukey, e.user_id AS uid, e.xray_email AS email,
         NULL::text AS dev, NULL::text AS dname, e.ts, NULL::bigint AS bytes, false AS rtr, e.site, e.inbound_tag AS inb, e.country, 1::bigint AS w, 'node'::text AS src
  FROM connection_events e WHERE ` + aScope + `
    AND ($5::text = 'path' OR NOT EXISTS (SELECT 1 FROM rt WHERE rt.panel_id = e.panel_id AND rt.covers_user = e.xray_email AND e.ts >= rt.since))
    AND ($5::text = '' OR ($5 = 'user' AND e.panel_id = $6::uuid AND e.user_id::text = $7::text)
         OR ($5 = 'raw' AND e.panel_id = $6::uuid AND e.user_id IS NULL AND e.xray_email = $7::text)
         OR ($5 = 'path' AND e.panel_id = $6::uuid AND e.inbound_tag = $7::text))
  UNION ALL
  SELECT d.panel_id, d.destination_host, host(d.destination_ip), d.destination_port, NULL::uuid, 'dev:' || host(d.device_ip), NULL::uuid, NULL::text,
         host(d.device_ip), d.device_name, d.started_at, d.up_bytes + d.down_bytes, true, d.site, NULL::text, d.country, 1::bigint, 'router'::text
  FROM device_connections d
  WHERE d.panel_id = ANY($1::uuid[]) AND cardinality($2::uuid[]) = 0 AND d.started_at >= $3 AND d.started_at < $4
    AND ($5::text = '' OR ($5 = 'device' AND d.panel_id = $6::uuid AND host(d.device_ip) = $7::text)
         OR ($5 = 'user' AND EXISTS (SELECT 1 FROM agents a JOIN users u ON u.panel_id = a.panel_id AND u.remote_uuid = a.covers_user
                                     WHERE a.id = d.agent_id AND u.id::text = $7::text)))
  UNION ALL
  SELECT i.panel_id, NULLIF(h.name, ''), host(h.remote_ip), h.remote_port, NULL::uuid, 'awg:' || host(h.client_ip), NULL::uuid, NULL::text,
         NULL::text, COALESCE(p.label, host(h.client_ip)), h.hour, h.up_bytes + h.down_bytes, true, h.site, NULL::text, h.country, h.flows::bigint, 'awg'::text
  FROM awg_flow_hourly h JOIN awg_instances i ON i.id = h.instance_id LEFT JOIN awg_peers p ON p.id = h.peer_id
  WHERE i.panel_id = ANY($1::uuid[]) AND cardinality($2::uuid[]) = 0 AND h.hour + interval '1 hour' > $3 AND h.hour < $4
    AND ($5::text = '' OR ($5 = 'awg' AND i.panel_id = $6::uuid AND ($7::text = '*' OR host(h.client_ip) = $7::text)))
)`

// ruleMatch picks the most specific enabled rule whose pattern is the name or one of its parents.
func ruleMatch(name string) string {
	return `LEFT JOIN LATERAL (SELECT sr.service, sr.confidence, sr.category, sr.source, sr.score FROM service_rules sr
	  WHERE sr.enabled AND (` + name + ` = sr.pattern OR ` + name + ` LIKE '%.' || sr.pattern)
	  ORDER BY length(sr.pattern) DESC, sr.rule_version DESC LIMIT 1) r ON TRUE`
}

// UncategorisedLabel is shown for sites no rule knows. It says "not classified", not "other".
const UncategorisedLabel = "Не определена"

func escapedLike(s string) string { return "%" + likeEscape(strings.TrimSpace(s)) + "%" }
