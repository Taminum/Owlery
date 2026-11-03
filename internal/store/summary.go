package store

import (
	"context"
	"strconv"
	"time"
)

// SummaryServerCount is a machine name with how many events it had in the window.
type SummaryServerCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// SummaryChange is one thing that changed on a machine: a firewall rewrite, a port that opened or closed.
type SummaryChange struct {
	Server string    `json:"server"`
	Type   string    `json:"type"`
	At     time.Time `json:"at"`
}

// FleetSummary is the "what happened while I was asleep" picture for a window.
type FleetSummary struct {
	Bans struct {
		Total   int                  `json:"total"`
		Servers []SummaryServerCount `json:"servers"`
	} `json:"bans"`
	Changes struct {
		Total int             `json:"total"`
		Items []SummaryChange `json:"items"`
	} `json:"changes"`
	TLS struct {
		Problems    int        `json:"problems"`
		NearestEnd  *time.Time `json:"nearest_end"`
		NearestHost string     `json:"nearest_host"`
	} `json:"tls"`
}

// changeTypes are the journal events a person wants to hear about in the morning.
var changeTypes = []string{"firewall.rules_changed", "port.public_reachable", "port.public_lost"}

// FleetSummary reads the security journal of every machine the scope can see for the window [from, to).
func (s *Store) FleetSummary(ctx context.Context, sc Scope, from, to time.Time) (FleetSummary, error) {
	var out FleetSummary
	out.Bans.Servers = []SummaryServerCount{}
	out.Changes.Items = []SummaryChange{}
	pred, args := vpsVisible(sc, 0)
	n := len(args)
	args = append(args, from, to)
	win := ` AND e.observed_at >= $` + strconv.Itoa(n+1) + ` AND e.observed_at < $` + strconv.Itoa(n+2)

	// A ban the agent saw is one event; a run of bans it missed is one event that says how many.
	rows, err := s.pool.Query(ctx, `SELECT v.name,
			sum(CASE WHEN e.type = 'fail2ban.ban' THEN 1
			         WHEN e.type = 'fail2ban.bans_unobserved' THEN COALESCE((e.payload->>'count')::int, 0) ELSE 0 END)::int AS bans
		FROM security_events e JOIN security_vps v ON v.id = e.vps_id
		WHERE `+pred+win+` AND e.type IN ('fail2ban.ban', 'fail2ban.bans_unobserved')
		GROUP BY v.name HAVING sum(CASE WHEN e.type = 'fail2ban.ban' THEN 1 ELSE COALESCE((e.payload->>'count')::int, 0) END) > 0
		ORDER BY bans DESC, v.name`, args...)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var c SummaryServerCount
		if err := rows.Scan(&c.Name, &c.Count); err != nil {
			rows.Close()
			return out, err
		}
		out.Bans.Total += c.Count
		if len(out.Bans.Servers) < 5 {
			out.Bans.Servers = append(out.Bans.Servers, c)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}

	cargs := append(append([]any{}, args...), changeTypes)
	crows, err := s.pool.Query(ctx, `SELECT v.name, e.type, e.observed_at FROM security_events e JOIN security_vps v ON v.id = e.vps_id
		WHERE `+pred+win+` AND e.type = ANY($`+strconv.Itoa(n+3)+`::text[]) ORDER BY e.observed_at DESC`, cargs...)
	if err != nil {
		return out, err
	}
	for crows.Next() {
		var c SummaryChange
		if err := crows.Scan(&c.Server, &c.Type, &c.At); err != nil {
			crows.Close()
			return out, err
		}
		out.Changes.Total++
		if len(out.Changes.Items) < 6 {
			out.Changes.Items = append(out.Changes.Items, c)
		}
	}
	crows.Close()
	if err := crows.Err(); err != nil {
		return out, err
	}

	targs := append([]any{}, args[:n]...)
	err = s.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE t.enabled AND t.last_state NOT IN ('ok', 'unreachable', 'error')),
			min(t.last_not_after) FILTER (WHERE t.enabled)
		FROM security_tls_endpoints t JOIN security_vps v ON v.id = t.vps_id WHERE `+pred, targs...).Scan(&out.TLS.Problems, &out.TLS.NearestEnd)
	if err != nil {
		return out, err
	}
	if out.TLS.NearestEnd != nil {
		_ = s.pool.QueryRow(ctx, `SELECT t.host FROM security_tls_endpoints t JOIN security_vps v ON v.id = t.vps_id
			WHERE `+pred+` AND t.enabled AND t.last_not_after = $`+strconv.Itoa(n+1)+` LIMIT 1`, append(append([]any{}, args[:n]...), *out.TLS.NearestEnd)...).Scan(&out.TLS.NearestHost)
	}
	return out, nil
}

// OwleryActivity counts what people did in Owlery itself in the window. Account-level entries (sign-ins) carry no
// panel, so only an owner sees them; callers check that.
type OwleryActivity struct {
	Logins    int `json:"logins"`
	Failed    int `json:"failed_logins"`
	Terminals int `json:"terminals"`
	Screens   int `json:"screens"`
	Desktops  int `json:"desktops"`
}

func (s *Store) OwleryActivity(ctx context.Context, from, to time.Time) (OwleryActivity, error) {
	var a OwleryActivity
	err := s.pool.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE action = 'auth.login'),
			count(*) FILTER (WHERE action IN ('auth.login_failed', 'auth.mfa_failed')),
			count(*) FILTER (WHERE action = 'terminal.open'),
			count(*) FILTER (WHERE action = 'screen.open'),
			count(*) FILTER (WHERE action = 'desktop.open')
		FROM audit_log WHERE ts >= $1 AND ts < $2`, from, to).Scan(&a.Logins, &a.Failed, &a.Terminals, &a.Screens, &a.Desktops)
	return a, err
}
