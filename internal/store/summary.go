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
	Win struct {
		Machines     int `json:"machines"`      // Windows machines whose agent reads the event log
		RDPFailed    int `json:"rdp_failed"`    // failed remote sign-ins in the window
		RDPOK        int `json:"rdp_ok"`        // remote-desktop sign-ins that worked
		Threats      int `json:"threats"`       // things Defender found
		DefenderOff  int `json:"defender_off"`  // times Defender's live protection was seen switched off
		DefenderDown int `json:"defender_down"` // machines where Defender is the active antivirus and its live protection is off now (another antivirus: not counted)
	} `json:"win"`
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
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security_snapshot_state st JOIN security_vps v ON v.id = st.vps_id WHERE `+pred+` AND st.category = 'winsec' AND st.status = 'ok'`, args[:n]...).Scan(&out.Win.Machines); err != nil {
		return out, err
	}
	if out.Win.Machines > 0 {
		if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM security_snapshot_state st JOIN security_vps v ON v.id = st.vps_id WHERE `+pred+` AND st.category = 'winsec' AND st.status = 'ok'
			AND st.data->'defender'->>'enabled' = 'true' AND st.data->'defender'->>'realtime' = 'false'`, args[:n]...).Scan(&out.Win.DefenderDown); err != nil {
			return out, err
		}
		if err := s.pool.QueryRow(ctx, `SELECT COALESCE(sum(CASE WHEN e.type = 'winsec.rdp_failed' THEN COALESCE((e.payload->>'count')::int, 0) END), 0)::int,
				(count(*) FILTER (WHERE e.type = 'winsec.rdp_ok'))::int, (count(*) FILTER (WHERE e.type = 'winsec.defender_threat'))::int, (count(*) FILTER (WHERE e.type = 'winsec.defender_off'))::int`+
			` FROM security_events e JOIN security_vps v ON v.id = e.vps_id WHERE `+pred+win+` AND e.category = 'winsec'`, args...).Scan(&out.Win.RDPFailed, &out.Win.RDPOK, &out.Win.Threats, &out.Win.DefenderOff); err != nil {
			return out, err
		}
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

// SummaryHour is one hour of the window: bans, changes and alerts that opened in it.
type SummaryHour struct {
	At      time.Time `json:"at"`
	Bans    int       `json:"bans"`
	Changes int       `json:"changes"`
	RDP     int       `json:"rdp"` // failed remote-desktop sign-ins
	Alerts  int       `json:"alerts"`
	Access  int       `json:"access"` // terminal, screen and desktop sessions; owners only
}

// SummaryIP is an address that was banned, with the jail that banned it most often.
type SummaryIP struct {
	IP    string `json:"ip"`
	Jail  string `json:"jail"`
	Count int    `json:"count"`
}

// SummaryJail is what was hit: a fail2ban jail with how many bans it made.
type SummaryJail struct {
	Name  string `json:"name"`
	Count int    `json:"count"` // blocks: by Fail2ban, or by the address blocker on a Windows machine
	// Attempts is how many failed sign-ins were seen behind the blocks (remote desktop only); it is shown beside the count.
	Attempts int `json:"attempts,omitempty"`
}

// SummaryEvent is one line of the recent journal.
type SummaryEvent struct {
	Server   string    `json:"server"`
	Type     string    `json:"type"`
	Severity string    `json:"severity"`
	At       time.Time `json:"at"`
}

// FleetDetails is the second half of the summary: the hour by hour picture and the top lists.
type FleetDetails struct {
	Hourly []SummaryHour  `json:"hourly"`
	TopIPs []SummaryIP    `json:"top_ips"`
	Jails  []SummaryJail  `json:"jails"`
	Recent []SummaryEvent `json:"recent"`
}

const banCount = `CASE WHEN e.type = 'fail2ban.ban' THEN 1 WHEN e.type = 'fail2ban.bans_unobserved' THEN COALESCE((e.payload->>'count')::int, 0) ELSE 0 END`

// rdpCount is how many failed remote sign-ins one winsec.rdp_failed event stands for.
const rdpCount = `CASE WHEN e.type = 'winsec.rdp_failed' THEN COALESCE((e.payload->>'count')::int, 0) ELSE 0 END`

// ipBlocked counts one block by the address blocker on a Windows machine.
const ipBlocked = `CASE WHEN e.type = 'winsec.ip_blocked' THEN 1 ELSE 0 END`

// FleetDetails fills the hour buckets (one per hour of the window, empty ones included) and the top lists. withAccess
// adds the access sessions and the opened alerts, which belong to no machine and so only an owner sees.
func (s *Store) FleetDetails(ctx context.Context, sc Scope, from, to time.Time, withAccess bool) (FleetDetails, error) {
	d := FleetDetails{TopIPs: []SummaryIP{}, Jails: []SummaryJail{}, Recent: []SummaryEvent{}}
	start := from.Truncate(time.Hour)
	idx := map[time.Time]int{}
	for h := start; h.Before(to); h = h.Add(time.Hour) {
		idx[h] = len(d.Hourly)
		d.Hourly = append(d.Hourly, SummaryHour{At: h})
	}
	put := func(h time.Time, f func(*SummaryHour)) {
		if i, ok := idx[h.UTC().Truncate(time.Hour)]; ok {
			f(&d.Hourly[i])
		}
	}
	pred, args := vpsVisible(sc, 0)
	n := len(args)
	args = append(args, from, to)
	win := ` AND e.observed_at >= $` + strconv.Itoa(n+1) + ` AND e.observed_at < $` + strconv.Itoa(n+2)
	from2 := ` FROM security_events e JOIN security_vps v ON v.id = e.vps_id WHERE ` + pred + win

	rows, err := s.pool.Query(ctx, `SELECT date_trunc('hour', e.observed_at AT TIME ZONE 'UTC'), sum(`+banCount+`)::int, (count(*) FILTER (WHERE e.type = ANY($`+strconv.Itoa(n+3)+`::text[])))::int, sum(`+rdpCount+`)::int`+from2+` GROUP BY 1`, append(append([]any{}, args...), changeTypes)...)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var h time.Time
		var bans, changes, rdp int
		if err := rows.Scan(&h, &bans, &changes, &rdp); err != nil {
			rows.Close()
			return d, err
		}
		put(h, func(x *SummaryHour) { x.Bans, x.Changes, x.RDP = bans, changes, rdp })
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return d, err
	}

	ips, err := s.pool.Query(ctx, `SELECT ip, COALESCE(mode() WITHIN GROUP (ORDER BY jail), ''), sum(n)::int FROM (
		SELECT e.payload->>'ip' AS ip, CASE WHEN e.type = 'winsec.rdp_failed' THEN 'rdp' ELSE e.payload->>'jail' END AS jail,
			CASE WHEN e.type = 'winsec.rdp_failed' THEN COALESCE((e.payload->>'count')::int, 0) ELSE 1 END AS n`+from2+`
			AND e.type IN ('fail2ban.ban', 'winsec.rdp_failed') AND COALESCE(e.payload->>'ip', '') <> '') x
		GROUP BY ip ORDER BY sum(n) DESC, ip LIMIT 5`, args...)
	if err != nil {
		return d, err
	}
	for ips.Next() {
		var x SummaryIP
		if err := ips.Scan(&x.IP, &x.Jail, &x.Count); err != nil {
			ips.Close()
			return d, err
		}
		d.TopIPs = append(d.TopIPs, x)
	}
	ips.Close()
	if err := ips.Err(); err != nil {
		return d, err
	}

	// Remote desktop counts blocks, like the other jails; the failed sign-ins behind them ride along as "attempts".
	jr, err := s.pool.Query(ctx, `SELECT CASE WHEN e.type IN ('winsec.rdp_failed', 'winsec.ip_blocked') THEN 'rdp' ELSE COALESCE(e.payload->>'jail', '') END,
			sum(`+banCount+` + `+ipBlocked+`)::int, sum(`+rdpCount+`)::int`+from2+`
		AND e.type IN ('fail2ban.ban', 'fail2ban.bans_unobserved', 'winsec.rdp_failed', 'winsec.ip_blocked') GROUP BY 1
		HAVING sum(`+banCount+` + `+ipBlocked+` + `+rdpCount+`) > 0 ORDER BY 2 DESC, 3 DESC, 1 LIMIT 6`, args...)
	if err != nil {
		return d, err
	}
	for jr.Next() {
		var x SummaryJail
		if err := jr.Scan(&x.Name, &x.Count, &x.Attempts); err != nil {
			jr.Close()
			return d, err
		}
		d.Jails = append(d.Jails, x)
	}
	jr.Close()
	if err := jr.Err(); err != nil {
		return d, err
	}

	ev, err := s.pool.Query(ctx, `SELECT v.name, e.type, e.severity, e.observed_at`+from2+`
		AND e.type NOT IN ('fail2ban.ban', 'fail2ban.unban', 'fail2ban.bans_unobserved', 'port.local_added', 'port.local_removed', 'port.local_bind_changed')
		AND NOT (e.type = 'winsec.rdp_failed' AND e.severity = 'info') ORDER BY e.observed_at DESC LIMIT 8`, args...)
	if err != nil {
		return d, err
	}
	for ev.Next() {
		var x SummaryEvent
		if err := ev.Scan(&x.Server, &x.Type, &x.Severity, &x.At); err != nil {
			ev.Close()
			return d, err
		}
		d.Recent = append(d.Recent, x)
	}
	ev.Close()
	if err := ev.Err(); err != nil {
		return d, err
	}

	if withAccess {
		ar, err := s.pool.Query(ctx, `SELECT date_trunc('hour', ts AT TIME ZONE 'UTC'), count(*)::int FROM audit_log WHERE ts >= $1 AND ts < $2 AND action IN ('terminal.open', 'screen.open', 'desktop.open') GROUP BY 1`, from, to)
		if err != nil {
			return d, err
		}
		for ar.Next() {
			var h time.Time
			var c int
			if err := ar.Scan(&h, &c); err != nil {
				ar.Close()
				return d, err
			}
			put(h, func(x *SummaryHour) { x.Access = c })
		}
		ar.Close()
		if err := ar.Err(); err != nil {
			return d, err
		}
		al, err := s.pool.Query(ctx, `SELECT date_trunc('hour', opened_at AT TIME ZONE 'UTC'), count(*)::int FROM alerts WHERE opened_at >= $1 AND opened_at < $2 GROUP BY 1`, from, to)
		if err != nil {
			return d, err
		}
		for al.Next() {
			var h time.Time
			var c int
			if err := al.Scan(&h, &c); err != nil {
				al.Close()
				return d, err
			}
			put(h, func(x *SummaryHour) { x.Alerts = c })
		}
		al.Close()
		if err := al.Err(); err != nil {
			return d, err
		}
	}
	return d, nil
}
