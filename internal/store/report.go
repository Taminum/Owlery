package store

import (
	"context"
	"sort"
	"time"
)

// The monthly report: what the month looked like across everything the owner sees, set beside the month before it.

type ReportMachine struct {
	Name     string `json:"name"`
	DownMins int    `json:"down_mins"`
}

type ReportKind struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

type ReportAlert struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Count int    `json:"count,omitempty"`
	Mins  int    `json:"mins,omitempty"`
}

type ReportMoney struct {
	Currency string  `json:"currency"`
	Amount   float64 `json:"amount"`
}

type ReportDue struct {
	Name     string  `json:"name"`
	Due      string  `json:"due"`
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

// MonthData is one month. A field that could not be known (no data was kept) is nil or empty, never a zero that looks like a fact.
type MonthData struct {
	Month        string          `json:"month"` // 2026-10
	Availability *float64        `json:"availability"`
	Worst        []ReportMachine `json:"worst"`
	Alerts       int             `json:"alerts"`
	AlertKinds   []ReportKind    `json:"alert_kinds"`
	Noisy        *ReportAlert    `json:"noisy"`
	Longest      *ReportAlert    `json:"longest"`
	Events       []EventCount    `json:"events"`
	EventTotal   int             `json:"event_total"`
	NetDowns     int             `json:"net_downs"`
	NetDownMins  int             `json:"net_down_mins"`
	NetWorst     string          `json:"net_worst,omitempty"`
	NewDevices   int             `json:"new_devices"`
	TrafficBytes *int64          `json:"traffic_bytes"`
	Paid         []ReportMoney   `json:"paid"`
}

type MonthReport struct {
	Cur      MonthData   `json:"cur"`
	Prev     MonthData   `json:"prev"`
	Upcoming []ReportDue `json:"upcoming"`
}

// MonthStart is the first moment of the month that contains t, in loc.
func MonthStart(t time.Time, loc *time.Location) time.Time {
	t = t.In(loc)
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, loc)
}

// BuildMonthReport gathers the month that starts at `month` and the one before it, and the bills that fall due in the next 14 days.
func (s *Store) BuildMonthReport(ctx context.Context, month time.Time, now time.Time, loc *time.Location) (MonthReport, error) {
	month = MonthStart(month, loc)
	var r MonthReport
	var err error
	if r.Cur, err = s.monthData(ctx, month, month.AddDate(0, 1, 0), now, loc); err != nil {
		return r, err
	}
	prev := month.AddDate(0, -1, 0)
	if r.Prev, err = s.monthData(ctx, prev, month, now, loc); err != nil {
		return r, err
	}
	r.Upcoming = []ReportDue{}
	rows, err := s.pool.Query(ctx, `SELECT name, next_due::text, amount::float8, currency FROM bills
		WHERE archived_at IS NULL AND next_due >= $1::date AND next_due <= $2::date ORDER BY next_due, name`, now.In(loc).Format("2006-01-02"), now.In(loc).AddDate(0, 0, 14).Format("2006-01-02"))
	if err != nil {
		return r, err
	}
	defer rows.Close()
	for rows.Next() {
		var d ReportDue
		if err := rows.Scan(&d.Name, &d.Due, &d.Amount, &d.Currency); err != nil {
			return r, err
		}
		r.Upcoming = append(r.Upcoming, d)
	}
	return r, rows.Err()
}

func (s *Store) monthData(ctx context.Context, from, to, now time.Time, loc *time.Location) (MonthData, error) {
	d := MonthData{Month: from.Format("2006-01"), Worst: []ReportMachine{}, AlertKinds: []ReportKind{}, Events: []EventCount{}, Paid: []ReportMoney{}}
	end := to
	if end.After(now) {
		end = now
	}

	// Availability: the minutes each machine answered, from the days that were kept. A day with no record is not counted either way.
	rows, err := s.pool.Query(ctx, `SELECT v.name, sum(u.minutes)::int, count(*)::int FROM host_uptime_days u JOIN security_vps v ON v.id = u.vps_id
		WHERE v.archived_at IS NULL AND u.day >= $1::date AND u.day < $2::date GROUP BY v.name`, from.Format("2006-01-02"), to.Format("2006-01-02"))
	if err != nil {
		return d, err
	}
	var up, total int
	for rows.Next() {
		var name string
		var mins, days int
		if err := rows.Scan(&name, &mins, &days); err != nil {
			rows.Close()
			return d, err
		}
		up += mins
		total += days * 1440
		if down := days*1440 - mins; down >= 5 {
			d.Worst = append(d.Worst, ReportMachine{Name: name, DownMins: down})
		}
	}
	rows.Close()
	if total > 0 {
		a := float64(up) / float64(total) * 100
		d.Availability = &a
	}
	sort.Slice(d.Worst, func(i, j int) bool { return d.Worst[i].DownMins > d.Worst[j].DownMins })
	if len(d.Worst) > 3 {
		d.Worst = d.Worst[:3]
	}

	// Alerts opened in the month.
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM alerts WHERE opened_at >= $1 AND opened_at < $2`, from, to).Scan(&d.Alerts); err != nil {
		return d, err
	}
	kr, err := s.pool.Query(ctx, `SELECT kind, count(*)::int FROM alerts WHERE opened_at >= $1 AND opened_at < $2 GROUP BY kind ORDER BY count(*) DESC, kind LIMIT 5`, from, to)
	if err != nil {
		return d, err
	}
	for kr.Next() {
		var k ReportKind
		if err := kr.Scan(&k.Kind, &k.Count); err != nil {
			kr.Close()
			return d, err
		}
		d.AlertKinds = append(d.AlertKinds, k)
	}
	kr.Close()
	var n ReportAlert
	err = s.pool.QueryRow(ctx, `SELECT kind, label, count(*)::int FROM alerts WHERE opened_at >= $1 AND opened_at < $2 GROUP BY kind, label HAVING count(*) >= 3
		ORDER BY count(*) DESC, label LIMIT 1`, from, to).Scan(&n.Kind, &n.Label, &n.Count)
	if err == nil {
		d.Noisy = &n
	}
	var l ReportAlert
	err = s.pool.QueryRow(ctx, `SELECT kind, label, (extract(epoch FROM (coalesce(resolved_at, $3) - opened_at)) / 60)::int AS m FROM alerts
		WHERE opened_at >= $1 AND opened_at < $2 AND kind NOT IN ('net_down') ORDER BY m DESC LIMIT 1`, from, to, end).Scan(&l.Kind, &l.Label, &l.Mins)
	if err == nil && l.Mins >= 5 {
		d.Longest = &l
	}

	// What the security journal recorded.
	er, err := s.pool.Query(ctx, `SELECT e.type, e.category, max(e.severity), count(*)::int FROM security_events e JOIN security_vps v ON v.id = e.vps_id
		WHERE v.archived_at IS NULL AND e.observed_at >= $1 AND e.observed_at < $2 GROUP BY e.type, e.category ORDER BY count(*) DESC, e.type`, from, to)
	if err != nil {
		return d, err
	}
	for er.Next() {
		var c EventCount
		if err := er.Scan(&c.Type, &c.Category, &c.Severity, &c.Count); err != nil {
			er.Close()
			return d, err
		}
		d.EventTotal += c.Count
		if len(d.Events) < 6 {
			d.Events = append(d.Events, c)
		}
	}
	er.Close()

	// Routers that fell silent, and devices that appeared.
	var worstMins *int
	var worst *string
	if err := s.pool.QueryRow(ctx, `SELECT count(*)::int, coalesce(sum(m), 0)::int, max(m)::int, (array_agg(label ORDER BY m DESC))[1] FROM (
			SELECT label, extract(epoch FROM (coalesce(resolved_at, $3) - opened_at)) / 60 AS m FROM alerts WHERE kind = 'net_down' AND opened_at >= $1 AND opened_at < $2) x`,
		from, to, end).Scan(&d.NetDowns, &d.NetDownMins, &worstMins, &worst); err != nil {
		return d, err
	}
	if worst != nil && d.NetDowns > 0 {
		d.NetWorst = *worst
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*)::int FROM lan_devices WHERE first_seen >= $1 AND first_seen < $2
		AND first_seen > coalesce((SELECT min(l2.first_seen) FROM lan_devices l2 WHERE l2.source_id = lan_devices.source_id), '-infinity') + interval '10 minutes'`, from, to).Scan(&d.NewDevices); err != nil {
		return d, err
	}

	// Traffic of the VPN nodes, when any was measured.
	if panels, err := s.ListPanels(ctx, Scope{All: true}); err == nil {
		var ids []string
		for _, p := range panels {
			if !p.Demo {
				ids = append(ids, p.ID)
			}
		}
		if len(ids) > 0 {
			if sum, err := s.TrafficSummaryFor(ctx, AnalyticsQuery{PanelIDs: ids, From: from, To: end, Granularity: 24 * time.Hour}); err == nil && sum.Samples > 0 {
				b := sum.NodeBytes
				d.TrafficBytes = &b
			}
		}
	}

	// What was paid.
	pr, err := s.pool.Query(ctx, `SELECT currency, sum(amount)::float8 FROM bill_payments WHERE paid_on >= $1::date AND paid_on < $2::date GROUP BY currency ORDER BY currency`,
		from.Format("2006-01-02"), to.Format("2006-01-02"))
	if err != nil {
		return d, err
	}
	defer pr.Close()
	for pr.Next() {
		var m ReportMoney
		if err := pr.Scan(&m.Currency, &m.Amount); err != nil {
			return d, err
		}
		d.Paid = append(d.Paid, m)
	}
	return d, pr.Err()
}

// ReportMonthSent says which month a channel last got the report for.
func (s *Store) ReportMonthSent(ctx context.Context, channelID string) (time.Time, error) {
	u, err := ParseID(channelID)
	if err != nil {
		return time.Time{}, ErrNotFound
	}
	var m time.Time
	err = s.pool.QueryRow(ctx, `SELECT report_month FROM notify_channels WHERE id=$1`, u).Scan(&m)
	return m, err
}

func (s *Store) MarkReportSent(ctx context.Context, channelID string, month time.Time) error {
	u, err := ParseID(channelID)
	if err != nil {
		return ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `UPDATE notify_channels SET report_month=$2::date WHERE id=$1`, u, month.Format("2006-01-02"))
	return err
}
