// Package alerts turns the state of agents and panels into open and closed alerts. It checks
// what is wrong now; it keeps no history of its own beyond the alerts table.
package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

const (
	// AgentSilentAfter is how long an agent that has connected before may stay unheard from.
	// Agents ping every few seconds, so this is long enough to ride out a restart.
	AgentSilentAfter = 5 * time.Minute
	// PanelFailures is how many failed syncs in a row make a panel "not syncing".
	PanelFailures = 3
)

var Kinds = []string{store.AlertAgentSilent, store.AlertPanelSync, store.AlertProbeDown, store.AlertSecAgent, store.AlertSecTLS, store.AlertSecPort, store.AlertDNSFailed, store.AlertDNSChange, store.AlertUserExpiry, store.AlertUserTraffic, store.AlertBillDue, store.AlertAWGDown, store.AlertAWGToolsOld, store.AlertHostDisk, store.AlertHostCPU, store.AlertHostMem, store.AlertHostFlood}

// ProbeFailures is how many probes in a row must fail before a channel counts as down: one lost
// packet is not an outage.
const ProbeFailures = 3

func minutes(d time.Duration) string {
	m := int(d.Round(time.Minute) / time.Minute)
	switch {
	case m >= 120:
		return fmt.Sprintf("%d ч", m/60)
	case m >= 1:
		return fmt.Sprintf("%d мин", m)
	}
	return "меньше минуты"
}

// Conditions lists everything wrong at moment now. It is a pure function of the states it is given.
func Conditions(agents []store.AgentState, panels []store.PanelState, probes []store.ProbeState, now time.Time) []store.Condition {
	var out []store.Condition
	for _, a := range agents {
		// An agent that was never heard from is "waiting to be installed", not "gone".
		if a.Status != "active" || a.LastSeen == nil {
			continue
		}
		if quiet := now.Sub(*a.LastSeen); quiet > AgentSilentAfter {
			label := "Агент ноды " + a.NodeName
			if a.Kind == "router" {
				label = "Агент роутера"
				if a.Name != "" {
					label += " " + a.Name
				}
			}
			out = append(out, store.Condition{PanelID: a.PanelID, Kind: store.AlertAgentSilent, Subject: a.AgentID, Label: label,
				Detail: "не выходит на связь " + minutes(quiet) + "; события за это время не собираются"})
		}
	}
	for _, p := range panels {
		open := p.Open != nil && p.Open.After(now)
		if p.Failures < PanelFailures && !open {
			continue
		}
		detail := fmt.Sprintf("синхронизация не удаётся: %d неудач подряд", p.Failures)
		if p.LastSync != nil {
			detail += ", последняя успешная " + minutes(now.Sub(*p.LastSync)) + " назад"
		}
		if open {
			detail += "; панель временно отключена от опроса (защита от перегрузки)"
		}
		out = append(out, store.Condition{PanelID: p.PanelID, Kind: store.AlertPanelSync, Subject: p.PanelID, Label: "Панель " + p.Name, Detail: detail})
	}
	for _, p := range probes {
		if len(p.Recent) < ProbeFailures {
			continue
		}
		down := true
		for _, ok := range p.Recent[:ProbeFailures] {
			down = down && !ok
		}
		if down {
			detail := fmt.Sprintf("не отвечает: %d проверки подряд", ProbeFailures)
			if p.LastErr != "" {
				detail += " (" + p.LastErr + ")"
			}
			out = append(out, store.Condition{PanelID: p.PanelID, Kind: store.AlertProbeDown, Subject: p.TargetID, Label: "Канал " + p.Name, Detail: detail})
		}
	}
	return out
}

// Evaluate reads the state and applies it to the alerts table.
func Evaluate(ctx context.Context, st *store.Store, now time.Time) (opened, closed int, err error) {
	agents, err := st.AgentStates(ctx)
	if err != nil {
		return 0, 0, err
	}
	panels, err := st.PanelStates(ctx)
	if err != nil {
		return 0, 0, err
	}
	probes, err := st.ProbeStates(ctx, now)
	if err != nil {
		return 0, 0, err
	}
	sec, err := st.SecurityAlertStates(ctx)
	if err != nil {
		return 0, 0, err
	}
	dns, err := st.DNSAlertStates(ctx, now)
	if err != nil {
		return 0, 0, err
	}
	users, err := st.UserLimitStates(ctx)
	if err != nil {
		return 0, 0, err
	}
	bills, err := st.BillDueStates(ctx)
	if err != nil {
		return 0, 0, err
	}
	awgs, err := st.AWGContainerStates(ctx, now)
	if err != nil {
		return 0, 0, err
	}
	hosts, err := st.HostAlertStates(ctx, now)
	if err != nil {
		return 0, 0, err
	}
	conds := append(Conditions(agents, panels, probes, now), SecurityConditions(sec, now)...)
	floods, err := st.HostFloodStates(ctx, now)
	if err != nil {
		return 0, 0, err
	}
	conds = append(conds, HostConditions(hosts)...)
	conds = append(conds, FloodConditions(floods)...)
	conds = append(conds, AWGConditions(awgs, now)...)
	conds = append(conds, DNSConditions(dns, now)...)
	conds = append(conds, UserConditions(users, now)...)
	return st.ApplyConditions(ctx, Kinds, append(conds, BillConditions(bills, now)...), now)
}

// Run evaluates every interval until ctx ends.
func Run(ctx context.Context, st *store.Store, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		now := time.Now().UTC()
		if o, c, err := Evaluate(ctx, st, now); err != nil {
			log.Error("alert evaluation failed", "err", err)
		} else if o > 0 || c > 0 {
			log.Info("alerts", "opened", o, "closed", c)
		}
		_ = st.PurgeResolvedAlerts(ctx, now.AddDate(0, 0, -90))
		_ = st.PurgeHostSamples(ctx, now.AddDate(0, 0, -7))
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
