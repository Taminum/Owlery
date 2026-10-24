package store

// AlertGroup is a set of alert kinds that the owner can switch on or off together in the notifications.
type AlertGroup struct {
	ID    string   `json:"id"`
	Kinds []string `json:"kinds"`
}

// AlertGroups are all the kinds there are, once each.
var AlertGroups = []AlertGroup{
	{"agents", []string{AlertAgentSilent, AlertProbeDown}},
	{"panels", []string{AlertPanelSync}},
	{"security", []string{AlertSecAgent, AlertSecTLS, AlertSecPort}},
	{"resources", []string{AlertHostDisk, AlertHostCPU, AlertHostMem}},
	{"flood", []string{AlertHostFlood}},
	{"awg", []string{AlertAWGDown, AlertAWGToolsOld}},
	{"dns", []string{AlertDNSFailed, AlertDNSChange}},
	{"users", []string{AlertUserExpiry, AlertUserTraffic}},
	{"billing", []string{AlertBillDue}},
}

// AlertGroupOf names the group of an alert kind, "" for a kind nobody listed (it is then always announced).
func AlertGroupOf(kind string) string {
	for _, g := range AlertGroups {
		for _, k := range g.Kinds {
			if k == kind {
				return g.ID
			}
		}
	}
	return ""
}

// CriticalKinds are announced even in quiet hours and while muted: something is down or under attack.
var CriticalKinds = map[string]bool{
	AlertHostFlood: true, AlertAWGDown: true, AlertPanelSync: true, AlertProbeDown: true, AlertSecAgent: true, AlertAgentSilent: true,
}

// ValidAlertGroup says whether id names a group.
func ValidAlertGroup(id string) bool {
	for _, g := range AlertGroups {
		if g.ID == id {
			return true
		}
	}
	return false
}
