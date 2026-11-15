package store

// AlertGroup is a set of alert kinds that the owner can switch on or off together in the notifications.
type AlertGroup struct {
	ID    string   `json:"id"`
	Kinds []string `json:"kinds"`
}

// AlertGroups are all the kinds there are, once each.
var AlertGroups = []AlertGroup{
	{"agents", []string{AlertAgentSilent, AlertProbeDown, AlertNetDown, AlertNetInternet, AlertNetWAN}},
	{"panels", []string{AlertPanelSync, AlertPanelBackup}},
	{"security", []string{AlertSecAgent, AlertSecTLS, AlertSecPort, AlertLANNew, AlertNetForward}},
	{"resources", []string{AlertHostDisk, AlertHostDiskForecast, AlertHostCPU, AlertHostMem, AlertHostContainer, AlertHostContainerDown, AlertNetConnFull}},
	{"flood", []string{AlertHostFlood}},
	{"awg", []string{AlertAWGDown, AlertAWGToolsOld}},
	{"dns", []string{AlertDNSFailed, AlertDNSChange}},
	{"users", []string{AlertUserExpiry, AlertUserTraffic, AlertSubLeak, AlertTorrent}},
	{"billing", []string{AlertBillDue}},
	// Proxmox at home. Off by default in every channel (see migration 0066): the page shows these alerts either way.
	{"home", []string{AlertPVEGuest, AlertPVEDisk, AlertPVEBackup, AlertPVETailscale}},
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
