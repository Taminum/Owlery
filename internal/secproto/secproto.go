// Package secproto is the wire format between a security agent (secagent) and the security ingest
// endpoint, and the payloads it carries. One JSON object per text frame:
//
//	agent -> hello       server -> welcome(ack_seq)
//	agent -> snapshot    server -> ack(ack_seq)       (only after the row is committed)
//	agent -> ping        server -> pong
//
// The agent only reports what it observed. The server never sends it a command in this version, so a
// compromised server cannot make the agent run anything.
package secproto

import (
	"encoding/json"
	"time"
)

const (
	Version         = 1
	Path            = "/ingest/security/v1"
	MaxMessageBytes = 1 << 20
	MaxDataBytes    = 256 << 10
	// StaleAfter is how long a snapshot may go unrefreshed before the server calls it stale. Agents
	// report every 30 seconds.
	StaleAfter = 2 * time.Minute
)

// Categories a snapshot may belong to.
const (
	CatFail2ban = "fail2ban"
	CatSockets  = "sockets"
	CatFirewall = "firewall"
)

func ValidCategory(c string) bool { return c == CatFail2ban || c == CatSockets || c == CatFirewall }

// EventCategories are the categories the journal can be filtered by: the agent's three plus the
// external checks'.
func ValidEventCategory(c string) bool { return ValidCategory(c) || c == "ports" || c == "tls" }

// Collection statuses. Anything but ok means Data is empty or partial and must not be read as "nothing found".
const (
	StatusOK               = "ok"
	StatusNotInstalled     = "not_installed"
	StatusStopped          = "stopped"
	StatusPermissionDenied = "permission_denied"
	StatusUnsupported      = "unsupported"
	StatusError            = "error"
)

func ValidStatus(s string) bool {
	switch s {
	case StatusOK, StatusNotInstalled, StatusStopped, StatusPermissionDenied, StatusUnsupported, StatusError:
		return true
	}
	return false
}

type Hello struct {
	Type         string   `json:"type"` // "hello"
	ProtoVersion int      `json:"proto"`
	AgentVersion string   `json:"agent_version"`
	Epoch        string   `json:"epoch"`
	Hostname     string   `json:"hostname,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"` // fail2ban_read | socket_read | firewall_read
}

type Welcome struct {
	Type            string `json:"type"` // "welcome"
	AckSeq          int64  `json:"ack_seq"`
	IntervalSeconds int    `json:"interval_seconds"`
}

type Snapshot struct {
	Type       string          `json:"type"` // "snapshot"
	Seq        int64           `json:"s"`
	Category   string          `json:"cat"`
	Schema     int             `json:"schema"`
	ObservedAt time.Time       `json:"at"`
	Status     string          `json:"status"`
	Data       json.RawMessage `json:"data,omitempty"`
}

type Ack struct {
	Type   string `json:"type"` // "ack"
	AckSeq int64  `json:"ack_seq"`
	Stored bool   `json:"stored"` // false: a repeat of something already acknowledged
}

type Ping struct {
	Type string `json:"type"` // "ping"
}

type Pong struct {
	Type string `json:"type"` // "pong"
}

type Error struct {
	Type string `json:"type"` // "error"
	Code string `json:"code"` // bad_message | bad_snapshot | revoked
}

const (
	CloseRevoked  = 4401
	CloseProtocol = 4400
)

// --- payloads ------------------------------------------------------------------------------------

const (
	MaxJails      = 200
	MaxBannedIPs  = 5000
	MaxListeners  = 2000
	MaxRulesBytes = 64 << 10
)

type Jail struct {
	Name            string   `json:"name"`
	CurrentlyFailed int      `json:"currently_failed"`
	TotalFailed     int      `json:"total_failed"`
	CurrentlyBanned int      `json:"currently_banned"`
	TotalBanned     int      `json:"total_banned"`
	BannedIPs       []string `json:"banned_ips"`
}

type Fail2ban struct {
	Jails []Jail `json:"jails"`
}

type Listener struct {
	Proto   string `json:"proto"` // tcp | udp
	Addr    string `json:"addr"`  // local address as bound: 0.0.0.0, ::, 127.0.0.1, a specific address
	Port    int    `json:"port"`
	State   string `json:"state,omitempty"`
	Process string `json:"process,omitempty"` // only when the agent was allowed to see it
	PID     int    `json:"pid,omitempty"`
}

type Sockets struct {
	Listeners   []Listener `json:"listeners"`
	ProcessInfo bool       `json:"process_info"` // false: process names were not readable, not "no process"
}

type Firewall struct {
	Backend   string `json:"backend"` // nft | iptables | ufw
	Rules     string `json:"rules"`   // canonical text: counters, handles and timestamps removed
	Truncated bool   `json:"truncated,omitempty"`
}
