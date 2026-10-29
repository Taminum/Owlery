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
	// Container is the Docker container that publishes this port, when the machine told the agent which ones do.
	Container string `json:"container,omitempty"`
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

// --- commands ------------------------------------------------------------------------------------
//
// The server can ask an agent that announced "fail2ban_ban" to ban or unban one address in one jail. These
// are the only two commands there are, they carry no free text, and the agent checks every field again.
// A command is delivered over the live connection or not at all: nothing is queued for later.

const CapFail2banBan = "fail2ban_ban"

const (
	OpBan   = "ban"
	OpUnban = "unban"
)

// MaxCommandTTL bounds how long an agent may take to carry a command out, counted from when it arrives.
const MaxCommandTTL = 60

type Command struct {
	Type       string `json:"type"` // "command"
	ID         string `json:"id"`   // a UUID chosen by the server; the agent runs one ID at most once
	Op         string `json:"op"`   // ban | unban
	Jail       string `json:"jail"`
	IP         string `json:"ip"`
	TTLSeconds int    `json:"ttl"` // the agent refuses to start the command later than this after receiving it
}

// Command results. Only "executed" and "already_done" mean the address is in the wanted state, and only
// when Verified says the agent saw it so afterwards.
const (
	CmdExecuted    = "executed"
	CmdAlreadyDone = "already_done" // it was banned (or not banned) already, so nothing was changed
	CmdRejected    = "rejected"     // refused before anything ran: a bad field, an unknown jail, a protected address
	CmdFailed      = "failed"
	CmdExpired     = "expired"
	CmdDuplicate   = "duplicate" // this ID was already carried out, once, possibly before a restart
)

type CommandResult struct {
	Type     string `json:"type"` // "command_result"
	ID       string `json:"id"`
	Status   string `json:"status"`
	Code     string `json:"code,omitempty"` // a short machine word for the reason
	Verified bool   `json:"verified"`       // the state was read again after the command and is as wanted
}

// --- probes --------------------------------------------------------------------------------------
//
// An agent that its host set up as a checker ("probe" capability) is asked to look at a public address from
// where it stands: connect to a TCP port, or read the certificate a TLS endpoint presents. It sends no data on
// a TCP probe, dials only public addresses (re-checked on the agent, whatever the server asks), and never
// returns more than the fields below. A probe is delivered over the live connection or not at all.

const CapProbe = "probe"

const (
	ProbeTCP = "tcp"
	ProbeTLS = "tls"
)

type Probe struct {
	Type string `json:"type"` // "probe"
	ID   string `json:"id"`   // chosen by the server; an answer for any other ID is dropped
	Kind string `json:"kind"` // tcp | tls
	Host string `json:"host"` // an IP address or a domain name
	Port int    `json:"port"`
	SNI  string `json:"sni,omitempty"`
}

// ProbeTLS is what a TLS endpoint presented, as the agent saw it.
type ProbeTLSResult struct {
	State       string    `json:"state"`
	IP          string    `json:"ip"`
	Resolved    []string  `json:"resolved,omitempty"`
	SNI         string    `json:"sni"`
	NameChecked bool      `json:"name_checked"`
	Version     string    `json:"version,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	DNSNames    []string  `json:"dns_names,omitempty"`
	Serial      string    `json:"serial,omitempty"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	DaysLeft    int       `json:"days_left"`
	HasCert     bool      `json:"has_cert"`
	Error       string    `json:"error,omitempty"`
}

type ProbeResult struct {
	Type string `json:"type"` // "probe_result"
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// Refused is set when the agent would not run the probe at all: bad_request, busy.
	Refused string `json:"refused,omitempty"`
	// TCP
	Result string `json:"result,omitempty"`
	IP     string `json:"ip,omitempty"`
	RTTms  int    `json:"rtt_ms,omitempty"`
	Error  string `json:"error,omitempty"`
	// TLS
	TLS *ProbeTLSResult `json:"tls,omitempty"`
}

// --- host resources -------------------------------------------------------------------------------
//
// Every full tick the agent also tells how loaded the host is. It is not a snapshot of the journal: it carries no
// sequence number, is not acknowledged and is not kept as a history of changes. A lost one is a gap in a chart.

const MaxHostDisks = 8

type HostDisk struct {
	Mount string `json:"m"`
	FS    string `json:"fs,omitempty"`
	Total int64  `json:"t"`
	Used  int64  `json:"u"`
}

type Host struct {
	Type string    `json:"type"` // "host"
	At   time.Time `json:"at"`
	// What the machine is: it changes only with an upgrade.
	OS       string `json:"os,omitempty"`
	Kernel   string `json:"kernel,omitempty"`
	Arch     string `json:"arch,omitempty"`
	CPUModel string `json:"cpu_model,omitempty"`
	CPUs     int    `json:"cpus,omitempty"`
	MemTotal int64  `json:"mem_total,omitempty"`
	// What it does now. CPUPct is -1 until the agent has two readings to compare.
	CPUPct    float64 `json:"cpu"`
	Load1     float64 `json:"l1"`
	Load5     float64 `json:"l5"`
	Load15    float64 `json:"l15"`
	MemUsed   int64   `json:"mem_used"` // total minus what can be had without swapping
	SwapTotal int64   `json:"swap_total,omitempty"`
	SwapUsed  int64   `json:"swap_used,omitempty"`
	UptimeSec int64   `json:"up"`
	NetRX     int64   `json:"rx"` // counters over the real interfaces since boot
	NetTX     int64   `json:"tx"`
	// What a flood of packets or connections shows first. The counters run since boot; the connection counts are as of now.
	NetRXPkts int64      `json:"rxp,omitempty"`
	NetTXPkts int64      `json:"txp,omitempty"`
	Estab     int        `json:"estab"`             // established TCP connections
	SynRecv   int        `json:"syn"`               // half-open TCP connections (SYN received, not yet completed)
	Syncookie int64      `json:"cookies,omitempty"` // SYN cookies sent since boot: the kernel sends them only when its queue overflows
	ListenDrp int64      `json:"ldrops,omitempty"`  // connections dropped for a full listen queue since boot
	Conntrack int64      `json:"ct,omitempty"`      // entries in the connection tracking table, 0 when it is not in use
	ConntrMax int64      `json:"ct_max,omitempty"`
	Disks     []HostDisk `json:"disks,omitempty"`
	// Procs are the busiest groups of processes by processor and by memory, at most MaxHostProcs. Only the short
	// program name and the unit it runs in are sent, never the command line, which may carry a secret.
	Procs []HostProc `json:"procs,omitempty"`
	// Units are the busiest services and containers as a whole: all their processes added up.
	Units []HostUnit `json:"units,omitempty"`
}

const MaxHostUnits = 16

// HostUnit is one service or container with everything that runs in it.
type HostUnit struct {
	Unit  string  `json:"u"`           // "name.service" or "docker:<12 characters>"
	Label string  `json:"l,omitempty"` // the container's name, when the host could tell
	Count int     `json:"c"`           // processes in it
	CPU   float64 `json:"cpu"`         // percent of one core
	RSS   int64   `json:"rss"`
}

const MaxHostProcs = 24

// HostProc is a group of processes with the same program name in the same unit (a service or a container).
type HostProc struct {
	Name  string  `json:"n"`
	Label string  `json:"l,omitempty"` // the container's name, when the host could tell
	Unit  string  `json:"u,omitempty"` // a systemd unit, or "docker:<12 characters>" for a container
	Count int     `json:"c"`           // how many processes
	CPU   float64 `json:"cpu"`         // percent of one core, so more than 100 is possible on several cores
	RSS   int64   `json:"rss"`         // resident memory in bytes
}

// CapShell is announced by an agent whose machine allows a terminal: on Linux a root helper is installed next to the
// agent (the agent itself is not root), on Windows the agent was installed with -allow-shell.
const CapShell = "shell"

// ShellPath is where an agent connects back for one terminal session, with its own credential and ?id=<session>.
// The session's bytes go over that connection alone, so a busy terminal never holds up the agent's reports.
const ShellPath = Path + "/shell"

// ShellOpen asks the agent to start a terminal session and connect back to ShellPath with its ID.
type ShellOpen struct {
	Type string `json:"type"` // "shell_open"
	ID   string `json:"id"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

// ShellResize travels as a text frame on a terminal connection; everything else on it is binary terminal data.
type ShellResize struct {
	Type string `json:"type"` // "resize"
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

// CapDesktop is announced by an agent whose machine allows its remote desktop to be reached through the agent:
// Owlery asks for a tunnel to one local port (RDP or VNC) and the agent connects back to TunnelPath with it.
const CapDesktop = "desktop"

const TunnelPath = Path + "/tunnel"

// DesktopPorts are the only local ports a tunnel may lead to: RDP and VNC.
var DesktopPorts = map[int]bool{3389: true, 5900: true}

// The first frame of a tunnel connection, a text frame from the agent: whether the local port answered.
const (
	TunnelReady      = "ready"
	TunnelPortClosed = "port_closed"
)

// TunnelOpen asks the agent to connect to 127.0.0.1:Port and back to TunnelPath with the session ID.
type TunnelOpen struct {
	Type string `json:"type"` // "tunnel_open"
	ID   string `json:"id"`
	Port int    `json:"port"`
}

// CapRemote is announced by an agent whose machine has the remote-control helper set up (Windows, for now): full
// interactive control through a second, user-session process (screen, mouse, keyboard), not a server reached through
// RDP/VNC. It is a different thing from CapDesktop: that one dials the machine's own RDP/VNC server; this one is the
// agent's own picture of the screen the signed-in person actually sees.
const CapRemote = "remote"

const RemotePath = Path + "/remote"

// RemoteHelperPort is the fixed loopback port the remote-control helper listens on. Nothing but the agent itself may
// speak to it: the first bytes of a connection must be the shared secret written when the helper was installed.
const RemoteHelperPort = 47821

// RemoteHelperPortFor is the port of the helper that serves one Windows session. Each session has its own helper: a
// helper started for the console cannot show the desktop of an administrator who is signed in over remote desktop.
func RemoteHelperPortFor(session uint32) int { return RemoteHelperPort + int(session%1000) }

// RemoteOpen asks the agent to relay a session to its remote-control helper.
type RemoteOpen struct {
	Type string `json:"type"` // "remote_open"
	ID   string `json:"id"`
}

// CapWeb is announced by an agent whose machine lets Owlery reach web services bound to 127.0.0.1 on it (an admin
// panel such as Komodo or Portainer), so that their ports need not be open to the network. Off unless the machine
// was set up with -allow-web.
const CapWeb = "web"

// ProxyPath is where an agent connects back for one connection to a local web service.
const ProxyPath = Path + "/proxy"

// ProxyOpen asks the agent to connect to 127.0.0.1:Port and back to ProxyPath with the session ID. The first frame on
// that connection is TunnelReady or TunnelPortClosed, as for a desktop tunnel.
type ProxyOpen struct {
	Type string `json:"type"` // "proxy_open"
	ID   string `json:"id"`
	Port int    `json:"port"`
}

// CapAdmin is announced by an agent whose machine lets Owlery manage it from the server card (processes, services,
// startup entries, sessions, event log, connections). Windows only, and off unless the machine was set up with
// -allow-admin: the agent runs as the system account there, so this is as strong as the terminal.
const CapAdmin = "admin"

// Admin operations. The first group only reads; the second changes the machine and is written to the audit log.
const (
	AdminProcs    = "procs"
	AdminServices = "services"
	AdminStartup  = "startup"
	AdminSessions = "sessions"
	AdminEvents   = "events"
	AdminConns    = "conns"

	AdminProcKill       = "proc_kill"
	AdminSvcStart       = "svc_start"
	AdminSvcStop        = "svc_stop"
	AdminSvcRestart     = "svc_restart"
	AdminSvcStartup     = "svc_startup"
	AdminStartupRemove  = "startup_remove"
	AdminStartupAdd     = "startup_add"
	AdminSessionLogoff  = "session_logoff"
	AdminSessionDisconn = "session_disconnect"
)

// AdminWrites are the operations that change the machine.
var AdminWrites = map[string]bool{
	AdminProcKill: true, AdminSvcStart: true, AdminSvcStop: true, AdminSvcRestart: true, AdminSvcStartup: true,
	AdminStartupRemove: true, AdminStartupAdd: true, AdminSessionLogoff: true, AdminSessionDisconn: true,
}

// AdminReads are the operations that only look.
var AdminReads = map[string]bool{AdminProcs: true, AdminServices: true, AdminStartup: true, AdminSessions: true, AdminEvents: true, AdminConns: true}

// AdminReq asks the agent for one operation. It is delivered over the live connection or not at all, and the answer
// comes back on the same connection, matched by ID; one for any other ID, or from another agent, is dropped.
type AdminReq struct {
	Type string          `json:"type"` // "admin_req"
	ID   string          `json:"id"`
	Op   string          `json:"op"`
	Args json.RawMessage `json:"args,omitempty"`
}

// AdminResult is the answer. Data is the operation's own JSON and is kept under MaxAdminData so the whole message fits
// MaxMessageBytes.
type AdminResult struct {
	Type  string          `json:"type"` // "admin_result"
	ID    string          `json:"id"`
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

const MaxAdminData = 900 << 10
