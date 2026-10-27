// Package ingestproto defines the messages an agent and the ingest endpoint exchange over a
// WebSocket. One JSON object per text frame, in this order:
//
//	agent -> hello            server -> welcome(ack_seq)
//	agent -> batch(items)     server -> ack(ack_seq)        (only after the rows are committed)
//	agent -> ping(spool)      server -> pong
//
// Sequence numbers are per agent and per epoch (an epoch is a random id the agent creates
// when it starts with no saved state). The server accepts a batch only if it continues
// exactly after the last acknowledged sequence, so nothing is lost or counted twice.
package ingestproto

import "time"

const (
	Version         = 1
	Path            = "/ingest/v1"
	MaxBatchLines   = 1000
	MaxLineBytes    = 2048
	MaxMessageBytes = 1 << 20
)

type Hello struct {
	Type         string `json:"type"` // "hello"
	ProtoVersion int    `json:"proto"`
	AgentVersion string `json:"agent_version"`
	Epoch        string `json:"epoch"`
	SourceID     string `json:"source_id"`
}

type Welcome struct {
	Type          string `json:"type"` // "welcome"
	AckSeq        int64  `json:"ack_seq"`
	MaxBatchLines int    `json:"max_batch_lines"`
}

type Item struct {
	Seq  int64  `json:"s"`
	Line string `json:"l"`
}

type Gap struct {
	From   *time.Time `json:"from,omitempty"`
	To     *time.Time `json:"to,omitempty"`
	Lines  int64      `json:"lines,omitempty"`
	Reason string     `json:"reason"`
}

type Batch struct {
	Type       string `json:"type"` // "batch"
	BatchID    string `json:"batch_id"`
	Items      []Item `json:"items"`
	Dropped    int64  `json:"dropped,omitempty"` // lines the agent had to discard since the last batch
	SpoolBytes int64  `json:"spool_bytes"`
	Gaps       []Gap  `json:"gaps,omitempty"`
}

type Ack struct {
	Type        string `json:"type"` // "ack"
	BatchID     string `json:"batch_id"`
	AckSeq      int64  `json:"ack_seq"`
	Accepted    int    `json:"accepted"`
	Duplicates  int    `json:"duplicates"`
	ParseErrors int    `json:"parse_errors"`
}

type Ping struct {
	Type       string `json:"type"` // "ping"
	SpoolBytes int64  `json:"spool_bytes"`
}

type Pong struct {
	Type string `json:"type"` // "pong"
}

type Error struct {
	Type        string `json:"type"` // "error"
	Code        string `json:"code"` // seq_gap | bad_batch | bad_message | revoked
	ExpectedSeq int64  `json:"expected_seq,omitempty"`
}

// Close codes (application range).
const (
	CloseRevoked   = 4401
	CloseProtocol  = 4400
	CloseSeqGap    = 4409
	CloseTooLarge  = 4413
	CloseRateLimit = 4429
)

// LiveDevice is one LAN device's speed over the last interval, in bytes per second.
type LiveDevice struct {
	IP   string `json:"ip"`
	Name string `json:"n,omitempty"`
	Up   int64  `json:"up"`
	Down int64  `json:"dn"`
	Conn int    `json:"c"`
}

// Live is a best-effort snapshot a router agent sends about the present moment. It is not part of
// the ordered, acknowledged stream: nothing replies to it, a lost one is simply a gap in a chart.
type Live struct {
	Type    string       `json:"type"` // "live"
	Conns   int          `json:"conns"`
	Up      int64        `json:"up"` // bytes per second, all devices
	Down    int64        `json:"dn"`
	Devices []LiveDevice `json:"devices,omitempty"`
}

const MaxLiveDevices = 60

// AWGPeer is one AmneziaWG peer as the interface reports it. Only public information travels:
// the public key, a name, the tunnel address and the counters. Never a private or preshared key.
type AWGPeer struct {
	Key       string `json:"k"`           // public key, base64
	Name      string `json:"n,omitempty"` // client name from the management table, if there is one
	IP        string `json:"ip,omitempty"`
	RX        int64  `json:"rx"` // bytes received from the peer since the interface came up
	TX        int64  `json:"tx"` // bytes sent to the peer
	Handshake int64  `json:"hs"` // unix seconds of the latest handshake, 0 = never
	// What the Amnezia management panel recorded about this client in its own table, as of
	// AWGInstance.LegacyAt (it is a snapshot, not live): totals from the client's side, and the latest
	// handshake. Zero means the panel had nothing.
	LegacyDown int64 `json:"ld,omitempty"` // "received" by the client = sent to it by the server
	LegacyUp   int64 `json:"lu,omitempty"`
	LegacyHS   int64 `json:"lhs,omitempty"`
	Created    int64 `json:"cr,omitempty"` // when the device was created, as the old table recorded it (unix seconds)
}

type AWGInstance struct {
	Container string    `json:"c"`
	Interface string    `json:"i"`
	Port      int       `json:"port,omitempty"`
	Fields    []string  `json:"f,omitempty"`   // names of the parameters found in the config (no values)
	Started   int64     `json:"st,omitempty"`  // when the container started (unix seconds): the counters count from about then
	LegacyAt  int64     `json:"lat,omitempty"` // when the Amnezia panel last wrote its client table
	Managed   bool      `json:"m,omitempty"`   // the host lets Owlery add and revoke devices here
	Peers     []AWGPeer `json:"peers"`
}

// AWG is a best-effort snapshot of the AmneziaWG interfaces on a host, like Live: unanswered, and a
// lost one is just a gap in a chart.
type AWG struct {
	Type      string        `json:"type"` // "awg"
	Instances []AWGInstance `json:"instances"`
	// ContainerAdmin says that the host has the helper that creates and removes containers installed. A host
	// with no container yet reports it too, which is how an empty server can be set up from Owlery.
	ContainerAdmin bool `json:"ca,omitempty"`
	// Containers is what each running container says about itself, whether or not it has an interface.
	Containers []AWGContainer `json:"cs,omitempty"`
}

// AWGContainer: a running container, the version of the awg tools inside it and of the host's kernel module, and
// whether it has no AmneziaWG interface (so nothing connects).
type AWGContainer struct {
	Name   string `json:"c"`
	Tools  string `json:"tv,omitempty"`
	Module string `json:"mv,omitempty"`
	Down   bool   `json:"d,omitempty"`
}

const (
	MaxAWGInstances = 8
	MaxAWGPeers     = 500
)

// AWGOp is a command the server sends to an AWG agent that has management switched on: add one
// device to, or revoke one device from, a container the host has declared managed. These are the only
// two commands there are. The agent checks every field again before it runs anything.
type AWGOp struct {
	Type      string `json:"type"` // "awg_op"
	ID        string `json:"id"`
	Op        string `json:"op"` // add | revoke | install | remove | export | restore
	Container string `json:"c"`
	Name      string `json:"n,omitempty"` // add: the device's name
	Key       string `json:"k,omitempty"` // revoke: the device's public key
	// install and remove act on a whole container and need the host to have opted in to container
	// administration (the "container_admin" capability). They carry no free text.
	Port    int    `json:"p,omitempty"` // install: the UDP port
	Subnet  string `json:"s,omitempty"` // install: the tunnel subnet, a /24 in 10.0.0.0/8
	Confirm string `json:"y,omitempty"` // remove: the confirmation word, which deletes every device in the container
	// restore: the files of a container's configuration, as export returned them.
	Files []AWGFile `json:"files,omitempty"`
}

// AWGFile is one file of a container's configuration, base64 encoded. The set is fixed (see AWGFileNames) and the
// content is secret: it holds the server's private key and every device's preshared key.
type AWGFile struct {
	Name string `json:"n"`
	Data string `json:"d"`
}

// AWGFileNames are the only files a backup carries.
var AWGFileNames = []string{"awg0.conf", "wireguard_server_private_key.key", "wireguard_server_public_key.key", "wireguard_psk.key", "clientsTable"}

// MaxAWGFilesBytes bounds the base64 text of all the files of one container.
const MaxAWGFilesBytes = 400 << 10

// AWGOpResult is the agent's answer. For a successful add it carries the new device's client
// configuration, which holds its private key: it is delivered once to whoever asked and kept nowhere.
type AWGOpResult struct {
	Type   string `json:"type"` // "awg_op_result"
	ID     string `json:"id"`
	Status string `json:"status"`         // ok | error
	Code   string `json:"code,omitempty"` // error: a short machine word
	Key    string `json:"k,omitempty"`    // the device's public key
	IP     string `json:"ip,omitempty"`   // its address in the tunnel
	Port   int    `json:"port,omitempty"` // install and restore: the port the container listens on
	// export: the container's configuration files. It is returned to the one who asked and kept nowhere.
	Files  []AWGFile `json:"files,omitempty"`
	Config string    `json:"cfg,omitempty"`
}

const MaxAWGConfigBytes = 16 << 10

// AWGFlow is the traffic of one flow in one window, as the sensor on the host saw it: which device (by its
// address in the tunnel), where it connected to, the bytes each way, and a name for the destination when the
// packets said one in the open. Never a payload, never a path.
type AWGFlow struct {
	Client string `json:"c"`
	Proto  uint8  `json:"p"`
	Remote string `json:"r"`
	Port   uint16 `json:"t"`
	Up     uint64 `json:"u"` // bytes from the device
	Down   uint64 `json:"d"` // bytes to the device
	Name   string `json:"n,omitempty"`
	How    string `json:"h,omitempty"` // sni | host | dns
	New    uint8  `json:"w,omitempty"` // 1 when the flow began in this window: one new connection
}

// AWGFlows is one reporting window of one container. Best effort, like AWG: a lost one is a gap.
type AWGFlows struct {
	Type      string    `json:"type"` // "awg_flows"
	Container string    `json:"c"`
	Start     int64     `json:"s"`
	End       int64     `json:"e"`
	Dropped   uint64    `json:"dp,omitempty"` // packets the sensor could not follow
	Left      uint64    `json:"lf,omitempty"` // flows left out of this report to keep it small
	Flows     []AWGFlow `json:"f"`
}

const MaxAWGFlows = 5000
