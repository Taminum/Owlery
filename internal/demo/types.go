package demo

import "time"

// Metric kinds are never mixed on one axis: connection counts and bytes live in
// separate series, each with its own source.
const (
	KindConnections = "connection_count"
	KindBytes       = "bytes"
)

type Gap struct {
	NodeID   string    `json:"node_id"`
	NodeName string    `json:"node_name"`
	PanelID  string    `json:"panel_id"`
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
}

type Coverage struct {
	Pct  float64 `json:"pct"`
	Gaps []Gap   `json:"gaps"`
}

type Meta struct {
	Demo               bool      `json:"demo"`
	State              string    `json:"state"` // ok | no_data | sync_pending
	Reason             string    `json:"reason,omitempty"`
	GeneratedAt        time.Time `json:"generated_at"`
	From               time.Time `json:"from"`
	To                 time.Time `json:"to"`
	GranularitySeconds int       `json:"granularity_seconds"`
	PanelIDs           []string  `json:"panel_ids"`
	NodeIDs            []string  `json:"node_ids"`
	Coverage           Coverage  `json:"coverage"`
}

type Series struct {
	TS []int64   `json:"ts"`
	V  []float64 `json:"v"`
}

type ConnectionsKPI struct {
	MetricKind string   `json:"metric_kind"`
	Source     string   `json:"source"`
	Total      int      `json:"total"`
	TCP        int      `json:"tcp"`
	UDP        int      `json:"udp"`
	DeltaPct   *float64 `json:"delta_pct"`
	Series     Series   `json:"series"`
}

type CountKPI struct {
	MetricKind string `json:"metric_kind"`
	Source     string `json:"source"`
	Value      int    `json:"value"`
	Series     Series `json:"series"`
}

type NodesKPI struct {
	Reporting int `json:"reporting"`
	Total     int `json:"total"`
}

type TrafficKPI struct {
	MetricKind  string         `json:"metric_kind"`
	Source      string         `json:"source"`
	Unit        string         `json:"unit"`
	UpBytes     int64          `json:"up_bytes"`
	DownBytes   int64          `json:"down_bytes"`
	CoveragePct float64        `json:"coverage_pct"`
	Series      []TrafficPoint `json:"series"`
	// Real panels give one cumulative counter, with no up/down split: the total is reported as a
	// total (TotalBytes is null when there are no samples) and the split fields stay zero.
	TotalBytes  *int64       `json:"total_bytes"`
	TotalSeries []TotalPoint `json:"total_series"`
	ResetCount  int          `json:"counter_resets"`
}

type TotalPoint struct {
	TS    int64 `json:"ts"`
	Bytes int64 `json:"bytes"`
}

type TrafficPoint struct {
	TS   int64 `json:"ts"`
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

type Freshness struct {
	LastEventAt time.Time `json:"last_event_at"`
	LagSeconds  int       `json:"lag_seconds"`
	Status      string    `json:"status"` // ok | stale
}

type TimelinePoint struct {
	TS  int64 `json:"ts"`
	TCP int   `json:"tcp"`
	UDP int   `json:"udp"`
	Gap bool  `json:"gap"`
}

type Row struct {
	Key        string  `json:"key"`
	Label      string  `json:"label"`
	Note       string  `json:"note,omitempty"`
	PanelID    string  `json:"panel_id,omitempty"`
	PanelName  string  `json:"panel_name,omitempty"`
	Count      int     `json:"count"`
	Share      float64 `json:"share"`
	Confidence string  `json:"confidence,omitempty"`
	Other      bool    `json:"other,omitempty"`
}

type Recent struct {
	TS        time.Time `json:"ts"`
	PanelID   string    `json:"panel_id"`
	PanelName string    `json:"panel_name"`
	NodeName  string    `json:"node_name"`
	UserLabel string    `json:"user_label"`
	Protocol  string    `json:"protocol"`
	Dest      string    `json:"dest"`
	DestType  string    `json:"dest_type"` // domain | ip
}

type Overview struct {
	Meta        Meta            `json:"meta"`
	Connections ConnectionsKPI  `json:"connections"`
	UniqueHosts CountKPI        `json:"unique_hosts"`
	UniqueIPs   CountKPI        `json:"unique_ips"`
	Nodes       NodesKPI        `json:"nodes"`
	Traffic     TrafficKPI      `json:"traffic"`
	Freshness   Freshness       `json:"freshness"`
	Timeline    []TimelinePoint `json:"timeline"`
	TopHosts    []Row           `json:"top_hosts"`
	TopIPs      []Row           `json:"top_ips"`
	TopPorts    []Row           `json:"top_ports"`
	Services    []Row           `json:"services"`
	Users       []Row           `json:"users"`
	Recent      []Recent        `json:"recent"`
}

type PanelInfo struct {
	ID    string     `json:"id"`
	Name  string     `json:"name"`
	Nodes []NodeInfo `json:"nodes"`
}

type NodeInfo struct {
	ID          string `json:"id"`
	PanelID     string `json:"panel_id"`
	Name        string `json:"name"`
	AgentStatus string `json:"agent_status"` // ok | lagging
	LagSeconds  int    `json:"lag_seconds"`
}

type Query struct {
	PanelIDs []string
	NodeIDs  []string
	From, To time.Time
	Now      time.Time
	State    string // demo_state preview: "", "empty", "pending"
}
