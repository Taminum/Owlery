// Package remnawave talks to a Remnawave panel's REST API.
//
// Endpoints and field names follow @remnawave/backend-contract 3.4.x. They are an
// adapter detail: every version difference is absorbed here and surfaced as a
// capability flag, never assumed. See testdata/README.md for how the fixtures were made.
package remnawave

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Taminum/RemnaScope/internal/safehttp"
)

// Getter is the HTTP surface the adapter needs. *safehttp.Client satisfies it in
// production; tests substitute a plain client against httptest.
type Getter interface {
	Get(ctx context.Context, rawURL string, header http.Header) (*safehttp.Response, error)
}

type Capabilities struct {
	Nodes       bool `json:"nodes"`
	Users       bool `json:"users"`
	SystemStats bool `json:"system_stats"`
	Bandwidth   bool `json:"bandwidth_stats"`
	Metadata    bool `json:"metadata"`
}

type Node struct {
	RemoteUUID       string
	Name             string
	CountryCode      string
	XrayVersion      string
	IsConnected      *bool
	IsDisabled       *bool
	UsersOnline      *int
	LastStatusChange *time.Time
	// TrafficUsedBytes is the node's cumulative counter ("trafficUsedBytes"), nil when the panel
	// did not send one. It can fall back to a small value when the panel resets it.
	TrafficUsedBytes *int64
}

type User struct {
	RemoteUUID string
	Username   string
	Status     string
	// Counters from "userTraffic". LifetimeBytes never goes down on its own; UsedBytes is the
	// current period's counter and resets with the user's traffic strategy. Either may be nil.
	LifetimeBytes *int64
	UsedBytes     *int64
}

// UsersPage is one offset-paginated page. Next is the offset for the following
// page, or -1 when the listing is complete.
type UsersPage struct {
	Users   []User
	Total   int
	Next    int
	Skipped int // rows without a usable UUID; never given an invented identity
	// SkippedFields are the field NAMES (never values) seen on skipped rows, to diagnose API differences.
	SkippedFields []string
	// WithCounter is how many users on this page carried a traffic counter.
	WithCounter int
}

type TrafficCounter struct {
	NodeUUID   string
	Direction  string
	BytesTotal int64
	ObservedAt time.Time
}

type CheckStatus string

const (
	CheckOK          CheckStatus = "ok"
	CheckFailed      CheckStatus = "failed"
	CheckUnsupported CheckStatus = "unsupported"
	CheckSkipped     CheckStatus = "skipped"
)

type Check struct {
	Name      string      `json:"name"`
	Status    CheckStatus `json:"status"`
	LatencyMS int64       `json:"latency_ms"`
	ErrorCode string      `json:"error_code,omitempty"`
	Required  bool        `json:"required"`
}

type ProbeResult struct {
	Reachable     bool         `json:"reachable"`
	TLSOK         bool         `json:"tls_ok"`
	Authenticated bool         `json:"authenticated"`
	APIVersion    string       `json:"api_version,omitempty"`
	Capabilities  Capabilities `json:"capabilities"`
	NodesPreview  []string     `json:"nodes_preview,omitempty"`
	NodeCount     int          `json:"node_count"`
	Checks        []Check      `json:"checks"`
}

// RequiredOK is true when everything a panel cannot be saved without passed.
func (p ProbeResult) RequiredOK() bool {
	for _, c := range p.Checks {
		if c.Required && c.Status != CheckOK {
			return false
		}
	}
	return len(p.Checks) > 0
}

// PanelAdapter is implemented once per supported Remnawave API generation.
type PanelAdapter interface {
	Probe(ctx context.Context) ProbeResult
	ListNodes(ctx context.Context) ([]Node, error)
	ListUsers(ctx context.Context, offset, size int) (UsersPage, error)
	GetTrafficCounters(ctx context.Context, from, to time.Time) ([]TrafficCounter, error)
	GetCapabilities(ctx context.Context) (Capabilities, error)
}

// Error codes shown to operators.
const (
	CodeUnauthorized   = "unauthorized"       // 401
	CodeForbidden      = "missing_permission" // 403
	CodeNotFound       = "endpoint_not_found" // 404: this API version lacks the endpoint
	CodeRateLimited    = "rate_limited"       // 429
	CodeUpstream       = "upstream_error"     // 5xx
	CodeIncompatible   = "incompatible_api"   // 2xx but not the shape we know
	CodeUnexpected     = "unexpected_status"
	CodeNotImplemented = "not_implemented"
)

type APIError struct {
	Code       string
	Status     int
	RetryAfter time.Duration
}

func (e *APIError) Error() string { return "remnawave: " + e.Code }

var ErrNotImplemented = &APIError{Code: CodeNotImplemented}

// ErrorCode returns a stable, secret-free code for any error from this package or safehttp.
func ErrorCode(err error) string {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return safehttp.CodeOf(err)
}
