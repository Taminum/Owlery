package remnawave

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/safehttp"
)

// Paths from @remnawave/backend-contract 3.4.x.
const (
	pathNodes     = "/api/nodes"
	pathUsers     = "/api/users/"
	pathStats     = "/api/system/stats"
	pathMetadata  = "/api/system/metadata"
	pathBandwidth = "/api/bandwidth-stats/nodes"

	maxUsersPageSize = 500
)

// V3 implements PanelAdapter for the Remnawave 3.x API.
type V3 struct {
	base  string
	token string
	g     Getter
	now   func() time.Time
}

func NewV3(baseURL, token string, g Getter) *V3 {
	return &V3{base: strings.TrimRight(baseURL, "/"), token: token, g: g, now: time.Now}
}

func (a *V3) get(ctx context.Context, path string, q url.Values) ([]byte, error) {
	u := a.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	resp, err := a.g.Get(ctx, u, http.Header{"Authorization": {"Bearer " + a.token}})
	if err != nil {
		return nil, err
	}
	switch {
	case resp.Status >= 200 && resp.Status < 300:
		return resp.Body, nil
	case resp.Status == 401:
		return nil, &APIError{Code: CodeUnauthorized, Status: 401}
	case resp.Status == 403:
		return nil, &APIError{Code: CodeForbidden, Status: 403}
	case resp.Status == 404:
		return nil, &APIError{Code: CodeNotFound, Status: 404}
	case resp.Status == 429:
		return nil, &APIError{Code: CodeRateLimited, Status: 429, RetryAfter: 30 * time.Second}
	case resp.Status >= 500:
		return nil, &APIError{Code: CodeUpstream, Status: resp.Status}
	default:
		return nil, &APIError{Code: CodeUnexpected, Status: resp.Status}
	}
}

func decode(body []byte, v any) error {
	if err := json.Unmarshal(body, v); err != nil {
		return &APIError{Code: CodeIncompatible}
	}
	return nil
}

type nodeDTO struct {
	UUID             string          `json:"uuid"`
	Name             string          `json:"name"`
	CountryCode      string          `json:"countryCode"`
	IsConnected      *bool           `json:"isConnected"`
	IsDisabled       *bool           `json:"isDisabled"`
	UsersOnline      *int            `json:"usersOnline"`
	LastStatusChange *string         `json:"lastStatusChange"`
	TrafficUsedBytes json.RawMessage `json:"trafficUsedBytes"`
	Versions         *struct {
		Xray string `json:"xray"`
	} `json:"versions"`
}

// byteCount reads a non-negative integer counter. Only a JSON number is accepted: a quoted
// value or anything fractional or out of range is treated as "no counter", never guessed.
func byteCount(raw json.RawMessage) *int64 {
	if len(raw) == 0 || raw[0] == '"' || raw[0] == 'n' {
		return nil
	}
	var n json.Number
	if json.Unmarshal(raw, &n) != nil {
		return nil
	}
	i, err := n.Int64()
	if err != nil || i < 0 {
		return nil
	}
	return &i
}

func (a *V3) ListNodes(ctx context.Context) ([]Node, error) {
	body, err := a.get(ctx, pathNodes, nil)
	if err != nil {
		return nil, err
	}
	var env struct {
		Response []nodeDTO `json:"response"`
	}
	if err := decode(body, &env); err != nil {
		return nil, err
	}
	out := make([]Node, 0, len(env.Response))
	for _, d := range env.Response {
		if d.UUID == "" || d.Name == "" {
			continue // an identity we cannot trust is not recorded
		}
		n := Node{RemoteUUID: d.UUID, Name: d.Name, CountryCode: d.CountryCode, IsConnected: d.IsConnected, IsDisabled: d.IsDisabled, UsersOnline: d.UsersOnline}
		n.TrafficUsedBytes = byteCount(d.TrafficUsedBytes)
		if d.Versions != nil {
			n.XrayVersion = d.Versions.Xray
		}
		if d.LastStatusChange != nil {
			if t, err := time.Parse(time.RFC3339, *d.LastStatusChange); err == nil {
				n.LastStatusChange = &t
			}
		}
		out = append(out, n)
	}
	if len(env.Response) > 0 && len(out) == 0 {
		return nil, &APIError{Code: CodeIncompatible} // data present but none of it recognisable
	}
	return out, nil
}

func rawString(m map[string]json.RawMessage, key string) string {
	var v string
	if raw, ok := m[key]; ok && json.Unmarshal(raw, &v) == nil {
		return v
	}
	return ""
}

// userIdentity is the panel's stable identifier for a user. Remnawave 3.4.x returns no
// "uuid" on users (observed on a real 3.4.3 panel): the identifier is the numeric "id", which
// is also what Xray writes as the log "email". shortUuid and vlessUuid are not used because
// they change when a subscription is revoked.
func userIdentity(row map[string]json.RawMessage) string {
	if u := rawString(row, "uuid"); u != "" {
		return u
	}
	if raw, ok := row["id"]; ok && len(raw) > 0 && raw[0] != '"' { // a JSON number only, never a string
		var n json.Number
		if json.Unmarshal(raw, &n) == nil {
			if i, err := n.Int64(); err == nil && i > 0 {
				return strconv.FormatInt(i, 10)
			}
		}
	}
	return ""
}

func (a *V3) ListUsers(ctx context.Context, offset, size int) (UsersPage, error) {
	if size <= 0 || size > maxUsersPageSize {
		size = maxUsersPageSize
	}
	if offset < 0 {
		offset = 0
	}
	body, err := a.get(ctx, pathUsers, url.Values{"start": {strconv.Itoa(offset)}, "size": {strconv.Itoa(size)}})
	if err != nil {
		return UsersPage{}, err
	}
	var env struct {
		Response struct {
			Users []map[string]json.RawMessage `json:"users"`
			Total int                          `json:"total"`
		} `json:"response"`
	}
	if err := decode(body, &env); err != nil {
		return UsersPage{}, err
	}
	page := UsersPage{Total: env.Response.Total, Next: -1}
	seen := map[string]bool{}
	for _, row := range env.Response.Users {
		uuid := userIdentity(row)
		if uuid == "" {
			page.Skipped++
			for k := range row {
				if !seen[k] && len(seen) < 40 {
					seen[k] = true
					page.SkippedFields = append(page.SkippedFields, k)
				}
			}
			continue
		}
		u := User{RemoteUUID: uuid, Username: rawString(row, "username"), Status: rawString(row, "status")}
		if raw, ok := row["userTraffic"]; ok {
			var ut struct {
				Used     json.RawMessage `json:"usedTrafficBytes"`
				Lifetime json.RawMessage `json:"lifetimeUsedTrafficBytes"`
			}
			if json.Unmarshal(raw, &ut) == nil {
				u.UsedBytes, u.LifetimeBytes = byteCount(ut.Used), byteCount(ut.Lifetime)
			}
		}
		if s := rawString(row, "expireAt"); s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				u.ExpireAt = &t
			}
		}
		u.LimitBytes = byteCount(row["trafficLimitBytes"])
		if u.UsedBytes != nil || u.LifetimeBytes != nil {
			page.WithCounter++
		}
		page.Users = append(page.Users, u)
	}
	sort.Strings(page.SkippedFields)
	got := len(env.Response.Users)
	if got > 0 && offset+got < page.Total {
		page.Next = offset + got
	}
	return page, nil
}

// GetTrafficCounters arrives with M3 (authoritative counters, reset handling).
func (a *V3) GetTrafficCounters(context.Context, time.Time, time.Time) ([]TrafficCounter, error) {
	return nil, ErrNotImplemented
}

func (a *V3) GetCapabilities(ctx context.Context) (Capabilities, error) {
	p := a.Probe(ctx)
	if !p.Reachable {
		return Capabilities{}, &APIError{Code: CodeUpstream}
	}
	return p.Capabilities, nil
}

// Probe runs the connection checks in order. Nothing here writes to the panel or stores anything.
func (a *V3) Probe(ctx context.Context) ProbeResult {
	var res ProbeResult
	add := func(name string, required bool, start time.Time, err error, unsupportedOK bool) bool {
		c := Check{Name: name, Required: required, LatencyMS: time.Since(start).Milliseconds(), Status: CheckOK}
		if err != nil {
			c.ErrorCode = ErrorCode(err)
			c.Status = CheckFailed
			if unsupportedOK && c.ErrorCode == CodeNotFound {
				c.Status = CheckUnsupported
			}
		}
		res.Checks = append(res.Checks, c)
		return err == nil
	}
	skip := func(name string, required bool) {
		res.Checks = append(res.Checks, Check{Name: name, Required: required, Status: CheckSkipped})
	}

	// 1. Reachability + TLS + authentication in one request: the node list.
	t := time.Now()
	nodes, err := a.ListNodes(ctx)
	var ae *APIError
	gotHTTP := false
	switch {
	case err == nil:
		gotHTTP = true
	case asAPIError(err, &ae):
		gotHTTP = true // any HTTP answer proves connectivity and a valid certificate
	}
	res.Reachable, res.TLSOK = gotHTTP, gotHTTP
	conn := Check{Name: "connection", Required: true, LatencyMS: time.Since(t).Milliseconds(), Status: CheckOK}
	if !gotHTTP {
		conn.Status, conn.ErrorCode = CheckFailed, ErrorCode(err)
		res.Checks = append(res.Checks, conn)
		skip("auth", true)
		skip("nodes", true)
		skip("users", false)
		skip("stats", false)
		skip("version", false)
		return res
	}
	res.Checks = append(res.Checks, conn)

	// Only an answer that proves the token was accepted counts as authenticated:
	// a 2xx, or a 2xx whose body we could not read. 401/403 mean rejected; 404, 429
	// and 5xx say nothing about the token, so auth stays unproven.
	authenticated := err == nil || (ae != nil && ae.Code == CodeIncompatible)
	if !authenticated {
		code := ae.Code
		res.Checks = append(res.Checks, Check{Name: "auth", Required: true, Status: CheckFailed, ErrorCode: code, LatencyMS: time.Since(t).Milliseconds()})
		skip("nodes", true)
		skip("users", false)
		skip("stats", false)
		skip("version", false)
		return res
	}
	res.Authenticated = true
	res.Checks = append(res.Checks, Check{Name: "auth", Required: true, Status: CheckOK, LatencyMS: time.Since(t).Milliseconds()})

	if add("nodes", true, t, err, false) {
		res.Capabilities.Nodes = true
		res.NodeCount = len(nodes)
		for i, n := range nodes {
			if i == 10 {
				break
			}
			res.NodesPreview = append(res.NodesPreview, n.Name)
		}
	} else {
		skip("users", false)
		skip("stats", false)
		skip("version", false)
		return res
	}

	// 2. Optional features: each one is probed on its own so a missing permission
	//    degrades that feature only.
	t = time.Now()
	_, uerr := a.ListUsers(ctx, 0, 1)
	res.Capabilities.Users = add("users", false, t, uerr, true)

	t = time.Now()
	_, serr := a.get(ctx, pathStats, nil)
	statsOK := serr == nil
	res.Capabilities.SystemStats = statsOK
	day := a.now().UTC().Format("2006-01-02")
	_, berr := a.get(ctx, pathBandwidth, url.Values{"start": {day}, "end": {day}})
	res.Capabilities.Bandwidth = berr == nil
	switch {
	case statsOK && berr == nil:
		add("stats", false, t, nil, true)
	case statsOK:
		add("stats", false, t, berr, true)
	default:
		add("stats", false, t, serr, true)
	}

	t = time.Now()
	body, merr := a.get(ctx, pathMetadata, nil)
	if add("version", false, t, merr, true) {
		var env struct {
			Response struct {
				Version string `json:"version"`
			} `json:"response"`
		}
		if json.Unmarshal(body, &env) == nil && validVersion(env.Response.Version) {
			res.APIVersion = env.Response.Version
			res.Capabilities.Metadata = true
		}
	}
	return res
}

func asAPIError(err error, target **APIError) bool {
	if e, ok := err.(*APIError); ok { //nolint:errorlint // exact type is what we want here
		*target = e
		return true
	}
	return false
}

func validVersion(v string) bool {
	if v == "" || len(v) > 32 {
		return false
	}
	for _, r := range v {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '.' || r == '-' || r == '+') {
			return false
		}
	}
	return true
}

var _ PanelAdapter = (*V3)(nil)
var _ Getter = (*safehttp.Client)(nil)

func (c Check) String() string { return fmt.Sprintf("%s=%s", c.Name, c.Status) }
