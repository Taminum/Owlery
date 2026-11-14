package remnawave

import (
	"context"
	"encoding/json"
	"hash/fnv"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	pathTorrentReports = "/api/node-plugins/torrent-blocker"
	pathHWIDDevices    = "/api/hwid/devices"
)

// TorrentReport is one time the torrent blocker of a node caught a subscription.
type TorrentReport struct {
	ID   int64
	User string
	Node string
	At   time.Time
}

// TorrentPage is one page of reports.
type TorrentPage struct {
	Reports []TorrentReport
	Total   int
}

// TorrentReader is implemented by adapters whose panel has the torrent blocker plugin. Separate, as older panels lack it.
type TorrentReader interface {
	TorrentReports(ctx context.Context, start, size int) (TorrentPage, error)
}

// Device is one device registered to a subscription.
type Device struct {
	HWID string
	User string
}

// DevicePage is one page of devices.
type DevicePage struct {
	Devices []Device
	Total   int
}

// DeviceReader is implemented by adapters whose panel keeps HWID devices.
type DeviceReader interface {
	HWIDDevices(ctx context.Context, start, size int) (DevicePage, error)
}

// scalar reads a number or a string as text: the panel gives ids as either.
func scalar(raw json.RawMessage) string {
	if len(raw) == 0 || raw[0] == 'n' {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	return ""
}

// firstScalar is the first of the keys the row has, also looking one level in (user.id) for "a.b" keys.
func firstScalar(row map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		if i := strings.IndexByte(k, '.'); i > 0 {
			var inner map[string]json.RawMessage
			if json.Unmarshal(row[k[:i]], &inner) == nil {
				if v := scalar(inner[k[i+1:]]); v != "" {
					return v
				}
			}
			continue
		}
		if v := scalar(row[k]); v != "" {
			return v
		}
	}
	return ""
}

// listOf finds the array of rows in a response envelope, whatever the panel calls it, and the total next to it.
func listOf(body []byte, names ...string) (rows []map[string]json.RawMessage, total int, err error) {
	var env struct {
		Response json.RawMessage `json:"response"`
	}
	if err := decode(body, &env); err != nil {
		return nil, 0, err
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(env.Response, &obj) != nil {
		if json.Unmarshal(env.Response, &rows) != nil {
			return nil, 0, &APIError{Code: CodeIncompatible}
		}
		return rows, len(rows), nil
	}
	for _, n := range names {
		if raw, ok := obj[n]; ok && json.Unmarshal(raw, &rows) == nil {
			break
		}
	}
	if t := byteCount(obj["total"]); t != nil {
		total = int(*t)
	} else {
		total = len(rows)
	}
	return rows, total, nil
}

func stableID(parts ...string) int64 {
	h := fnv.New64a()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return int64(h.Sum64() >> 1)
}

func (a *V3) TorrentReports(ctx context.Context, start, size int) (TorrentPage, error) {
	if size <= 0 || size > maxHistoryPageSize {
		size = maxHistoryPageSize
	}
	body, err := a.get(ctx, pathTorrentReports, url.Values{"start": {strconv.Itoa(max(start, 0))}, "size": {strconv.Itoa(size)}})
	if err != nil {
		return TorrentPage{}, err
	}
	rows, total, err := listOf(body, "records", "reports", "items")
	if err != nil {
		return TorrentPage{}, err
	}
	out := TorrentPage{Total: total, Reports: make([]TorrentReport, 0, len(rows))}
	for _, row := range rows {
		user := firstScalar(row, "userId", "userUuid", "user.id", "user.uuid")
		at, perr := time.Parse(time.RFC3339, firstScalar(row, "createdAt", "reportedAt", "timestamp", "at"))
		if user == "" || perr != nil {
			continue
		}
		node := firstScalar(row, "nodeName", "node.name", "nodeId", "nodeUuid", "node.uuid")
		id := int64(0)
		if v := byteCount(row["id"]); v != nil {
			id = *v
		} else {
			id = stableID(firstScalar(row, "id"), user, node, at.UTC().Format(time.RFC3339Nano))
		}
		out.Reports = append(out.Reports, TorrentReport{ID: id, User: user, Node: node, At: at.UTC()})
	}
	if len(rows) > 0 && len(out.Reports) == 0 {
		return TorrentPage{}, &APIError{Code: CodeIncompatible}
	}
	return out, nil
}

func (a *V3) HWIDDevices(ctx context.Context, start, size int) (DevicePage, error) {
	if size <= 0 || size > maxHistoryPageSize {
		size = maxHistoryPageSize
	}
	body, err := a.get(ctx, pathHWIDDevices, url.Values{"start": {strconv.Itoa(max(start, 0))}, "size": {strconv.Itoa(size)}})
	if err != nil {
		return DevicePage{}, err
	}
	rows, total, err := listOf(body, "devices", "records", "items")
	if err != nil {
		return DevicePage{}, err
	}
	out := DevicePage{Total: total, Devices: make([]Device, 0, len(rows))}
	for _, row := range rows {
		user, hw := firstScalar(row, "userId", "userUuid", "user.id", "user.uuid"), firstScalar(row, "hwid")
		if user == "" || hw == "" {
			continue
		}
		out.Devices = append(out.Devices, Device{HWID: hw, User: user})
	}
	if len(rows) > 0 && len(out.Devices) == 0 {
		return DevicePage{}, &APIError{Code: CodeIncompatible}
	}
	return out, nil
}
