package remnawave

import (
	"context"
	"encoding/json"
	"sort"
)

const pathBandwidthRealtime = "/api/bandwidth-stats/nodes/realtime"

// NodeRate is what a node is carrying right now, as the panel reports it.
type NodeRate struct {
	NodeUUID string
	Name     string
	// DownBps and UpBps are the panel's "downloadSpeedBps" and "uploadSpeedBps", taken as bytes per second.
	DownBps int64
	UpBps   int64
}

// RealtimeReader is implemented by adapters whose panel can say what its nodes carry right now. It is a
// separate interface because older panels lack the endpoint.
type RealtimeReader interface {
	NodesRealtime(ctx context.Context) ([]NodeRate, error)
}

func (a *V3) NodesRealtime(ctx context.Context) ([]NodeRate, error) {
	body, err := a.get(ctx, pathBandwidthRealtime, nil)
	if err != nil {
		return nil, err
	}
	var env struct {
		Response []map[string]json.RawMessage `json:"response"`
	}
	if err := decode(body, &env); err != nil {
		return nil, err
	}
	out := make([]NodeRate, 0, len(env.Response))
	for _, row := range env.Response {
		id := rawString(row, "nodeUuid")
		if id == "" {
			continue // an identity we cannot trust is not shown
		}
		r := NodeRate{NodeUUID: id, Name: rawString(row, "nodeName")}
		if v := byteCount(row["downloadSpeedBps"]); v != nil {
			r.DownBps = *v
		}
		if v := byteCount(row["uploadSpeedBps"]); v != nil {
			r.UpBps = *v
		}
		out = append(out, r)
	}
	if len(env.Response) > 0 && len(out) == 0 {
		return nil, &APIError{Code: CodeIncompatible}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
