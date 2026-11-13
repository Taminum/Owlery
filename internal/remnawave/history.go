package remnawave

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"time"
)

const pathSubscriptionHistory = "/api/subscription-request-history"

// SubscriptionRequest is one time somebody asked the panel for a subscription.
type SubscriptionRequest struct {
	ID     int64
	UserID string // the panel's numeric user id, as the users listing identifies users
	At     time.Time
	IP     string
	Agent  string
}

// SubscriptionHistory is one page of the history. Total is how many records the panel holds.
type SubscriptionHistory struct {
	Records []SubscriptionRequest
	Total   int
	Skipped int // rows without a usable id, user or time; never given an invented identity
}

// SubscriptionHistoryReader is implemented by adapters whose panel keeps a subscription request history. It is a separate
// interface because older panels lack the endpoint.
type SubscriptionHistoryReader interface {
	SubscriptionHistory(ctx context.Context, start, size int) (SubscriptionHistory, error)
}

const maxHistoryPageSize = 1000

func (a *V3) SubscriptionHistory(ctx context.Context, start, size int) (SubscriptionHistory, error) {
	if size <= 0 || size > maxHistoryPageSize {
		size = maxHistoryPageSize
	}
	if start < 0 {
		start = 0
	}
	body, err := a.get(ctx, pathSubscriptionHistory, url.Values{"start": {strconv.Itoa(start)}, "size": {strconv.Itoa(size)}})
	if err != nil {
		return SubscriptionHistory{}, err
	}
	var env struct {
		Response struct {
			Records []map[string]json.RawMessage `json:"records"`
			Total   int                          `json:"total"`
		} `json:"response"`
	}
	if err := decode(body, &env); err != nil {
		return SubscriptionHistory{}, err
	}
	out := SubscriptionHistory{Total: env.Response.Total, Records: make([]SubscriptionRequest, 0, len(env.Response.Records))}
	for _, row := range env.Response.Records {
		id, user := byteCount(row["id"]), byteCount(row["userId"])
		at, err := time.Parse(time.RFC3339, rawString(row, "requestAt"))
		if id == nil || *id <= 0 || user == nil || *user <= 0 || err != nil {
			out.Skipped++
			continue
		}
		out.Records = append(out.Records, SubscriptionRequest{ID: *id, UserID: strconv.FormatInt(*user, 10), At: at.UTC(),
			IP: rawString(row, "requestIp"), Agent: rawString(row, "userAgent")})
	}
	if len(env.Response.Records) > 0 && len(out.Records) == 0 {
		return SubscriptionHistory{}, &APIError{Code: CodeIncompatible}
	}
	return out, nil
}
