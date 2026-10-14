// Package gemini is a small client for the Google Gemini API, built for one job: asking a model to
// sort a short list of domain names into categories and getting back strictly structured JSON.
//
// It talks only to the Gemini host, follows no redirects, limits the size of what it reads, never
// puts the key in a URL, a log line or an error value, and reads the key from a file on every call so
// that changing or removing the key takes effect without a restart.
package gemini

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultEndpoint = "https://generativelanguage.googleapis.com"
	maxResponse     = 1 << 20 // bytes read from any response
	userAgent       = "remnascope-autoclassify/1"
)

// Errors a caller can act on. None of them carries the key or the response body.
var (
	ErrNoKey      = errors.New("gemini: no API key configured")
	ErrBadRequest = errors.New("gemini: the request was rejected") // 4xx other than 429: do not retry as is
	ErrBadReply   = errors.New("gemini: the reply was not in the expected shape")
	ErrAuth       = errors.New("gemini: the key was refused") // 401/403
)

// RateLimited is returned for HTTP 429; RetryAfter is what the server asked for (0 if it did not).
type RateLimited struct{ RetryAfter time.Duration }

func (e *RateLimited) Error() string { return "gemini: rate limited" }

// Upstream is returned for 5xx and for network errors and timeouts: worth retrying later.
type Upstream struct{ Status int }

func (e *Upstream) Error() string {
	if e.Status == 0 {
		return "gemini: the service could not be reached"
	}
	return "gemini: the service failed (" + strconv.Itoa(e.Status) + ")"
}

// Client calls the API. The zero value is not usable: set KeyFile.
type Client struct {
	Endpoint string // default DefaultEndpoint; tests point it at a local server
	KeyFile  string
	HTTP     *http.Client
}

func (c *Client) endpoint() string {
	if c.Endpoint != "" {
		return strings.TrimRight(c.Endpoint, "/")
	}
	return DefaultEndpoint
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{
		Timeout:       45 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// key reads the key file. An empty or missing file means "no key".
func (c *Client) key() (string, error) {
	if c.KeyFile == "" {
		return "", ErrNoKey
	}
	b, err := os.ReadFile(c.KeyFile)
	if err != nil {
		return "", ErrNoKey
	}
	// A file written by Notepad or PowerShell may start with a byte-order mark and end with a line break.
	k := strings.TrimSpace(string(bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})))
	if k == "" || len(k) > 512 || !keyChars(k) {
		return "", ErrNoKey // anything but the characters real keys use is not a key, and never reaches a header
	}
	return k, nil
}

func keyChars(k string) bool {
	for _, r := range k {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// HasKey reports whether a usable key is present, without using it.
func (c *Client) HasKey() bool { _, err := c.key(); return err == nil }

func (c *Client) do(ctx context.Context, method, path string, q url.Values, body []byte) ([]byte, error) {
	key, err := c.key()
	if err != nil {
		return nil, err
	}
	u := c.endpoint() + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, ErrBadRequest
	}
	req.Header.Set("x-goog-api-key", key) // in a header, never in the URL
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, &Upstream{} // the error text could echo the URL or headers: say nothing of it
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil || len(raw) > maxResponse {
		return nil, &Upstream{Status: resp.StatusCode}
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return raw, nil
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, &RateLimited{RetryAfter: retryAfter(resp.Header.Get("Retry-After"))}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, ErrAuth
	case resp.StatusCode == http.StatusBadRequest && keyRefused(raw):
		return nil, ErrAuth // Google answers an invalid key with 400, not 401
	case resp.StatusCode >= 500:
		return nil, &Upstream{Status: resp.StatusCode}
	default:
		return nil, ErrBadRequest
	}
}

// keyRefused reads Google's error body and says whether it is about the key. Only fixed codes are
// looked at; the message text is never kept or shown.
func keyRefused(body []byte) bool {
	var e struct {
		Error struct {
			Status  string `json:"status"`
			Details []struct {
				Reason string `json:"reason"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return false
	}
	if e.Error.Status == "UNAUTHENTICATED" || e.Error.Status == "PERMISSION_DENIED" {
		return true
	}
	for _, d := range e.Error.Details {
		if strings.HasPrefix(d.Reason, "API_KEY_") || d.Reason == "CREDENTIALS_MISSING" || d.Reason == "ACCESS_TOKEN_EXPIRED" {
			return true
		}
	}
	return false
}

func retryAfter(h string) time.Duration {
	h = strings.TrimSpace(h)
	if n, err := strconv.Atoi(h); err == nil && n >= 0 {
		return min(time.Duration(n)*time.Second, 15*time.Minute)
	}
	if t, err := http.ParseTime(h); err == nil {
		return max(0, min(time.Until(t), 15*time.Minute))
	}
	return 0
}

// Model is one entry of the model list that can generate text.
type Model struct {
	Name        string `json:"name"` // e.g. gemini-2.5-flash (the "models/" prefix removed)
	DisplayName string `json:"display_name"`
}

// ListModels returns the models the key can use to generate content, so the one in use is chosen
// from what is actually available instead of a name that may have been retired.
func (c *Client) ListModels(ctx context.Context) ([]Model, error) {
	var out []Model
	token := ""
	for page := 0; page < 5; page++ {
		q := url.Values{"pageSize": {"100"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		raw, err := c.do(ctx, http.MethodGet, "/v1beta/models", q, nil)
		if err != nil {
			return nil, err
		}
		var r struct {
			Models []struct {
				Name        string   `json:"name"`
				DisplayName string   `json:"displayName"`
				Methods     []string `json:"supportedGenerationMethods"`
			} `json:"models"`
			Next string `json:"nextPageToken"`
		}
		if json.Unmarshal(raw, &r) != nil {
			return nil, ErrBadReply
		}
		for _, m := range r.Models {
			gen := false
			for _, x := range m.Methods {
				gen = gen || x == "generateContent"
			}
			name := strings.TrimPrefix(m.Name, "models/")
			if gen && validModelName(name) {
				out = append(out, Model{Name: name, DisplayName: m.DisplayName})
			}
		}
		if r.Next == "" {
			break
		}
		token = r.Next
	}
	return out, nil
}

// validModelName keeps a model name to the characters real names use, since it goes into a URL path.
func validModelName(n string) bool {
	if n == "" || len(n) > 100 {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_') {
			return false
		}
	}
	return true
}

// Usage is the token accounting the API reports for one call.
type Usage struct{ In, Out int }

// GenerateJSON asks a model for a JSON answer that matches schema, and returns the JSON text the model
// produced. The text still has to be validated by the caller: this function only guarantees that it
// came from a successful call and fits the size limit.
func (c *Client) GenerateJSON(ctx context.Context, model, system, prompt string, schema any, maxOut int) (string, Usage, error) {
	if !validModelName(model) {
		return "", Usage{}, ErrBadRequest
	}
	body, err := json.Marshal(map[string]any{
		"systemInstruction": map[string]any{"parts": []map[string]string{{"text": system}}},
		"contents":          []map[string]any{{"role": "user", "parts": []map[string]string{{"text": prompt}}}},
		"generationConfig": map[string]any{
			"temperature":      0,
			"responseMimeType": "application/json",
			"responseSchema":   schema,
			"maxOutputTokens":  maxOut,
		},
	})
	if err != nil {
		return "", Usage{}, ErrBadRequest
	}
	raw, err := c.do(ctx, http.MethodPost, "/v1beta/models/"+model+":generateContent", nil, body)
	if err != nil {
		return "", Usage{}, err
	}
	var r struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
		Usage struct {
			In  int `json:"promptTokenCount"`
			Out int `json:"candidatesTokenCount"`
		} `json:"usageMetadata"`
	}
	if json.Unmarshal(raw, &r) != nil || len(r.Candidates) == 0 {
		return "", Usage{}, ErrBadReply
	}
	cand := r.Candidates[0]
	if cand.FinishReason != "" && cand.FinishReason != "STOP" {
		return "", Usage{In: r.Usage.In, Out: r.Usage.Out}, fmt.Errorf("%w (finish: %s)", ErrBadReply, safeToken(cand.FinishReason))
	}
	var sb strings.Builder
	for _, p := range cand.Content.Parts {
		sb.WriteString(p.Text)
	}
	if sb.Len() == 0 {
		return "", Usage{In: r.Usage.In, Out: r.Usage.Out}, ErrBadReply
	}
	return sb.String(), Usage{In: r.Usage.In, Out: r.Usage.Out}, nil
}

// safeToken keeps a short machine word out of a provider string, for an error that is shown to people.
func safeToken(s string) string {
	if len(s) > 32 {
		s = s[:32]
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r == '_') {
			return "?"
		}
	}
	return s
}
