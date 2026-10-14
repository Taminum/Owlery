package gemini

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testKey = "AIzaTESTKEY-0123456789-abcdef"

func keyFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &Client{Endpoint: srv.URL, KeyFile: keyFile(t, testKey+"\n")}, srv
}

func ok(w http.ResponseWriter, text string, in, out int) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"candidates":    []any{map[string]any{"content": map[string]any{"parts": []any{map[string]any{"text": text}}}, "finishReason": "STOP"}},
		"usageMetadata": map[string]any{"promptTokenCount": in, "candidatesTokenCount": out},
	})
}

func TestKeyGoesInAHeaderNeverInTheURLAndBodyIsStructured(t *testing.T) {
	var gotKey, gotPath, gotQuery string
	var body map[string]any
	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotKey, gotPath, gotQuery = r.Header.Get("x-goog-api-key"), r.URL.Path, r.URL.RawQuery
		_ = json.NewDecoder(r.Body).Decode(&body)
		ok(w, `[{"domain":"a.test"}]`, 120, 30)
	})
	text, usage, err := c.GenerateJSON(context.Background(), "gemini-x-flash", "SYS", "PROMPT", map[string]any{"type": "ARRAY"}, 777)
	if err != nil || text != `[{"domain":"a.test"}]` || usage.In != 120 || usage.Out != 30 {
		t.Fatalf("%q %+v %v", text, usage, err)
	}
	if gotKey != testKey || gotPath != "/v1beta/models/gemini-x-flash:generateContent" || strings.Contains(gotQuery, "AIza") || gotQuery != "" {
		t.Fatalf("key=%q path=%q query=%q", gotKey, gotPath, gotQuery)
	}
	gc, _ := body["generationConfig"].(map[string]any)
	if gc["responseMimeType"] != "application/json" || gc["temperature"] != float64(0) || gc["maxOutputTokens"] != float64(777) || gc["responseSchema"] == nil {
		t.Fatalf("generationConfig: %+v", gc)
	}
	if !strings.Contains(string(mustJSON(body)), "SYS") || !strings.Contains(string(mustJSON(body)), "PROMPT") {
		t.Fatal("system instruction and prompt must both be sent")
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestNoKeyMeansNoRequest(t *testing.T) {
	called := false
	c, _ := newClient(t, func(http.ResponseWriter, *http.Request) { called = true })
	for name, content := range map[string]string{"empty": "", "spaces": "   \n", "inner space": "AIza bad key", "huge": strings.Repeat("a", 600), "asterisks": "AQ.**********-jw2H0w", "unicode": "AQ.ключ", "header injection": "AQ.abc\nX-Evil: 1", "quotes": "\"AQ.abc\""} {
		c.KeyFile = keyFile(t, content)
		if c.HasKey() {
			t.Errorf("%s: counted as a key", name)
		}
		if _, _, err := c.GenerateJSON(context.Background(), "m", "s", "p", nil, 10); !errors.Is(err, ErrNoKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	c.KeyFile = filepath.Join(t.TempDir(), "missing")
	if _, err := c.ListModels(context.Background()); !errors.Is(err, ErrNoKey) || called {
		t.Fatalf("a missing file: %v (called=%v)", err, called)
	}
	if (&Client{}).HasKey() {
		t.Fatal("no key file configured")
	}
}

func TestErrorsAreClassifiedAndCarryNoSecrets(t *testing.T) {
	var status int
	var retry string
	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		if retry != "" {
			w.Header().Set("Retry-After", retry)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":{"message":"bad key ` + testKey + `"}}`)) // a hostile or careless body
	})
	call := func() error {
		_, _, err := c.GenerateJSON(context.Background(), "m-1", "s", "p", nil, 10)
		return err
	}
	status, retry = 429, "7"
	var rl *RateLimited
	if err := call(); !errors.As(err, &rl) || rl.RetryAfter != 7*time.Second {
		t.Fatalf("429: %v", err)
	}
	status, retry = 429, "999999"
	if err := call(); !errors.As(err, &rl) || rl.RetryAfter != 15*time.Minute {
		t.Fatalf("an absurd Retry-After is capped: %v", err)
	}
	status, retry = 429, ""
	if err := call(); !errors.As(err, &rl) || rl.RetryAfter != 0 {
		t.Fatalf("no Retry-After: %v", err)
	}
	var up *Upstream
	for _, s := range []int{500, 502, 503} {
		status = s
		if err := call(); !errors.As(err, &up) || up.Status != s {
			t.Fatalf("%d: %v", s, err)
		}
	}
	for _, s := range []int{401, 403} {
		status = s
		if err := call(); !errors.Is(err, ErrAuth) {
			t.Fatalf("%d: %v", s, err)
		}
	}
	status = 400
	if err := call(); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("400: %v", err)
	}
	for _, s := range []int{429, 500, 401, 400} {
		status = s
		if err := call(); err != nil && strings.Contains(err.Error(), "AIza") {
			t.Fatalf("an error text carries the key: %v", err)
		}
	}
}

func TestNetworkFailuresAreUpstreamAndDoNotEchoTheURL(t *testing.T) {
	c := &Client{Endpoint: "http://127.0.0.1:1", KeyFile: keyFile(t, testKey), HTTP: &http.Client{Timeout: 2 * time.Second}}
	_, _, err := c.GenerateJSON(context.Background(), "m", "s", "p", nil, 10)
	var up *Upstream
	if !errors.As(err, &up) || up.Status != 0 || strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), "AIza") {
		t.Fatalf("%v", err)
	}
}

func TestOddRepliesAreBadRepliesNotCrashes(t *testing.T) {
	var reply string
	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(reply)) })
	for name, r := range map[string]string{
		"not json":       "<html>",
		"no candidates":  `{"candidates":[]}`,
		"empty text":     `{"candidates":[{"content":{"parts":[{"text":""}]},"finishReason":"STOP"}]}`,
		"cut by length":  `{"candidates":[{"content":{"parts":[{"text":"[{"}]},"finishReason":"MAX_TOKENS"}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":9}}`,
		"blocked":        `{"candidates":[{"finishReason":"SAFETY"}]}`,
		"weird finish":   `{"candidates":[{"content":{"parts":[{"text":"x"}]},"finishReason":"drop table; --"}]}`,
		"too large body": `{"candidates":[{"content":{"parts":[{"text":"` + strings.Repeat("x", maxResponse) + `"}]}}]}`,
	} {
		reply = r
		_, _, err := c.GenerateJSON(context.Background(), "m", "s", "p", nil, 10)
		var up *Upstream
		if !errors.Is(err, ErrBadReply) && !errors.As(err, &up) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A reply cut by the token limit still reports what it used.
	reply = `{"candidates":[{"content":{"parts":[{"text":"[{"}]},"finishReason":"MAX_TOKENS"}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":9}}`
	if _, u, err := c.GenerateJSON(context.Background(), "m", "s", "p", nil, 10); !errors.Is(err, ErrBadReply) || u.In != 5 || u.Out != 9 {
		t.Fatalf("%+v %v", u, err)
	}
}

func TestListModelsKeepsOnlyGeneratorsWithSafeNamesAndFollowsPages(t *testing.T) {
	calls := 0
	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("pageToken") == "" {
			_, _ = w.Write([]byte(`{"models":[{"name":"models/gemini-a-flash","displayName":"A Flash","supportedGenerationMethods":["generateContent","countTokens"]},
				{"name":"models/embedding-1","displayName":"Embed","supportedGenerationMethods":["embedContent"]}],"nextPageToken":"p2"}`))
			return
		}
		_, _ = w.Write([]byte(`{"models":[{"name":"models/gemini-b-pro","displayName":"B Pro","supportedGenerationMethods":["generateContent"]},
			{"name":"models/bad name/../x","displayName":"Evil","supportedGenerationMethods":["generateContent"]}]}`))
	})
	ms, err := c.ListModels(context.Background())
	if err != nil || calls != 2 {
		t.Fatalf("%v calls=%d", err, calls)
	}
	if len(ms) != 2 || ms[0].Name != "gemini-a-flash" || ms[1].Name != "gemini-b-pro" {
		t.Fatalf("%+v", ms)
	}
}

func TestModelNamesAreValidatedBeforeTheyReachAURL(t *testing.T) {
	called := false
	c, _ := newClient(t, func(http.ResponseWriter, *http.Request) { called = true })
	for _, m := range []string{"", "a/b", "m?x=1", "m:generateContent", "../x", "m m", strings.Repeat("a", 101)} {
		if _, _, err := c.GenerateJSON(context.Background(), m, "s", "p", nil, 10); !errors.Is(err, ErrBadRequest) {
			t.Errorf("%q: %v", m, err)
		}
	}
	if called {
		t.Fatal("a request was sent for an invalid model name")
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	hit := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer other.Close()
	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, http.StatusFound) })
	_, _, err := c.GenerateJSON(context.Background(), "m", "s", "p", nil, 10)
	if err == nil || hit {
		t.Fatalf("a redirect must not be followed (err=%v hit=%v)", err, hit)
	}
}

func TestKeyChangesTakeEffectWithoutARestart(t *testing.T) {
	seen := ""
	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) { seen = r.Header.Get("x-goog-api-key"); ok(w, "[]", 1, 1) })
	if _, _, err := c.GenerateJSON(context.Background(), "m", "s", "p", nil, 10); err != nil || seen != testKey {
		t.Fatalf("%v %q", err, seen)
	}
	if err := os.WriteFile(c.KeyFile, []byte("NEWKEY-abcdefghijklmnop"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.GenerateJSON(context.Background(), "m", "s", "p", nil, 10); err != nil || seen != "NEWKEY-abcdefghijklmnop" {
		t.Fatalf("%v %q", err, seen)
	}
	if err := os.WriteFile(c.KeyFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.GenerateJSON(context.Background(), "m", "s", "p", nil, 10); !errors.Is(err, ErrNoKey) {
		t.Fatalf("removing the key must stop calls: %v", err)
	}
}

// Google answers an invalid API key with HTTP 400 and a coded body, not with 401.
func TestAnInvalidKeyAnsweredWith400IsAnAuthErrorButOther400sAreNot(t *testing.T) {
	var body string
	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(400); _, _ = w.Write([]byte(body)) })
	call := func() error { _, _, err := c.GenerateJSON(context.Background(), "m", "s", "p", nil, 10); return err }
	for name, b := range map[string]string{
		"api key invalid":   `{"error":{"code":400,"status":"INVALID_ARGUMENT","details":[{"reason":"API_KEY_INVALID"}]}}`,
		"api key expired":   `{"error":{"code":400,"status":"INVALID_ARGUMENT","details":[{"reason":"API_KEY_EXPIRED"}]}}`,
		"unauthenticated":   `{"error":{"code":400,"status":"UNAUTHENTICATED"}}`,
		"permission denied": `{"error":{"code":400,"status":"PERMISSION_DENIED"}}`,
	} {
		body = b
		if err := call(); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, b := range map[string]string{
		"bad argument": `{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"Invalid JSON payload","details":[{"reason":"SOMETHING_ELSE"}]}}`,
		"html":         "<html>Error 400</html>",
		"empty":        "",
	} {
		body = b
		if err := call(); !errors.Is(err, ErrBadRequest) || errors.Is(err, ErrAuth) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// ListModels reports the same way, so the settings page can say "key not accepted".
	body = `{"error":{"code":400,"status":"INVALID_ARGUMENT","details":[{"reason":"API_KEY_INVALID"}]}}`
	if _, err := c.ListModels(context.Background()); !errors.Is(err, ErrAuth) {
		t.Fatalf("%v", err)
	}
}

// Files written by Notepad or PowerShell carry a byte-order mark and a CR LF: both are tolerated.
func TestAKeyFileWithABOMAndLineEndingStillWorks(t *testing.T) {
	seen := ""
	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) { seen = r.Header.Get("x-goog-api-key"); ok(w, "[]", 1, 1) })
	c.KeyFile = keyFile(t, "\xEF\xBB\xBFAQ.Ab8RN6-realistic_key.0123456789\r\n")
	if !c.HasKey() {
		t.Fatal("a key behind a BOM must count as a key")
	}
	if _, _, err := c.GenerateJSON(context.Background(), "m", "s", "p", nil, 10); err != nil || seen != "AQ.Ab8RN6-realistic_key.0123456789" {
		t.Fatalf("%v %q", err, seen)
	}
}
