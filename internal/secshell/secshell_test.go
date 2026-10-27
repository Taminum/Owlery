package secshell

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Taminum/Owlery/internal/secproto"
)

// A real shell in a real pseudo-terminal answers a command typed into the connection.
func TestServeRunsAShell(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		_ = Serve(r.Context(), c, 100, 30)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	rs, _ := json.Marshal(secproto.ShellResize{Type: "resize", Cols: 90, Rows: 20})
	if err := c.Write(ctx, websocket.MessageText, rs); err != nil {
		t.Fatal(err)
	}
	if err := c.Write(ctx, websocket.MessageBinary, []byte("echo owl$((40+2))\r")); err != nil {
		t.Fatal(err)
	}
	var seen strings.Builder
	for !strings.Contains(seen.String(), "owl42") {
		_, b, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("no answer; got %q: %v", seen.String(), err)
		}
		seen.Write(b)
		// PowerShell does not expand $((...)): it prints the text as typed, which still has no "owl42" in it.
		if strings.Contains(seen.String(), "owl$((40+2))") && strings.Contains(seen.String(), "PS ") {
			_ = c.Write(ctx, websocket.MessageBinary, []byte("echo ('owl' + (40+2))\r"))
		}
	}
}
