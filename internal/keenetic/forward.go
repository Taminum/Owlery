package keenetic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/Taminum/Owlery/internal/netdev"
)

// The only two things Owlery ever writes to a router: one static port forward added, or one taken away, and then the
// configuration saved. Nothing else is sent to it, and the shapes are fixed here, not built from what a caller sends.

var (
	ErrForbidden   = errors.New("keenetic: this user may not change the router's settings")
	ErrRejected    = errors.New("keenetic: the router did not take the change")
	ErrUnknownHost = errors.New("keenetic: the router does not know a device with that address")
	ErrPortTaken   = errors.New("keenetic: that port is already forwarded")
	ErrMissing     = errors.New("keenetic: no such forward on the router")
)

// ForwardSpec is a forward to be added: the outside port, and the device (by its address in the home network) and port it leads to.
type ForwardSpec struct {
	Protocol string // tcp or udp
	Port     int
	ToPort   int // 0 means the same as Port
	ToIP     string
	Comment  string
}

type staticRule = map[string]any

func (c *Client) post(ctx context.Context, h *http.Client, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return ErrUnexpected
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/rci/", bytes.NewReader(raw))
	if err != nil {
		return ErrUnexpected
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ErrForbidden
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: the change answered %d", ErrUnexpected, resp.StatusCode)
	}
	var v any
	if json.Unmarshal(data, &v) == nil {
		if msg, bad := statusError(v, 0); bad {
			low := strings.ToLower(msg)
			if strings.Contains(low, "access") || strings.Contains(low, "permission") || strings.Contains(low, "denied") {
				return ErrForbidden
			}
			return fmt.Errorf("%w: %s", ErrRejected, netdev.Clean(msg, 120))
		}
	}
	return nil
}

// statusError finds an "error" status anywhere in a reply: the router answers 200 even when a command failed.
func statusError(v any, depth int) (string, bool) {
	if depth > 6 {
		return "", false
	}
	switch x := v.(type) {
	case map[string]any:
		if s, _ := x["status"].(string); s == "error" || s == "critical" {
			m, _ := x["message"].(string)
			return m, true
		}
		for _, e := range x {
			if m, bad := statusError(e, depth+1); bad {
				return m, true
			}
		}
	case []any:
		for _, e := range x {
			if m, bad := statusError(e, depth+1); bad {
				return m, true
			}
		}
	}
	return "", false
}

func (c *Client) save(ctx context.Context, h *http.Client) error {
	return c.post(ctx, h, map[string]any{"system": map[string]any{"configuration": map[string]any{"save": map[string]any{}}}})
}

func (c *Client) statics(ctx context.Context, h *http.Client) ([]staticRule, error) {
	var out []staticRule
	if err := get(ctx, h, c.base, "show/sc/ip/static", &out); err != nil {
		return nil, err
	}
	return out, nil
}

func str(m staticRule, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatInt(int64(v), 10)
	}
	return ""
}

func (c *Client) writer(ctx context.Context) (*http.Client, error) {
	h := c.session()
	if err := c.signIn(ctx, h); err != nil {
		return nil, err
	}
	return h, nil
}

// AddForward opens one port to the outside, towards a device the router knows by its address, then saves the configuration and
// reads the list back to be sure the router took it.
func (c *Client) AddForward(ctx context.Context, f ForwardSpec) error {
	to := net.ParseIP(f.ToIP)
	if (f.Protocol != "tcp" && f.Protocol != "udp") || f.Port < 1 || f.Port > 65535 || f.ToPort < 0 || f.ToPort > 65535 || to == nil {
		return ErrUnexpected
	}
	h, err := c.writer(ctx)
	if err != nil {
		return err
	}
	var hs hotspotResp
	if err := get(ctx, h, c.base, "show/ip/hotspot", &hs); err != nil {
		return err
	}
	mac := ""
	for _, x := range hs.Host {
		if ip := net.ParseIP(strings.TrimSpace(x.IP)); ip != nil && ip.Equal(to) {
			if hw, err := net.ParseMAC(strings.TrimSpace(x.MAC)); err == nil {
				mac = strings.ToLower(hw.String())
			}
		}
	}
	if mac == "" {
		return ErrUnknownHost
	}
	var routes []struct {
		Destination string `json:"destination"`
		Interface   string `json:"interface"`
	}
	if err := get(ctx, h, c.base, "show/ip/route", &routes); err != nil {
		return err
	}
	wan := ""
	for _, r := range routes {
		if r.Destination == "0.0.0.0/0" && r.Interface != "" {
			wan = r.Interface
			break
		}
	}
	if wan == "" {
		return fmt.Errorf("%w: no way out found to open the port on", ErrUnexpected)
	}
	port := strconv.Itoa(f.Port)
	cur, err := c.statics(ctx, h)
	if err != nil {
		return err
	}
	for _, r := range cur {
		if str(r, "interface") == wan && str(r, "port") == port && (str(r, "protocol") == f.Protocol || str(r, "protocol") == "tcpudp") && r["disable"] != true {
			return ErrPortTaken
		}
	}
	rule := staticRule{"interface": wan, "protocol": f.Protocol, "port": port, "to-host": mac, "disable": map[string]any{"no": true}}
	if f.ToPort != 0 && f.ToPort != f.Port {
		rule["to-port"] = strconv.Itoa(f.ToPort)
	}
	if cm := netdev.Clean(f.Comment, 80); cm != "" {
		rule["comment"] = cm
	}
	if err := c.post(ctx, h, map[string]any{"ip": map[string]any{"static": rule}}); err != nil {
		return err
	}
	if err := c.save(ctx, h); err != nil {
		return err
	}
	after, err := c.statics(ctx, h)
	if err != nil {
		return err
	}
	for _, r := range after {
		if str(r, "interface") == wan && str(r, "port") == port && str(r, "protocol") == f.Protocol && strings.EqualFold(str(r, "to-host"), mac) {
			return nil
		}
	}
	return fmt.Errorf("%w: the forward is not in the list afterwards", ErrRejected)
}

// DeleteForward takes away the static forward with this index (as listed by the router), saves, and reads the list back.
func (c *Client) DeleteForward(ctx context.Context, ref string) error {
	if ref == "" || len(ref) > 64 {
		return ErrMissing
	}
	h, err := c.writer(ctx)
	if err != nil {
		return err
	}
	cur, err := c.statics(ctx, h)
	if err != nil {
		return err
	}
	var found staticRule
	for _, r := range cur {
		if str(r, "index") == ref {
			found = r
		}
	}
	if found == nil {
		return ErrMissing
	}
	payload := staticRule{}
	for k, v := range found {
		if k != "disable" {
			payload[k] = v
		}
	}
	payload["no"] = true
	if err := c.post(ctx, h, map[string]any{"ip": map[string]any{"static": payload}}); err != nil {
		return err
	}
	if err := c.save(ctx, h); err != nil {
		return err
	}
	after, err := c.statics(ctx, h)
	if err != nil {
		return err
	}
	for _, r := range after {
		if str(r, "index") == ref {
			return fmt.Errorf("%w: the forward is still in the list", ErrRejected)
		}
	}
	return nil
}
