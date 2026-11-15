package keenetic

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// More things Owlery may write to a router, each in a fixed shape and each checked by reading the router again: block or allow a
// device by its MAC, switch a port forward off or on, keep a device's address for it (a DHCP reservation), and restart the router.

func cleanMAC(s string) (string, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 {
		return "", ErrUnexpected
	}
	return strings.ToLower(hw.String()), nil
}

type hostRow struct {
	MAC    string `json:"mac"`
	IP     string `json:"ip"`
	Access string `json:"access"`
}

// SetBlocked blocks a device (deny) or lets it back (permit), then reads the router's list to be sure.
func (c *Client) SetBlocked(ctx context.Context, rawMAC string, blocked bool) error {
	mac, err := cleanMAC(rawMAC)
	if err != nil {
		return err
	}
	h, err := c.writer(ctx)
	if err != nil {
		return err
	}
	var hs hotspotResp
	if err := get(ctx, h, c.base, "show/ip/hotspot", &hs); err != nil {
		return err
	}
	known := false
	for _, x := range hs.Host {
		if m, err := cleanMAC(x.MAC); err == nil && m == mac {
			known = true
		}
	}
	if !known {
		return ErrUnknownHost
	}
	flag := "permit"
	if blocked {
		flag = "deny"
	}
	if err := c.post(ctx, h, map[string]any{"ip": map[string]any{"hotspot": map[string]any{"host": map[string]any{"mac": mac, flag: true}}}}); err != nil {
		return err
	}
	if err := c.save(ctx, h); err != nil {
		return err
	}
	var rows []hostRow
	if err := get(ctx, h, c.base, "show/sc/ip/hotspot/host", &rows); err != nil {
		return err
	}
	for _, r := range rows {
		if m, err := cleanMAC(r.MAC); err == nil && m == mac && r.Access == flag {
			return nil
		}
	}
	return fmt.Errorf("%w: the device is not %s afterwards", ErrRejected, flag)
}

// SetForwardOff switches the static forward with this index off (or on again) without taking it away.
func (c *Client) SetForwardOff(ctx context.Context, ref string, off bool) error {
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
	if off {
		payload["disable"] = true
	} else {
		payload["disable"] = map[string]any{"no": true}
	}
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
			if (r["disable"] == true) == off {
				return nil
			}
			break
		}
	}
	return fmt.Errorf("%w: the forward did not change", ErrRejected)
}

// SetReserved makes the router keep the address a device has now for it (reserve), or lets it go (not reserve).
func (c *Client) SetReserved(ctx context.Context, rawMAC string, reserve bool) error {
	mac, err := cleanMAC(rawMAC)
	if err != nil {
		return err
	}
	h, err := c.writer(ctx)
	if err != nil {
		return err
	}
	var hs hotspotResp
	if err := get(ctx, h, c.base, "show/ip/hotspot", &hs); err != nil {
		return err
	}
	var ip string
	for _, x := range hs.Host {
		if m, err := cleanMAC(x.MAC); err == nil && m == mac {
			if p := net.ParseIP(strings.TrimSpace(x.IP)); p != nil {
				ip = p.String()
			}
		}
	}
	var cur []hostRow
	if err := get(ctx, h, c.base, "show/sc/ip/dhcp/host", &cur); err != nil {
		return err
	}
	if reserve {
		if ip == "" {
			return ErrUnknownHost
		}
		for _, r := range cur {
			if r.IP == ip {
				if m, err := cleanMAC(r.MAC); err == nil && m != mac {
					return ErrPortTaken // the address is already kept for another device
				}
			}
		}
		if err := c.post(ctx, h, map[string]any{"ip": map[string]any{"dhcp": map[string]any{"host": map[string]any{"mac": mac, "ip": ip}}}}); err != nil {
			return err
		}
	} else if err := c.post(ctx, h, map[string]any{"ip": map[string]any{"dhcp": map[string]any{"host": map[string]any{"mac": mac, "no": true}}}}); err != nil {
		return err
	}
	if err := c.save(ctx, h); err != nil {
		return err
	}
	var after []hostRow
	if err := get(ctx, h, c.base, "show/sc/ip/dhcp/host", &after); err != nil {
		return err
	}
	has := false
	for _, r := range after {
		if m, err := cleanMAC(r.MAC); err == nil && m == mac && (!reserve || r.IP == ip) {
			has = true
		}
	}
	if has != reserve {
		return fmt.Errorf("%w: the reservation did not change", ErrRejected)
	}
	return nil
}

// Reboot restarts the router. There is nothing to read back: the router stops answering for a minute or two.
func (c *Client) Reboot(ctx context.Context) error {
	h, err := c.writer(ctx)
	if err != nil {
		return err
	}
	return c.post(ctx, h, map[string]any{"system": map[string]any{"reboot": map[string]any{}}})
}
