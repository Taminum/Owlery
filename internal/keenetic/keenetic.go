// Package keenetic asks a Keenetic router how it is doing, through its web interface (RCI), which is the same address the
// router has under its KeenDNS name. Reading uses only a fixed few read-only "show" commands: the router also has commands
// that would hand out the password hashes of its users, and those are never asked for. The only writes are in forward.go:
// one port forward added or removed, in a fixed shape, at the owner's request.
package keenetic

import (
	"context"
	"crypto/md5" //nolint:gosec // Keenetic's own login scheme: md5(login:realm:password), then sha256 with the challenge
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Taminum/Owlery/internal/netdev"
)

// AllowLocal lets the client talk to loopback and link-local addresses. It is for tests only: a router that the owner names
// must not be a way to reach services on the server itself.
var AllowLocal = false

const (
	maxBody    = 4 << 20
	maxIfaces  = 24
	reqTimeout = 25 * time.Second
)

// What went wrong, in terms the page can say.
var (
	ErrUnreachable = errors.New("keenetic: the router does not answer")
	ErrAuth        = errors.New("keenetic: the router does not accept the login")
	ErrUnexpected  = errors.New("keenetic: the router answered with something unexpected")
)

// Code names an error for storing and showing: unreachable, auth or unexpected.
func Code(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrAuth):
		return "auth"
	case errors.Is(err, ErrForbidden):
		return "forbidden"
	case errors.Is(err, ErrRejected):
		return "rejected"
	case errors.Is(err, ErrUnknownHost):
		return "unknown_host"
	case errors.Is(err, ErrPortTaken):
		return "port_taken"
	case errors.Is(err, ErrMissing):
		return "missing"
	case errors.Is(err, ErrUnreachable):
		return "unreachable"
	default:
		return "unexpected"
	}
}

// ParseBase checks the address the owner typed and reduces it to scheme://host[:port]. Only https is taken, with no login in it.
func ParseBase(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw != "" && !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("keenetic: the address must be https://name or https://name:port")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", errors.New("keenetic: bad port")
		}
	}
	if len(u.Host) > 255 {
		return "", errors.New("keenetic: the address is too long")
	}
	return "https://" + strings.ToLower(u.Host), nil
}

// Client asks one router. It signs in afresh on every Poll, so it holds no session between asks.
type Client struct {
	base, login, password string
	// HTTP, when set, is used instead of the default client (tests).
	HTTP *http.Client
}

// New makes a client for the router at base (as ParseBase gave it).
func New(base, login, password string) (*Client, error) {
	b, err := ParseBase(base)
	if err != nil {
		return nil, err
	}
	if login == "" || password == "" {
		return nil, errors.New("keenetic: a login and a password are needed")
	}
	return &Client{base: b, login: login, password: password}, nil
}

func guard(network, address string, _ syscall.RawConn) error {
	if AllowLocal {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ErrUnreachable
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("%w: address not allowed", ErrUnreachable)
	}
	return nil
}

func (c *Client) session() *http.Client {
	jar, _ := cookiejar.New(nil)
	if c.HTTP != nil {
		h := *c.HTTP
		h.Jar = jar
		if h.Timeout == 0 {
			h.Timeout = reqTimeout
		}
		return &h
	}
	d := &net.Dialer{Timeout: 10 * time.Second, Control: guard}
	return &http.Client{
		Jar:       jar,
		Timeout:   reqTimeout,
		Transport: &http.Transport{DialContext: d.DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (c *Client) signIn(ctx context.Context, h *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/auth", nil)
	if err != nil {
		return ErrUnexpected
	}
	resp, err := h.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil // already allowed in
	}
	challenge, realm := resp.Header.Get("X-NDM-Challenge"), resp.Header.Get("X-NDM-Realm")
	if resp.StatusCode != http.StatusUnauthorized || challenge == "" || realm == "" {
		return fmt.Errorf("%w: this does not look like a Keenetic", ErrUnexpected)
	}
	m := md5.Sum([]byte(c.login + ":" + realm + ":" + c.password)) //nolint:gosec
	s := sha256.Sum256([]byte(challenge + hex.EncodeToString(m[:])))
	body, _ := json.Marshal(map[string]string{"login": c.login, "password": hex.EncodeToString(s[:])})
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/auth", strings.NewReader(string(body)))
	if err != nil {
		return ErrUnexpected
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err = h.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrAuth
	}
	return fmt.Errorf("%w: sign-in answered %d", ErrUnexpected, resp.StatusCode)
}

// get reads one RCI path (always one of the fixed read-only ones) into out.
func get(ctx context.Context, h *http.Client, base, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/rci/"+path, nil)
	if err != nil {
		return ErrUnexpected
	}
	resp, err := h.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ErrAuth
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s answered %d", ErrUnexpected, path, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUnexpected, path, err)
	}
	return nil
}

// flex reads a number that the router writes sometimes as a number and sometimes as a string.
type flex int64

func (f *flex) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return err
	}
	*f = flex(n)
	return nil
}

type versionResp struct {
	Title string `json:"title"`
	Model string `json:"model"`
}

type systemResp struct {
	CPULoad    float64 `json:"cpuload"`
	MemTotal   flex    `json:"memtotal"`
	MemFree    flex    `json:"memfree"`
	MemBuffers flex    `json:"membuffers"`
	MemCache   flex    `json:"memcache"`
	Uptime     flex    `json:"uptime"`
	ConnTotal  flex    `json:"conntotal"`
	ConnFree   flex    `json:"connfree"`
}

type hotspotResp struct {
	Host []struct {
		MAC      string `json:"mac"`
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
		Name     string `json:"name"`
		Active   bool   `json:"active"`
		Access   string `json:"access"`
	} `json:"host"`
}

// text reads a value the router writes sometimes as a number and sometimes as a string.
type text string

func (t *text) UnmarshalJSON(b []byte) error {
	v := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if v == "null" {
		v = ""
	}
	*t = text(v)
	return nil
}

type forwardResp struct {
	Protocol  string `json:"protocol"`
	Port      text   `json:"port"`
	ToPort    text   `json:"to-port"`
	Index     string `json:"index"`
	ToHost    string `json:"to-host"`
	ToAddress string `json:"to-address"`
	Comment   string `json:"comment"`
	Disable   bool   `json:"disable"`
}

type upnpResp struct {
	Entry []struct {
		Protocol    string `json:"protocol"`
		Port        text   `json:"port"`
		ToPort      text   `json:"to-port"`
		ToAddress   string `json:"to-address"`
		Description string `json:"description"`
		Packets     flex   `json:"packets"`
		Bytes       flex   `json:"bytes"`
	} `json:"entry"`
}

type internetResp struct {
	Internet bool `json:"internet"`
}

type ifaceInfo struct {
	Type    string `json:"type"`
	State   string `json:"state"`
	Link    string `json:"link"`
	Address string `json:"address"`
}

type statResp struct {
	RX flex `json:"rxbytes"`
	TX flex `json:"txbytes"`
}

// wanKinds are the kinds of interface that carry the way out: they are listed even when they are down, because that is
// the news.
var wanKinds = map[string]bool{"PPPoE": true, "PPTP": true, "L2TP": true, "SSTP": true, "Wireguard": true, "OpenVPN": true, "UsbModem": true, "UsbLte": true, "UsbQmi": true, "Wwan": true}

func wantIface(i ifaceInfo) bool {
	switch i.Type {
	case "", "Port", "AccessPoint", "WifiStation", "WifiMaster", "GigabitEthernet":
		return false
	}
	if wanKinds[i.Type] {
		return true
	}
	return i.State == "up" && (i.Address != "" || i.Type == "Bridge")
}

// Poll signs in and reads the router: what it is, how loaded, the interfaces with their counters, and who is connected.
func (c *Client) Poll(ctx context.Context) (netdev.Report, error) {
	h := c.session()
	if err := c.signIn(ctx, h); err != nil {
		return netdev.Report{}, err
	}
	var ver versionResp
	if err := get(ctx, h, c.base, "show/version", &ver); err != nil {
		return netdev.Report{}, err
	}
	var sys systemResp
	if err := get(ctx, h, c.base, "show/system", &sys); err != nil {
		return netdev.Report{}, err
	}
	var hs hotspotResp
	if err := get(ctx, h, c.base, "show/ip/hotspot", &hs); err != nil {
		return netdev.Report{}, err
	}
	r := netdev.Report{HasStats: true, ResetClients: true, ResetNat: true, Board: netdev.Clean(ver.Model, 60), Version: netdev.Clean(ver.Title, 40)}
	r.UptimeSec = int64(sys.Uptime)
	r.CPU = sys.CPULoad
	if r.CPU < 0 {
		r.CPU = 0
	}
	if r.CPU > 100 {
		r.CPU = 100
	}
	if sys.MemTotal > 0 {
		r.MemTotal = int64(sys.MemTotal) * 1024
		free := (int64(sys.MemFree) + int64(sys.MemBuffers) + int64(sys.MemCache)) * 1024
		if free > r.MemTotal {
			free = r.MemTotal
		}
		if free < 0 {
			free = 0
		}
		r.MemFree = free
	}
	if sys.ConnTotal > 0 {
		used := int64(sys.ConnTotal - sys.ConnFree)
		if used < 0 {
			used = 0
		}
		r.HasConn, r.Conn, r.ConnMax = true, used, int64(sys.ConnTotal)
	}
	ipOf := map[string]string{} // the address behind each known MAC, for a forward that names only the machine
	for _, x := range hs.Host {
		if ip, hw := net.ParseIP(strings.TrimSpace(x.IP)), strings.TrimSpace(x.MAC); ip != nil {
			if m, err := net.ParseMAC(hw); err == nil {
				ipOf[strings.ToUpper(m.String())] = ip.String()
			}
		}
	}
	for _, x := range hs.Host {
		if !x.Active || x.Access == "deny" || len(r.Clients) >= netdev.MaxClients { // a device the router refuses is not a client
			continue
		}
		ip, mac := net.ParseIP(strings.TrimSpace(x.IP)), strings.TrimSpace(x.MAC)
		hw, err := net.ParseMAC(mac)
		if ip == nil || err != nil || len(hw) != 6 {
			continue
		}
		name := x.Hostname
		if name == "" {
			name = x.Name
		}
		r.Clients = append(r.Clients, netdev.Client{IP: ip.String(), MAC: strings.ToUpper(hw.String()), Host: netdev.Clean(name, 60)})
	}
	// What is open to the outside and whether the way out works are bonuses too: an older firmware may not know them.
	var fw []forwardResp
	if err := get(ctx, h, c.base, "show/sc/ip/static", &fw); err == nil {
		for _, f := range fw {
			if len(r.Nat) >= netdev.MaxNat {
				continue
			}
			to := strings.TrimSpace(f.ToAddress)
			if to == "" {
				if m, err := net.ParseMAC(strings.TrimSpace(f.ToHost)); err == nil {
					to = ipOf[strings.ToUpper(m.String())]
					if to == "" {
						to = strings.ToUpper(m.String())
					}
				}
			}
			tp := string(f.ToPort)
			if tp == "" {
				tp = string(f.Port)
			}
			r.Nat = append(r.Nat, netdev.NatRule{Chain: "dstnat", Action: "forward " + netdev.Clean(f.Protocol, 8), Packets: -1, Bytes: -1,
				DstPort: netdev.Clean(string(f.Port), 40), ToAddr: netdev.Clean(to, 60), ToPorts: netdev.Clean(tp, 40), Comment: netdev.Clean(f.Comment, 80), Ref: netdev.Clean(f.Index, 64), Off: f.Disable})
		}
	} else if errors.Is(err, ErrAuth) {
		return netdev.Report{}, err
	}
	// Who the router refuses and which addresses it keeps: both are lists in its settings, read like the rest.
	type who struct {
		ip, name string
	}
	byMAC := map[string]who{}
	for _, x := range hs.Host {
		if m, err := cleanMAC(x.MAC); err == nil {
			name := x.Hostname
			if name == "" {
				name = x.Name
			}
			byMAC[m] = who{ip: strings.TrimSpace(x.IP), name: name}
		}
	}
	var access, keep []hostRow
	if e1, e2 := get(ctx, h, c.base, "show/sc/ip/hotspot/host", &access), get(ctx, h, c.base, "show/sc/ip/dhcp/host", &keep); e1 == nil && e2 == nil {
		r.HasAccess = true
		for _, a := range access {
			m, err := cleanMAC(a.MAC)
			if err != nil || a.Access != "deny" || len(r.Blocked) >= netdev.MaxClients {
				continue
			}
			b := netdev.Blocked{MAC: strings.ToUpper(m), Host: netdev.Clean(byMAC[m].name, 60)}
			if ip := net.ParseIP(byMAC[m].ip); ip != nil {
				b.IP = ip.String()
			}
			r.Blocked = append(r.Blocked, b)
		}
		for _, d := range keep {
			m, err := cleanMAC(d.MAC)
			if ip := net.ParseIP(strings.TrimSpace(d.IP)); err == nil && ip != nil && len(r.Reserved) < netdev.MaxClients {
				r.Reserved = append(r.Reserved, netdev.Reserve{MAC: strings.ToUpper(m), IP: ip.String()})
			}
		}
	} else if errors.Is(e1, ErrAuth) || errors.Is(e2, ErrAuth) {
		return netdev.Report{}, ErrAuth
	}
	var up upnpResp
	if err := get(ctx, h, c.base, "show/upnp/redirect", &up); err == nil {
		for _, u := range up.Entry {
			if len(r.Nat) >= netdev.MaxNat {
				break
			}
			tp := string(u.ToPort)
			if tp == "" {
				tp = string(u.Port)
			}
			r.Nat = append(r.Nat, netdev.NatRule{Chain: "dstnat", Action: "upnp " + netdev.Clean(u.Protocol, 8), Packets: int64(u.Packets), Bytes: int64(u.Bytes),
				DstPort: netdev.Clean(string(u.Port), 40), ToAddr: netdev.Clean(u.ToAddress, 60), ToPorts: netdev.Clean(tp, 40), Comment: netdev.Clean(u.Description, 80)})
		}
	} else if errors.Is(err, ErrAuth) {
		return netdev.Report{}, err
	}
	var in internetResp
	if err := get(ctx, h, c.base, "show/internet/status", &in); err == nil {
		r.Internet = &in.Internet
	} else if errors.Is(err, ErrAuth) {
		return netdev.Report{}, err
	}
	// The interfaces are a bonus: when the list or a counter cannot be had, the rest is still worth keeping.
	var all map[string]ifaceInfo
	if err := get(ctx, h, c.base, "show/interface", &all); err == nil {
		ids := make([]string, 0, len(all))
		for id, info := range all {
			if wantIface(info) {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		if len(ids) > maxIfaces {
			ids = ids[:maxIfaces]
		}
		for _, id := range ids {
			info := all[id]
			f := netdev.Iface{Name: netdev.Clean(id, 40), Up: info.State == "up" && info.Link == "up"}
			var st statResp
			if get(ctx, h, c.base, "show/interface/stat?name="+url.QueryEscape(id), &st) == nil && st.RX >= 0 && st.TX >= 0 {
				f.RX, f.TX = int64(st.RX), int64(st.TX)
			}
			r.Ifaces = append(r.Ifaces, f)
		}
	} else if errors.Is(err, ErrAuth) {
		return netdev.Report{}, err
	}
	return r, nil
}
