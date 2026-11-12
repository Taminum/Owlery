// Package linuxhelper is the one place that looks at systemd services and files on behalf of the security agent. The agent has
// no rights of its own for this; it can only ask this helper, over a Unix socket, for a short list of things:
//
//   - the list of services and how each is doing (everyone may see it);
//   - the end of one service's journal;
//   - start, stop or restart of one service, only if the owner named it when installing the helper (-units);
//   - the entries of a folder and the end of a text file, only under the folders named there (-dirs), read only.
//
// The helper checks every unit name against a fixed pattern and against the units that exist, never builds a shell command,
// and passes nothing to systemctl or journalctl but the name. A path is cleaned and resolved through symbolic links before it
// is compared with the allowed folders, so a link cannot lead out of them, and names that usually hold secrets (private keys,
// tokens, shadow files, certificates) are neither listed nor read, whatever folder they are in.
//
// It runs as root, because starting a service takes that; its unit file takes away everything else.
package linuxhelper

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Taminum/Owlery/internal/seccollect"
	"github.com/Taminum/Owlery/internal/secproto"
)

const (
	CodeOK          = "ok"
	CodeBadRequest  = "bad_request"
	CodeNoSuch      = "no_such"
	CodeNotAllowed  = "not_allowed"
	CodeCommand     = "command_error"
	CodeUnavailable = "helper_unavailable"
	CodeBinary      = "binary"
	CodeNotFile     = "not_a_file"
)

const (
	maxRequestBytes = 4 << 10
	DefaultTail     = 200
	maxPath         = 1024
)

type Request struct {
	Op   string `json:"op"`
	Name string `json:"name,omitempty"`
	Path string `json:"path,omitempty"`
	Tail int    `json:"tail,omitempty"`
}

type Response struct {
	OK        bool                  `json:"ok"`
	Code      string                `json:"code,omitempty"`
	Units     []secproto.LinuxUnit  `json:"units,omitempty"`
	Dir       string                `json:"dir,omitempty"`
	Dirs      []string              `json:"dirs,omitempty"`
	Entries   []secproto.LinuxEntry `json:"entries,omitempty"`
	Text      string                `json:"text,omitempty"`
	Truncated bool                  `json:"truncated,omitempty"`
	Active    string                `json:"active,omitempty"`
}

var unitRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@\\-]{0,190}\.service$`)

// ValidUnit reports whether s may name a service at all. Whether it exists is checked against systemd.
func ValidUnit(s string) bool { return unitRe.MatchString(s) }

// neverControlled are units the panel may not stop or restart even when the owner listed them: the agent's own, which would cut
// the connection the request came on.
var neverControlled = []string{"remnascope-secagent"}

// Server answers requests on a Unix socket.
type Server struct {
	Runner     seccollect.Runner
	Systemctl  string   // the systemctl path or name
	Journalctl string   // the journalctl path or name
	Units      []string // services that may be started, stopped and restarted
	Dirs       []string // folders that may be looked at
	mu         sync.Mutex
}

func normUnit(u string) string {
	u = strings.TrimSpace(u)
	if u != "" && !strings.HasSuffix(u, ".service") {
		u += ".service"
	}
	return u
}

func (s *Server) manageable(name string) bool {
	for _, n := range neverControlled {
		if strings.HasPrefix(name, n) {
			return false
		}
	}
	for _, u := range s.Units {
		if normUnit(u) == name {
			return true
		}
	}
	return false
}

// Handle answers one request.
func (s *Server) Handle(ctx context.Context, rq Request) Response {
	switch rq.Op {
	case secproto.LinuxList:
		units, ok := s.list(ctx)
		if !ok {
			return Response{Code: CodeCommand}
		}
		return Response{OK: true, Code: CodeOK, Units: units}
	case secproto.LinuxJournal, secproto.LinuxStart, secproto.LinuxStop, secproto.LinuxRestart:
		if !ValidUnit(rq.Name) {
			return Response{Code: CodeBadRequest}
		}
		units, ok := s.list(ctx)
		if !ok {
			return Response{Code: CodeCommand}
		}
		var found *secproto.LinuxUnit
		for i := range units {
			if units[i].Name == rq.Name && units[i].Load != "not-found" {
				found = &units[i]
			}
		}
		if found == nil {
			return Response{Code: CodeNoSuch}
		}
		if rq.Op == secproto.LinuxJournal {
			return s.journal(ctx, rq)
		}
		if !found.Manage {
			return Response{Code: CodeNotAllowed}
		}
		return s.control(ctx, rq.Op, rq.Name)
	case secproto.LinuxLs:
		return s.ls(rq.Path)
	case secproto.LinuxCat:
		return s.cat(rq)
	}
	return Response{Code: CodeBadRequest}
}

// list reads every service: what is loaded, and which of the others are installed but not running.
func (s *Server) list(ctx context.Context) ([]secproto.LinuxUnit, bool) {
	r := s.Runner.Run(ctx, s.Systemctl, "list-units", "--type=service", "--all", "--plain", "--no-legend", "--no-pager", "--full")
	if r.Err != nil || r.ExitCode != 0 {
		return nil, false
	}
	byName := map[string]*secproto.LinuxUnit{}
	var out []secproto.LinuxUnit
	for _, line := range strings.Split(r.Stdout, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && !unitStart(f[0]) { // a marker some versions put before a failed one
			f = f[1:]
		}
		if len(f) < 4 || !ValidUnit(f[0]) {
			continue
		}
		u := secproto.LinuxUnit{Name: f[0], Load: f[1], Active: f[2], Sub: f[3], Desc: cutRunes(strings.Join(f[4:], " "), 160)}
		u.Manage = s.manageable(u.Name)
		out = append(out, u)
		if len(out) >= secproto.MaxLinuxUnits {
			break
		}
	}
	for i := range out {
		byName[out[i].Name] = &out[i]
	}
	// How each starts at boot comes from a second list; a machine that cannot give it still gets the first.
	if fr := s.Runner.Run(ctx, s.Systemctl, "list-unit-files", "--type=service", "--plain", "--no-legend", "--no-pager", "--full"); fr.Err == nil && fr.ExitCode == 0 {
		for _, line := range strings.Split(fr.Stdout, "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				if u := byName[f[0]]; u != nil {
					u.Enabled = f[1]
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, true
}

func unitStart(s string) bool {
	return s != "" && (s[0] >= '0' && s[0] <= '9' || s[0] >= 'A' && s[0] <= 'Z' || s[0] >= 'a' && s[0] <= 'z')
}

func cutRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

func (s *Server) control(ctx context.Context, op, name string) Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.Runner.Run(ctx, s.Systemctl, op, name); r.Err != nil || r.ExitCode != 0 {
		return Response{Code: CodeCommand}
	}
	r := s.Runner.Run(ctx, s.Systemctl, "is-active", name)
	return Response{OK: true, Code: CodeOK, Active: strings.TrimSpace(r.Stdout)}
}

func (s *Server) journal(ctx context.Context, rq Request) Response {
	tail := rq.Tail
	if tail <= 0 {
		tail = DefaultTail
	}
	tail = min(tail, secproto.MaxLinuxTail)
	r := s.Runner.Run(ctx, s.Journalctl, "-u", rq.Name, "-n", strconv.Itoa(tail), "--no-pager", "-o", "short-iso")
	if r.Err != nil || r.ExitCode != 0 {
		return Response{Code: CodeCommand}
	}
	text, cut := lastBytes(r.Stdout, secproto.MaxLinuxText)
	return Response{OK: true, Code: CodeOK, Text: cleanText(text), Truncated: cut}
}

// lastBytes keeps the end of s that fits, starting at a line.
func lastBytes(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	s = s[len(s)-n:]
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	return s, true
}

var ansi = regexp.MustCompile("\x1b\\[[0-9;?]*[ -/]*[@-~]")

// cleanText makes text safe to show: no colour codes, no control characters but the line ones, valid UTF-8.
func cleanText(s string) string {
	s = ansi.ReplaceAllString(s, "")
	s = strings.ToValidUTF8(s, "?")
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r == '\r' {
			return -1
		}
		if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
			return '?'
		}
		return r
	}, s)
}

// --- files ---

var denyDirs = map[string]bool{
	"private": true, "letsencrypt": true, "wireguard": true, "amneziawg": true, "openvpn": true, "remnascope": true, "remnascope-sec": true,
	".ssh": true, ".gnupg": true, "secrets": true, "ssl-private": true,
}

var denyFiles = map[string]bool{
	"shadow": true, "shadow-": true, "gshadow": true, "gshadow-": true, ".env": true, ".netrc": true, ".git-credentials": true,
	".htpasswd": true, "htpasswd": true, "id_rsa": true, "id_dsa": true, "id_ecdsa": true, "id_ed25519": true, "secagent.token": true,
	"token": true, "credentials": true,
}

var denySuffix = []string{".key", ".pem", ".p12", ".pfx", ".token", ".secret", ".secrets", ".keytab", "_key", ".env"}

// secretName says whether one path component is the kind that holds secrets.
func secretName(name string, last bool) bool {
	n := strings.ToLower(name)
	if denyDirs[n] || (last && denyFiles[n]) {
		return true
	}
	if !last {
		return false
	}
	for _, suf := range denySuffix {
		if strings.HasSuffix(n, suf) {
			return true
		}
	}
	return strings.HasPrefix(n, ".env.") || strings.HasPrefix(n, "ssh_host_")
}

// pathAllowed says whether the resolved path is inside one of the allowed folders and has no secret-looking name in it.
func (s *Server) pathAllowed(real string) bool {
	for _, d := range s.Dirs {
		root := cleanDir(d)
		if root == "" {
			continue
		}
		if real != root && !strings.HasPrefix(real, root+"/") {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(real, "/"), "/")
		for i, p := range parts {
			if p != "" && secretName(p, i == len(parts)-1) {
				return false
			}
		}
		return true
	}
	return false
}

// cleanDir gives an allowed folder as it really is on disk, or "" if it is not usable (missing, or the whole disk).
func cleanDir(d string) string {
	d = strings.TrimSpace(d)
	if !filepath.IsAbs(d) {
		return ""
	}
	real, err := filepath.EvalSymlinks(filepath.Clean(d))
	if err != nil || real == "/" || real == "" {
		return ""
	}
	return filepath.ToSlash(real)
}

// resolve turns a requested path into the real one if it may be looked at.
func (s *Server) resolve(p string) (string, string) {
	if p == "" || len(p) > maxPath || strings.ContainsRune(p, 0) || !(strings.HasPrefix(p, "/") || filepath.IsAbs(p)) {
		return "", CodeBadRequest
	}
	real, err := filepath.EvalSymlinks(filepath.Clean(p))
	if err != nil {
		return "", CodeNoSuch
	}
	real = filepath.ToSlash(real)
	if !s.pathAllowed(real) {
		return "", CodeNotAllowed
	}
	return real, ""
}

func (s *Server) ls(p string) Response {
	if p == "" {
		var dirs []string
		for _, d := range s.Dirs {
			if c := cleanDir(d); c != "" {
				dirs = append(dirs, c)
			}
		}
		return Response{OK: true, Code: CodeOK, Dirs: dirs}
	}
	real, code := s.resolve(p)
	if code != "" {
		return Response{Code: code}
	}
	des, err := os.ReadDir(real)
	if err != nil {
		return Response{Code: CodeCommand}
	}
	var out []secproto.LinuxEntry
	for _, de := range des {
		if secretName(de.Name(), !de.IsDir()) {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		e := secproto.LinuxEntry{Name: de.Name(), Size: info.Size(), Mod: info.ModTime().Unix()}
		if info.Mode()&os.ModeSymlink != 0 {
			e.Link = true
			// What the link points at decides whether it is a folder; one that leads outside the allowed folders is not shown.
			t, err := filepath.EvalSymlinks(filepath.Join(real, de.Name()))
			if err != nil || !s.pathAllowed(filepath.ToSlash(t)) {
				continue
			}
			if st, err := os.Stat(t); err == nil {
				e.Dir, e.Size = st.IsDir(), st.Size()
			}
		} else {
			e.Dir = de.IsDir()
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	cut := len(out) > secproto.MaxLinuxEntries
	if cut {
		out = out[:secproto.MaxLinuxEntries]
	}
	return Response{OK: true, Code: CodeOK, Dir: real, Entries: out, Truncated: cut}
}

func (s *Server) cat(rq Request) Response {
	real, code := s.resolve(rq.Path)
	if code != "" {
		return Response{Code: code}
	}
	f, err := os.Open(real)
	if err != nil {
		return Response{Code: CodeCommand}
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return Response{Code: CodeNotFile}
	}
	cut := false
	if st.Size() > secproto.MaxLinuxText {
		if _, err := f.Seek(st.Size()-secproto.MaxLinuxText, io.SeekStart); err != nil {
			return Response{Code: CodeCommand}
		}
		cut = true
	}
	b, err := io.ReadAll(io.LimitReader(f, secproto.MaxLinuxText))
	if err != nil {
		return Response{Code: CodeCommand}
	}
	if bytes.IndexByte(b[:min(len(b), 8192)], 0) >= 0 {
		return Response{Code: CodeBinary}
	}
	text := string(b)
	if cut {
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			text = text[i+1:]
		}
	}
	if rq.Tail > 0 {
		tail := min(rq.Tail, secproto.MaxLinuxTail)
		lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
		if len(lines) > tail {
			text, cut = strings.Join(lines[len(lines)-tail:], "\n")+"\n", true
		}
	}
	return Response{OK: true, Code: CodeOK, Text: cleanText(text), Truncated: cut, Dir: real}
}

// Serve accepts connections until ctx ends. Each connection carries one request and one response.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	go func() { <-ctx.Done(); l.Close() }()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.conn(ctx, c)
	}
}

func (s *Server) conn(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	var rq Request
	dec := json.NewDecoder(io.LimitReader(c, maxRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rq); err != nil {
		_ = json.NewEncoder(c).Encode(Response{Code: CodeBadRequest})
		return
	}
	_ = json.NewEncoder(c).Encode(s.Handle(ctx, rq))
}

// Listen creates the socket with the given mode.
func Listen(path string, mode os.FileMode) (net.Listener, error) {
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Client asks a helper.
type Client struct{ Path string }

func (c Client) Do(ctx context.Context, rq Request) (Response, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return Response{Code: CodeUnavailable}, err
	}
	defer conn.Close()
	dl, ok := ctx.Deadline()
	if !ok || time.Until(dl) > 60*time.Second {
		dl = time.Now().Add(60 * time.Second)
	}
	_ = conn.SetDeadline(dl)
	if err := json.NewEncoder(conn).Encode(rq); err != nil {
		return Response{Code: CodeUnavailable}, err
	}
	var rs Response
	if err := json.NewDecoder(io.LimitReader(conn, 4<<20)).Decode(&rs); err != nil {
		return Response{Code: CodeUnavailable}, err
	}
	return rs, nil
}
