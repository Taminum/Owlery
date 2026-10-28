// Package config reads and validates the server's environment. Secrets are only ever
// referenced by file path here (Docker/host secrets), never carried in variables.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr        string
	DatabaseURL       string
	MasterKeyFile     string
	ActiveKeyVersion  int
	CookieSecure      bool
	TrustedProxies    []netip.Prefix
	AllowedPorts      []int
	AllowPrivateHosts []string
	TrustedCAFile     string
	SeedDemo          bool
	BootstrapOwner    string
	BootstrapPassFile string
	GeminiKeyFile     string // optional: the file holding the Gemini API key (a secret, never a variable)
	RecordsDir        string // optional: where terminal sessions are recorded; empty = not recorded
	GuacdAddr         string // optional: guacd for remote desktops (host:port); empty = desktops off
	DesktopHost       string // how guacd reaches the API for a desktop tunnel
	ServicesDomain    string // optional: parent domain of web services' subdomains; empty = off
	SyncEnabled       bool
	SessionTTL        time.Duration
	IdleTTL           time.Duration
}

// Load parses env (a lookup function, so tests need not touch the process environment).
func Load(get func(string) string) (Config, error) {
	c := Config{
		ListenAddr:        or(get("LISTEN_ADDR"), ":8080"),
		DatabaseURL:       get("DATABASE_URL"),
		MasterKeyFile:     get("MASTER_KEY_FILE"),
		CookieSecure:      true,
		AllowedPorts:      []int{443},
		TrustedCAFile:     get("TRUSTED_CA_FILE"),
		BootstrapOwner:    get("BOOTSTRAP_OWNER"),
		BootstrapPassFile: get("BOOTSTRAP_PASSWORD_FILE"),
		GeminiKeyFile:     get("GEMINI_API_KEY_FILE"),
		RecordsDir:        get("RECORDS_DIR"),
		GuacdAddr:         get("GUACD_ADDR"),
		DesktopHost:       or(get("DESKTOP_HOST"), "api"),
		ServicesDomain:    strings.ToLower(strings.TrimSpace(get("SERVICES_DOMAIN"))),
		SyncEnabled:       true,
		SessionTTL:        12 * time.Hour,
		IdleTTL:           2 * time.Hour,
	}
	var errs []error
	boolVar := func(name string, dst *bool) {
		if v := get(name); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s must be true or false", name))
				return
			}
			*dst = b
		}
	}
	boolVar("COOKIE_SECURE", &c.CookieSecure)
	boolVar("SEED_DEMO", &c.SeedDemo)
	boolVar("SYNC_ENABLED", &c.SyncEnabled)

	if v := get("ACTIVE_KEY_VERSION"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			errs = append(errs, errors.New("ACTIVE_KEY_VERSION must be a positive integer"))
		}
		c.ActiveKeyVersion = n
	}
	for _, s := range split(get("TRUSTED_PROXIES")) {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			errs = append(errs, fmt.Errorf("TRUSTED_PROXIES: %q is not a CIDR", s))
			continue
		}
		c.TrustedProxies = append(c.TrustedProxies, p)
	}
	if v := get("ALLOWED_PORTS"); v != "" {
		c.AllowedPorts = nil
		for _, s := range split(v) {
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 || n > 65535 {
				errs = append(errs, fmt.Errorf("ALLOWED_PORTS: %q is not a port", s))
				continue
			}
			c.AllowedPorts = append(c.AllowedPorts, n)
		}
	}
	for _, h := range split(get("ALLOW_PRIVATE_HOSTS")) {
		if strings.ContainsAny(h, "/:*") || !strings.Contains(h, ".") {
			errs = append(errs, fmt.Errorf("ALLOW_PRIVATE_HOSTS: %q must be an exact host name, no wildcards or ports", h))
			continue
		}
		c.AllowPrivateHosts = append(c.AllowPrivateHosts, strings.ToLower(h))
	}
	if v := get("SESSION_TTL_HOURS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 24*30 {
			errs = append(errs, errors.New("SESSION_TTL_HOURS must be 1 to 720"))
		} else {
			c.SessionTTL = time.Duration(n) * time.Hour
		}
	}
	if (c.BootstrapOwner == "") != (c.BootstrapPassFile == "") {
		errs = append(errs, errors.New("BOOTSTRAP_OWNER and BOOTSTRAP_PASSWORD_FILE must be set together"))
	}
	return c, errors.Join(errs...)
}

// Require checks what `serve` cannot run without.
func (c Config) Require() error {
	var errs []error
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("DATABASE_URL is required"))
	}
	if c.MasterKeyFile == "" {
		errs = append(errs, errors.New("MASTER_KEY_FILE is required: panel tokens cannot be stored without an encryption key"))
	}
	return errors.Join(errs...)
}

func or(v, d string) string {
	if v != "" {
		return v
	}
	return d
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// FromEnv is Load over the real environment.
func FromEnv() (Config, error) { return Load(os.Getenv) }
