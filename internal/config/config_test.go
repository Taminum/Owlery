package config

import "testing"

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDefaultsAreSafe(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !c.CookieSecure || len(c.AllowedPorts) != 1 || c.AllowedPorts[0] != 443 || len(c.AllowPrivateHosts) != 0 || c.SeedDemo || len(c.TrustedProxies) != 0 {
		t.Fatalf("%+v", c)
	}
	if c.Require() == nil {
		t.Fatal("database and master key must be required")
	}
}

func TestParsing(t *testing.T) {
	c, err := Load(env(map[string]string{
		"DATABASE_URL": "postgres://x", "MASTER_KEY_FILE": "/run/secrets/k", "COOKIE_SECURE": "false", "SEED_DEMO": "true",
		"TRUSTED_PROXIES": "172.16.0.0/12, 10.0.0.0/8", "ALLOWED_PORTS": "443,8443", "ALLOW_PRIVATE_HOSTS": "Mock-Home.internal.test",
		"ACTIVE_KEY_VERSION": "2", "SESSION_TTL_HOURS": "8", "BOOTSTRAP_OWNER": "owner", "BOOTSTRAP_PASSWORD_FILE": "/run/secrets/p",
	}))
	if err != nil || c.Require() != nil {
		t.Fatalf("%v %v", err, c.Require())
	}
	if c.CookieSecure || !c.SeedDemo || len(c.TrustedProxies) != 2 || len(c.AllowedPorts) != 2 || c.AllowPrivateHosts[0] != "mock-home.internal.test" ||
		c.ActiveKeyVersion != 2 || c.SessionTTL.Hours() != 8 {
		t.Fatalf("%+v", c)
	}
}

func TestRejectsBadValues(t *testing.T) {
	for name, m := range map[string]map[string]string{
		"bool":           {"COOKIE_SECURE": "maybe"},
		"proxy":          {"TRUSTED_PROXIES": "not-a-cidr"},
		"port":           {"ALLOWED_PORTS": "443,99999"},
		"wildcard host":  {"ALLOW_PRIVATE_HOSTS": "*.corp.test"},
		"host with port": {"ALLOW_PRIVATE_HOSTS": "a.corp.test:8443"},
		"single label":   {"ALLOW_PRIVATE_HOSTS": "localhost"},
		"key version":    {"ACTIVE_KEY_VERSION": "0"},
		"session ttl":    {"SESSION_TTL_HOURS": "0"},
		"half bootstrap": {"BOOTSTRAP_OWNER": "owner"},
	} {
		if _, err := Load(env(m)); err == nil {
			t.Errorf("%s should be rejected", name)
		}
	}
}
