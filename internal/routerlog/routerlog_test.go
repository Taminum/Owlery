package routerlog

import (
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)

const good = `{"v":1,"id":"c1","t":"2026-10-13T07:59:00Z","u":"2026-10-13T07:59:30Z","src":"192.168.1.176","n":"Home","h":"API.Example.com.","di":"1.2.3.4","dp":443,"p":"tcp","up":10,"dn":20,"o":"main-out"}`

func TestParseGood(t *testing.T) {
	e, err := Parse(good, now)
	if err != nil {
		t.Fatal(err)
	}
	if e.Host != "api.example.com" || e.Device.String() != "192.168.1.176" || e.Up != 10 || e.Down != 20 || e.Port != 443 || e.DeviceName != "Home" {
		t.Fatalf("%+v", e)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"public device":    strings.Replace(good, "192.168.1.176", "8.8.8.8", 1),
		"bad proto":        strings.Replace(good, `"tcp"`, `"icmp"`, 1),
		"negative bytes":   strings.Replace(good, `"up":10`, `"up":-1`, 1),
		"port too big":     strings.Replace(good, `"dp":443`, `"dp":70000`, 1),
		"future start":     strings.Replace(good, "2026-10-13T07:59:00Z", "2026-10-14T07:59:00Z", 1),
		"ancient start":    strings.Replace(good, "2026-10-13T07:59:00Z", "2026-01-01T07:59:00Z", 1),
		"seen before":      strings.Replace(good, "2026-10-13T07:59:30Z", "2026-10-13T07:58:00Z", 1),
		"unknown field":    strings.Replace(good, `"v":1`, `"v":1,"x":1`, 1),
		"wrong version":    strings.Replace(good, `"v":1`, `"v":2`, 1),
		"control in name":  strings.Replace(good, "Home", `Ho\u0007me`, 1),
		"no destination":   strings.Replace(strings.Replace(good, `"h":"API.Example.com.",`, "", 1), `"di":"1.2.3.4",`, "", 1),
		"bad dest ip":      strings.Replace(good, "1.2.3.4", "nope", 1),
		"empty id":         strings.Replace(good, `"id":"c1"`, `"id":""`, 1),
		"not json":         "198.18.0.1 accepted",
		"unspecified host": strings.Replace(good, "192.168.1.176", "0.0.0.0", 1),
	}
	for name, line := range cases {
		if _, err := Parse(line, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestIsRecord(t *testing.T) {
	if !IsRecord(good) || IsRecord("2026/10/13 accepted") {
		t.Fatal("IsRecord")
	}
}
