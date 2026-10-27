package alerts

import (
	"strings"
	"testing"

	"github.com/Taminum/Owlery/internal/secproto"
	"github.com/Taminum/Owlery/internal/store"
)

func TestWindowsDisksOnlyTheSystemDriveAlerts(t *testing.T) {
	full := func(m string) secproto.HostDisk { return secproto.HostDisk{Mount: m, Total: 100, Used: 99} }
	got := HostConditions([]store.HostAlertState{{VPSID: "pc", Name: "home-pc", Online: true, Disks: []secproto.HostDisk{full("C:"), full("D:"), full("I:")}},
		{VPSID: "srv", Name: "exit", Online: true, Disks: []secproto.HostDisk{full("/"), full("/data")}}})
	var subjects []string
	for _, c := range got {
		subjects = append(subjects, c.Subject)
	}
	if strings.Join(subjects, " ") != "pc:C: srv:/ srv:/data" {
		t.Fatalf("%v", subjects)
	}
}
