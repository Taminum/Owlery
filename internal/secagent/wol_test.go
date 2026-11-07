package secagent

import (
	"bytes"
	"net"
	"testing"

	"github.com/Taminum/Owlery/internal/secproto"
)

func TestMagicPacketIsSixFFAndTheAddressSixteenTimes(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	p := magicPacket(mac)
	if len(p) != 102 || !bytes.Equal(p[:6], bytes.Repeat([]byte{0xFF}, 6)) || !bytes.Equal(p[96:], mac) || !bytes.Equal(p[6:12], mac) {
		t.Fatalf("bad packet: %x", p)
	}
}

func TestWolRefusesABadAddressAndAnUnknownOperation(t *testing.T) {
	for _, mac := range []string{"", "zz", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:01:02:03"} {
		if r := wolHandle(secproto.WolReq{ID: "1", Op: secproto.WolSend, MAC: mac}); r.OK || r.Error == "" {
			t.Errorf("%q must be refused: %+v", mac, r)
		}
	}
	if r := wolHandle(secproto.WolReq{ID: "1", Op: "reboot"}); r.OK {
		t.Errorf("unknown operation: %+v", r)
	}
}

func TestSoftwareNetworkCardsAreNotOffered(t *testing.T) {
	for _, n := range []string{"docker0", "veth12ab", "vEthernet (WSL)", "Tailscale", "br-1f2e", "VMware Network Adapter VMnet8"} {
		if !isVirtualNIC(n) {
			t.Errorf("%s is virtual", n)
		}
	}
	for _, n := range []string{"Ethernet", "eth0", "enp3s0", "Wi-Fi"} {
		if isVirtualNIC(n) {
			t.Errorf("%s is real", n)
		}
	}
}
