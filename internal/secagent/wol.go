package secagent

import (
	"net"
	"strings"

	"github.com/Taminum/Owlery/internal/secproto"
)

// A network card that is only a software one (containers, virtual machines, tunnels) is never what wakes a machine up.
var virtualNIC = []string{"veth", "docker", "br-", "virbr", "vethernet", "vmware", "virtualbox", "vboxnet", "loopback", "tailscale", "tun", "tap", "wg", "zerotier", "hyper-v", "wsl", "isatap", "teredo", "pseudo"}

func isVirtualNIC(name string) bool {
	n := strings.ToLower(name)
	for _, v := range virtualNIC {
		if strings.Contains(n, v) {
			return true
		}
	}
	return false
}

// privateV4 lists the interface's private IPv4 addresses with their networks.
func privateV4(ifc net.Interface) []*net.IPNet {
	addrs, _ := ifc.Addrs()
	var out []*net.IPNet
	for _, ad := range addrs {
		ipn, ok := ad.(*net.IPNet)
		if !ok {
			continue
		}
		if ip4 := ipn.IP.To4(); ip4 != nil && ip4.IsPrivate() && len(ipn.Mask) >= 4 {
			out = append(out, &net.IPNet{IP: ip4, Mask: ipn.Mask[len(ipn.Mask)-4:]})
		}
	}
	return out
}

// wolReport names this machine's real network cards: up, with a hardware address and a private address.
func wolReport() []secproto.WolNIC {
	ifs, _ := net.Interfaces()
	var out []secproto.WolNIC
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || len(ifc.HardwareAddr) != 6 || isVirtualNIC(ifc.Name) {
			continue
		}
		nets := privateV4(ifc)
		if len(nets) == 0 {
			continue
		}
		n := secproto.WolNIC{Name: ifc.Name, MAC: ifc.HardwareAddr.String()}
		for _, x := range nets {
			n.IPs = append(n.IPs, x.IP.String())
		}
		out = append(out, n)
		if len(out) == 8 {
			break
		}
	}
	return out
}

// magicPacket is six 0xFF bytes and then the address sixteen times.
func magicPacket(mac net.HardwareAddr) []byte {
	p := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		p = append(p, 0xFF)
	}
	for i := 0; i < 16; i++ {
		p = append(p, mac...)
	}
	return p
}

// wolSend broadcasts the packet on every real private network this machine is in, and returns how many broadcasts went out.
func wolSend(mac net.HardwareAddr) int {
	pkt := magicPacket(mac)
	ifs, _ := net.Interfaces()
	sent := 0
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || isVirtualNIC(ifc.Name) {
			continue
		}
		for _, n := range privateV4(ifc) {
			bc := make(net.IP, 4)
			for i := range bc {
				bc[i] = n.IP[i] | ^n.Mask[i]
			}
			conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: n.IP}, &net.UDPAddr{IP: bc, Port: 9})
			if err != nil {
				continue
			}
			if _, err := conn.Write(pkt); err == nil {
				sent++
			}
			conn.Close()
		}
	}
	return sent
}

// wolHandle answers one request. The address is parsed here again, whatever the server sent.
func wolHandle(req secproto.WolReq) secproto.WolResult {
	res := secproto.WolResult{Type: "wol_result", ID: req.ID}
	switch req.Op {
	case secproto.WolReport:
		res.NICs = wolReport()
		res.OK = true
	case secproto.WolSend:
		mac, err := net.ParseMAC(req.MAC)
		if err != nil || len(mac) != 6 {
			res.Error = "неверный MAC-адрес"
			return res
		}
		res.Sent = wolSend(mac)
		res.OK = res.Sent > 0
		if !res.OK {
			res.Error = "у этой машины нет подходящей сети, пакет не ушёл"
		}
	default:
		res.Error = "неизвестное действие"
	}
	return res
}
