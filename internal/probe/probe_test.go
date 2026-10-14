package probe

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
)

func hostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(p)
	return h, n
}

func allowLoopback(t *testing.T) {
	t.Helper()
	old := allowAddr
	allowAddr = func(a netip.Addr) bool { return a.IsLoopback() }
	t.Cleanup(func() { allowAddr = old })
}

func TestMeasureTCPAndTLS(t *testing.T) {
	allowLoopback(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	host, port := hostPort(t, srv.Listener.Addr().String())

	tcp := Measure(t.Context(), host, port, "tcp", "")
	if !tcp.OK || tcp.ConnectMS < 1 || tcp.TLSMS != 0 || tcp.Error != "" {
		t.Fatalf("tcp: %+v", tcp)
	}
	tl := Measure(t.Context(), host, port, "tls", "anything.example")
	if !tl.OK || tl.ConnectMS < 1 || tl.TLSMS < 1 {
		t.Fatalf("tls: %+v", tl)
	}
	// A plain TCP listener is reachable but does not speak TLS: the connect time is kept, the handshake fails.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("not tls\n"))
			c.Close()
		}
	}()
	h2, p2 := hostPort(t, ln.Addr().String())
	if r := Measure(t.Context(), h2, p2, "tls", ""); r.OK || r.Error != "tls" || r.ConnectMS < 1 {
		t.Fatalf("non-TLS peer: %+v", r)
	}
	_ = tls.VersionTLS12
}

func TestMeasureFailuresHaveShortCodes(t *testing.T) {
	allowLoopback(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_, port := hostPort(t, ln.Addr().String())
	ln.Close() // nothing listens any more
	if r := Measure(t.Context(), "127.0.0.1", port, "tcp", ""); r.OK || r.Error != "refused" {
		t.Fatalf("refused: %+v", r)
	}
	if r := Measure(t.Context(), "no-such-host.invalid", 443, "tcp", ""); r.OK || r.Error != "dns" {
		t.Fatalf("dns: %+v", r)
	}
}

// With the real policy nothing private, local or reserved can be probed, by address or by name,
// so a target cannot be used to look at the server's own network.
func TestMeasureRefusesNonPublicAddresses(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "::1", "100.64.0.1", "0.0.0.0", "fe80::1", "198.18.0.1"} {
		if r := Measure(t.Context(), host, 80, "tcp", ""); r.OK || r.Error != ErrorBlocked {
			t.Errorf("%s: %+v", host, r)
		}
	}
	// "localhost" resolves to loopback: refused as well, not "dns".
	if r := Measure(t.Context(), "localhost", 80, "tcp", ""); r.OK || r.Error != ErrorBlocked {
		t.Errorf("localhost: %+v", r)
	}
}
