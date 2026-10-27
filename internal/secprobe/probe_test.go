package secprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Taminum/Owlery/internal/secevents"
)

// allowLoopback lets the checker dial the test servers, then puts the real rule back.
func allowLoopback(t *testing.T) {
	t.Helper()
	old := AllowAddr
	AllowAddr = func(a netip.Addr) bool { return a.IsLoopback() }
	t.Cleanup(func() { AllowAddr = old })
}

func listen(t *testing.T) (net.Listener, int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, l.Addr().(*net.TCPAddr).Port
}

func TestTCPReachableRefusedAndBlocked(t *testing.T) {
	ctx := context.Background()
	// With the real rule, a loopback target is refused outright and nothing is dialled.
	l, port := listen(t)
	if r := TCP(ctx, "127.0.0.1", port); r.Result != secevents.PortError || r.Error != "blocked_address" {
		t.Fatalf("a private target must be blocked: %+v", r)
	}
	for _, h := range []string{"10.0.0.1", "192.168.1.1", "169.254.169.254", "::1", "fe80::1"} {
		if r := TCP(ctx, h, 80); r.Result != secevents.PortError {
			t.Errorf("%s: %+v", h, r)
		}
	}

	allowLoopback(t)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if r := TCP(ctx, "127.0.0.1", port); r.Result != secevents.PortReachable || r.IP != "127.0.0.1" || r.RTTms < 1 {
		t.Fatalf("%+v", r)
	}
	l2, closedPort := listen(t)
	l2.Close()
	if r := TCP(ctx, "127.0.0.1", closedPort); r.Result != secevents.PortRefused {
		t.Fatalf("%+v", r)
	}
}

func TestResolveKeepsOnlyPublicAddressesAndPrefersIPv4(t *testing.T) {
	old := Lookup
	t.Cleanup(func() { Lookup = old })
	Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("93.184.216.34")}, nil
	}
	oldAllow := AllowAddr
	t.Cleanup(func() { AllowAddr = oldAllow })
	AllowAddr = func(a netip.Addr) bool { return !a.IsPrivate() }
	addrs, resolved, err := Resolve(context.Background(), "example.test")
	if err != nil || len(addrs) != 2 || addrs[0].String() != "93.184.216.34" || len(resolved) != 3 {
		t.Fatalf("%v %v %v", addrs, resolved, err)
	}
	// A name that points only inward is blocked, and the answer is still recorded.
	Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.1.1.1")}, nil
	}
	if _, res, err := Resolve(context.Background(), "inner.test"); err == nil || len(res) != 1 {
		t.Fatalf("%v %v", res, err)
	}
}

func selfSigned(t *testing.T, notBefore, notAfter time.Time, names ...string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "test"}, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: names, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func serveTLS(t *testing.T, cert tls.Certificate) int {
	t.Helper()
	l, port := listen(t)
	tl := tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{cert}})
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	return port
}

func TestTLSKeepsDatesOfAnUntrustedCertificateAndJudgesHonestly(t *testing.T) {
	allowLoopback(t)
	ctx := context.Background()
	now := time.Now()

	// Self-signed: untrusted, but the dates and fingerprint are not lost.
	port := serveTLS(t, selfSigned(t, now.Add(-time.Hour), now.Add(10*24*time.Hour), "a.example"))
	r := TLS(ctx, "127.0.0.1", port, "a.example", now)
	if r.State != secevents.TLSUntrusted || !r.HasCert || r.Fingerprint == "" || r.DaysLeft < 9 || r.DaysLeft > 10 || r.IP != "127.0.0.1" || r.Version == "" {
		t.Fatalf("%+v", r)
	}
	if !r.NameChecked || r.SNI != "a.example" {
		t.Fatalf("%+v", r)
	}

	// The same certificate seen again has the same fingerprint (what renewal detection relies on).
	if r2 := TLS(ctx, "127.0.0.1", port, "a.example", now); r2.Fingerprint != r.Fingerprint {
		t.Fatal("the fingerprint is not stable")
	}

	// An address with no SNI: nothing to check the name against, and that is said.
	if r3 := TLS(ctx, "127.0.0.1", port, "", now); r3.NameChecked || r3.SNI != "" {
		t.Fatalf("%+v", r3)
	}

	// An expired certificate reports its negative days.
	exp := serveTLS(t, selfSigned(t, now.Add(-30*24*time.Hour), now.Add(-2*24*time.Hour), "b.example"))
	if r4 := TLS(ctx, "127.0.0.1", exp, "b.example", now); !r4.HasCert || r4.DaysLeft >= 0 || r4.State != secevents.TLSExpired {
		t.Fatalf("%+v", r4)
	}

	// A server that does not speak TLS is a handshake error, not an expiry.
	plain, pp := listen(t)
	go func() {
		for {
			c, err := plain.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-test\r\n"))
			c.Close()
		}
	}()
	if r5 := TLS(ctx, "127.0.0.1", pp, "", now); r5.State != secevents.TLSHandshake || r5.HasCert {
		t.Fatalf("%+v", r5)
	}

	// Nothing listening: unreachable, never a verdict about a certificate.
	l, cp := listen(t)
	l.Close()
	if r6 := TLS(ctx, "127.0.0.1", cp, "", now); r6.State != secevents.TLSUnreachable || r6.HasCert {
		t.Fatalf("%+v", r6)
	}
}

func TestTLSRefusesPrivateTargets(t *testing.T) {
	r := TLS(context.Background(), "127.0.0.1", 443, "", time.Now())
	if r.State != secevents.TLSBlocked || r.Error != "blocked_address" {
		t.Fatalf("%+v", r)
	}
}
