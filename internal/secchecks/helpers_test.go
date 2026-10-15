package secchecks

import (
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

	"github.com/Taminum/RemnaScope/internal/secprobe"
)

// allowLoopback lets the checker dial the test servers, then puts the real rule back.
func allowLoopback(t *testing.T) {
	t.Helper()
	old := secprobe.AllowAddr
	secprobe.AllowAddr = func(a netip.Addr) bool { return a.IsLoopback() }
	t.Cleanup(func() { secprobe.AllowAddr = old })
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
