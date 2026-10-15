package netintel

import (
	"crypto/x509"
	"time"
)

// VerifyChain judges a presented chain: ok, or why not (expired | untrusted | hostname_mismatch | invalid).
// An empty host skips the name check.
func VerifyChain(certs []*x509.Certificate, host string, now time.Time) (bool, string) {
	return verifyChain(certs, host, now)
}

// DescribeCert summarises one certificate.
func DescribeCert(c *x509.Certificate, now time.Time) CertInfo { return certInfo(c, now) }
