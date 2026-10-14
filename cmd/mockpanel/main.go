// mockpanel pretends to be two Remnawave panels over HTTPS, for local development only.
// It keeps its own CA in -state (so the CA is stable across restarts), writes the CA
// certificate to -certs for the API to trust, and serves each panel on its own port.
// Never run it anywhere that real tokens exist.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	certs := flag.String("certs", "/certs", "directory to write ca.pem into (shared with the API, read-only there)")
	state := flag.String("state", "/state", "directory that keeps the CA key between restarts (private to this container)")
	homeHost := flag.String("home-host", "mock-home.demo.test", "DNS name of the home panel")
	workHost := flag.String("work-host", "mock-work.demo.test", "DNS name of the work panel")
	homePort := flag.Int("home-port", 8443, "port of the home panel")
	workPort := flag.Int("work-port", 8444, "port of the work panel")
	homeTokenFile := flag.String("home-token-file", "", "file holding the home panel API token")
	workTokenFile := flag.String("work-token-file", "", "file holding the work panel API token")
	check := flag.String("check", "", "exit 0 if this file exists (used as a container health check)")
	flag.Parse()

	if *check != "" {
		if _, err := os.Stat(*check); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	read := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil || strings.TrimSpace(string(b)) == "" {
			log.Fatalf("token file %q is required and must not be empty", path)
		}
		return strings.TrimSpace(string(b))
	}
	home, work := specs(read(*homeTokenFile), read(*workTokenFile))

	ca, err := loadOrCreateCA(*state)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := ca.issue([]string{*homeHost, *workHost})
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(*certs, 0o755); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*certs, "ca.pem"), ca.certPEM, 0o644); err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serve := func(port int, s spec) {
		srv := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: newHandler(s), ReadHeaderTimeout: 5 * time.Second,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
		go func() {
			<-ctx.Done()
			_ = srv.Close()
		}()
		log.Printf("%s listening on :%d", s.Name, port)
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}
	go serve(*workPort, work)
	serve(*homePort, home)
}

type authority struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

// loadOrCreateCA reuses the CA stored in dir, or makes one and stores it.
func loadOrCreateCA(dir string) (*authority, error) {
	certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if certPEM, err := os.ReadFile(certPath); err == nil {
		keyPEM, kerr := os.ReadFile(keyPath)
		if kerr != nil {
			return nil, kerr
		}
		return parseCA(certPEM, keyPEM)
	}
	a, keyPEM, err := newCA()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, a.certPEM, 0o644); err != nil {
		return nil, err
	}
	return a, nil
}

func parseCA(certPEM, keyPEM []byte) (*authority, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("stored CA is not valid PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &authority{cert: cert, key: key, certPEM: certPEM}, nil
}

func newCA() (*authority, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "RemnaScope mock panels dev CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return &authority{cert: cert, key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})},
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

// issue makes a leaf certificate valid for the given DNS names, signed by this CA.
func (a *authority) issue(names []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
