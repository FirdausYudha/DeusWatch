// Package mtls provides certificate generation and TLS configuration for
// DeusWatch mutual-TLS (mTLS) communication.
//
// All agent–server communication MUST use mTLS (design doc section 4): there is no
// plaintext path. The generator is based on the stdlib crypto/x509 so it is cross-OS
// (Linux/Windows/macOS) without depending on an external openssl binary.
package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CertPaths points to the standard PEM file locations within a certificate directory.
type CertPaths struct {
	CACert     string
	CAKey      string
	ServerCert string
	ServerKey  string
	ClientCert string
	ClientKey  string
}

// Paths returns the standard PEM file locations inside dir.
func Paths(dir string) CertPaths {
	return CertPaths{
		CACert:     filepath.Join(dir, "ca.crt"),
		CAKey:      filepath.Join(dir, "ca.key"),
		ServerCert: filepath.Join(dir, "server.crt"),
		ServerKey:  filepath.Join(dir, "server.key"),
		ClientCert: filepath.Join(dir, "client.crt"),
		ClientKey:  filepath.Join(dir, "client.key"),
	}
}

// Options controls certificate bundle generation.
type Options struct {
	Dir       string        // output directory
	ServerDNS []string      // SAN DNS for the server certificate
	ServerIPs []net.IP      // SAN IP for the server certificate
	ValidFor  time.Duration // leaf certificate validity (server & client)
}

type keyPair struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// generateCA creates a new self-signed CA.
func generateCA(commonName string, validFor time.Duration) (*keyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"DeusWatch"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // may only issue leaf certs, not intermediate CAs
	}
	return finalize(tmpl, tmpl, key, key)
}

// issueLeaf issues a CA-signed leaf certificate (server/client).
func issueLeaf(ca *keyPair, commonName string, dnsNames []string, ips []net.IP, eku []x509.ExtKeyUsage, validFor time.Duration) (*keyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"DeusWatch"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	return finalize(tmpl, ca.cert, key, ca.key)
}

// finalize creates a certificate from the template, signs it with signerKey,
// then parses the result back.
func finalize(tmpl, parent *x509.Certificate, subjectKey *ecdsa.PrivateKey, signerKey *ecdsa.PrivateKey) (*keyPair, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &subjectKey.PublicKey, signerKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &keyPair{cert: cert, der: der, key: subjectKey}, nil
}

func writeCertPEM(path string, der []byte) error {
	buf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return os.WriteFile(path, buf, 0o644)
}

func writeKeyPEM(path string, key *ecdsa.PrivateKey) error {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	buf := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})
	return os.WriteFile(path, buf, 0o600) // private key: owner only
}

// CA is a Certificate Authority loaded from disk, used to issue per-agent client
// certificates during enrollment (design doc sections 4 & 12).
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// LoadCA loads the CA (ca.crt + ca.key) from the certificate directory.
func LoadCA(dir string) (*CA, error) {
	p := Paths(dir)
	certPEM, err := os.ReadFile(p.CACert)
	if err != nil {
		return nil, fmt.Errorf("mtls: read ca.crt: %w", err)
	}
	keyPEM, err := os.ReadFile(p.CAKey)
	if err != nil {
		return nil, fmt.Errorf("mtls: read ca.key: %w", err)
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, fmt.Errorf("mtls: ca.crt is not valid PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mtls: parse ca.crt: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("mtls: ca.key is not valid PEM")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mtls: parse ca.key: %w", err)
	}
	key, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("mtls: ca.key is not ECDSA")
	}
	return &CA{cert: cert, key: key}, nil
}

// IssueClient issues a new client certificate with CommonName commonName, signed by
// the CA. Returns the cert + key PEM and the serial number (for audit/revoke).
func (ca *CA) IssueClient(commonName string, validFor time.Duration) (certPEM, keyPEM []byte, serial string, err error) {
	leaf, err := issueLeaf(&keyPair{cert: ca.cert, key: ca.key}, commonName, nil, nil,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, validFor)
	if err != nil {
		return nil, nil, "", err
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(leaf.key)
	if err != nil {
		return nil, nil, "", err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, leaf.cert.SerialNumber.String(), nil
}

// CACertPEM returns the CA certificate in PEM (to send to the agent at enroll time).
func (ca *CA) CACertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

// GenerateBundle creates a CA + server certificate + client certificate and writes
// them as PEM files to opt.Dir. Safe to call again (overwrites).
func GenerateBundle(opt Options) (CertPaths, error) {
	if opt.ValidFor == 0 {
		opt.ValidFor = 825 * 24 * time.Hour // ~27 months, common TLS certificate limit
	}
	paths := Paths(opt.Dir)
	if err := os.MkdirAll(opt.Dir, 0o755); err != nil {
		return paths, err
	}

	ca, err := generateCA("DeusWatch Root CA", 10*365*24*time.Hour)
	if err != nil {
		return paths, fmt.Errorf("generate CA: %w", err)
	}
	server, err := issueLeaf(ca, "deuswatch-server", opt.ServerDNS, opt.ServerIPs,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, opt.ValidFor)
	if err != nil {
		return paths, fmt.Errorf("issue server cert: %w", err)
	}
	client, err := issueLeaf(ca, "deuswatch-agent", nil, nil,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, opt.ValidFor)
	if err != nil {
		return paths, fmt.Errorf("issue client cert: %w", err)
	}

	writes := []struct {
		fn   func() error
		what string
	}{
		{func() error { return writeCertPEM(paths.CACert, ca.der) }, "ca.crt"},
		{func() error { return writeKeyPEM(paths.CAKey, ca.key) }, "ca.key"},
		{func() error { return writeCertPEM(paths.ServerCert, server.der) }, "server.crt"},
		{func() error { return writeKeyPEM(paths.ServerKey, server.key) }, "server.key"},
		{func() error { return writeCertPEM(paths.ClientCert, client.der) }, "client.crt"},
		{func() error { return writeKeyPEM(paths.ClientKey, client.key) }, "client.key"},
	}
	for _, w := range writes {
		if err := w.fn(); err != nil {
			return paths, fmt.Errorf("write %s: %w", w.what, err)
		}
	}
	return paths, nil
}
