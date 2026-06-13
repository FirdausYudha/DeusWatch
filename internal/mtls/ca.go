// Package mtls menyediakan pembuatan sertifikat dan konfigurasi TLS untuk
// komunikasi mutual-TLS (mTLS) DeusWatch.
//
// Seluruh komunikasi agent–server WAJIB mTLS (design doc bagian 4): tidak ada
// jalur plaintext. Generator berbasis crypto/x509 stdlib agar lintas-OS
// (Linux/Windows/macOS) tanpa ketergantungan pada biner openssl eksternal.
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

// CertPaths menunjuk lokasi berkas PEM standar di sebuah direktori sertifikat.
type CertPaths struct {
	CACert     string
	CAKey      string
	ServerCert string
	ServerKey  string
	ClientCert string
	ClientKey  string
}

// Paths mengembalikan lokasi berkas PEM standar di dalam dir.
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

// Options mengatur pembuatan bundel sertifikat.
type Options struct {
	Dir       string        // direktori output
	ServerDNS []string      // SAN DNS untuk sertifikat server
	ServerIPs []net.IP      // SAN IP untuk sertifikat server
	ValidFor  time.Duration // masa berlaku sertifikat daun (server & client)
}

type keyPair struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// generateCA membuat CA self-signed baru.
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
		MaxPathLenZero:        true, // hanya boleh menerbitkan sertifikat daun, bukan intermediate CA
	}
	return finalize(tmpl, tmpl, key, key)
}

// issueLeaf menerbitkan sertifikat daun (server/client) yang ditandatangani CA.
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

// finalize membuat sertifikat dari template, menandatanganinya dengan signerKey,
// lalu mem-parse hasilnya kembali.
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
	return os.WriteFile(path, buf, 0o600) // kunci privat: hanya pemilik
}

// CA adalah Certificate Authority termuat dari disk, untuk menerbitkan
// sertifikat client per-agent saat enrollment (design doc bagian 4 & 12).
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// LoadCA memuat CA (ca.crt + ca.key) dari direktori sertifikat.
func LoadCA(dir string) (*CA, error) {
	p := Paths(dir)
	certPEM, err := os.ReadFile(p.CACert)
	if err != nil {
		return nil, fmt.Errorf("mtls: baca ca.crt: %w", err)
	}
	keyPEM, err := os.ReadFile(p.CAKey)
	if err != nil {
		return nil, fmt.Errorf("mtls: baca ca.key: %w", err)
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, fmt.Errorf("mtls: ca.crt bukan PEM valid")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mtls: parse ca.crt: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("mtls: ca.key bukan PEM valid")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mtls: parse ca.key: %w", err)
	}
	key, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("mtls: ca.key bukan ECDSA")
	}
	return &CA{cert: cert, key: key}, nil
}

// IssueClient menerbitkan sertifikat client baru ber-CommonName commonName,
// ditandatangani CA. Mengembalikan PEM cert + key dan nomor serial (untuk audit/revoke).
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

// CACertPEM mengembalikan sertifikat CA dalam PEM (untuk dikirim ke agent saat enroll).
func (ca *CA) CACertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

// GenerateBundle membuat CA + sertifikat server + sertifikat client lalu
// menuliskannya sebagai berkas PEM ke opt.Dir. Aman dipanggil ulang (overwrite).
func GenerateBundle(opt Options) (CertPaths, error) {
	if opt.ValidFor == 0 {
		opt.ValidFor = 825 * 24 * time.Hour // ~27 bulan, batas umum sertifikat TLS
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
			return paths, fmt.Errorf("tulis %s: %w", w.what, err)
		}
	}
	return paths, nil
}
