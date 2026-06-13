package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// caPool memuat sertifikat CA dari berkas PEM menjadi pool verifikasi.
func caPool(caCertPath string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("mtls: gagal mem-parse CA dari %s", caCertPath)
	}
	return pool, nil
}

// ServerConfig mengembalikan *tls.Config untuk sisi server yang MEWAJIBKAN dan
// memverifikasi sertifikat client (mTLS penuh) — tidak ada jalur plaintext.
func ServerConfig(p CertPaths) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(p.ServerCert, p.ServerKey)
	if err != nil {
		return nil, fmt.Errorf("muat sertifikat server: %w", err)
	}
	pool, err := caPool(p.CACert)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientConfig mengembalikan *tls.Config untuk sisi client yang menyodorkan
// sertifikat client dan memverifikasi server terhadap CA yang sama.
func ClientConfig(p CertPaths) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(p.ClientCert, p.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("muat sertifikat client: %w", err)
	}
	pool, err := caPool(p.CACert)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
