package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// caPool loads the CA certificate from a PEM file into a verification pool.
func caPool(caCertPath string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("mtls: failed to parse CA from %s", caCertPath)
	}
	return pool, nil
}

// ServerConfig returns a *tls.Config for the server side that REQUIRES and verifies
// the client certificate (full mTLS) — there is no plaintext path.
func ServerConfig(p CertPaths) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(p.ServerCert, p.ServerKey)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
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

// ClientConfig returns a *tls.Config for the client side that presents the client
// certificate and verifies the server against the same CA.
//
// Trust is established by the private, per-deployment CA — NOT by the server's
// hostname/IP. So we verify the server cert's chain against our CA but skip the default
// SAN name check; otherwise every manager IP/hostname an agent might dial would have to
// be baked into the server cert (the cross-host "x509: certificate is valid for … not
// <ip>" pitfall). The gateway still RequireAndVerifyClientCert, so both sides are
// mutually authenticated by the CA.
func ClientConfig(p CertPaths) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(p.ClientCert, p.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}
	pool, err := caPool(p.CACert)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            pool,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // we run our own chain check below (no hostname check)
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("mtls: server presented no certificate")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("mtls: parse server certificate: %w", err)
			}
			inter := x509.NewCertPool()
			for _, raw := range rawCerts[1:] {
				if c, err := x509.ParseCertificate(raw); err == nil {
					inter.AddCert(c)
				}
			}
			_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter})
			return err
		},
	}, nil
}
