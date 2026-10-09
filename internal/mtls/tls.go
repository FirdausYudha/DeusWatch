package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// ClientIdentity reports the CommonName and expiry of the client certificate at p.
//
// The CN *is* the agent's identity on the wire: the gateway keys the heartbeat, the
// pushed config, the blocklist scope and every ingested log line on it, and it must match
// an enrolled `agents.name` row byte-for-byte. Nothing in the TLS handshake checks that,
// any CA-signed certificate is accepted, so a wrong CN fails silently on the manager
// side. Exposed here so the agent can print what it is presenting at startup, which turns
// "the dashboard says never connected" into a one-line journalctl answer.
func ClientIdentity(p CertPaths) (cn string, notAfter time.Time, err error) {
	pemBytes, err := os.ReadFile(p.ClientCert)
	if err != nil {
		return "", time.Time{}, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", time.Time{}, fmt.Errorf("mtls: no PEM block in %s", p.ClientCert)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("mtls: parse %s: %w", p.ClientCert, err)
	}
	return leaf.Subject.CommonName, leaf.NotAfter, nil
}

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
// the client certificate (full mTLS). There is no plaintext path.
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
// Trust is established by the private, per-deployment CA, NOT by the server's
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
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
		// #nosec G402 -- not unverified: the chain is checked against our private CA in both
		// callbacks below. Only the hostname check is skipped, deliberately.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("mtls: server presented no certificate")
			}
			certs := make([]*x509.Certificate, 0, len(rawCerts))
			for _, raw := range rawCerts {
				c, err := x509.ParseCertificate(raw)
				if err != nil {
					return fmt.Errorf("mtls: parse server certificate: %w", err)
				}
				certs = append(certs, c)
			}
			return verifyChain(certs, pool)
		},
		// VerifyConnection as well, and this is not belt-and-braces. A resumed TLS session sends
		// no certificate message, so VerifyPeerCertificate above is never called for it and the
		// chain check is silently skipped. VerifyConnection runs on every handshake, resumed
		// included, with the peer chain from the resumed state.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("mtls: server presented no certificate")
			}
			return verifyChain(cs.PeerCertificates, pool)
		},
	}, nil
}

// verifyChain checks a server chain against our own CA only. The hostname is deliberately not
// checked: trust here comes from the per-deployment CA, not from which IP the agent dialled.
func verifyChain(certs []*x509.Certificate, pool *x509.CertPool) error {
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter})
	return err
}
