package enroll

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"deuswatch/internal/mtls"
)

func dsn() string {
	if d := os.Getenv("STORE_DSN"); d != "" {
		return d
	}
	return "postgres://deuswatch:deuswatch_dev@localhost:5432/deuswatch?sslmode=disable"
}

func TestEnrollFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}

	// Temporary CA.
	dir := t.TempDir()
	if _, err := mtls.GenerateBundle(mtls.Options{Dir: dir, ValidFor: time.Hour}); err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}
	ca, err := mtls.LoadCA(dir)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	s := NewStore(pool, ca)
	name := fmt.Sprintf("test-agent-%d", time.Now().UnixNano())
	defer pool.Exec(ctx, `DELETE FROM agents WHERE name LIKE 'test-agent-%'`)
	defer pool.Exec(ctx, `DELETE FROM agent_enroll_tokens WHERE created_by='test'`)

	raw, _, err := s.CreateToken(ctx, "test")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	bundle, err := s.Enroll(ctx, raw, name, "linux")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// The client certificate must be CA-signed & CN = agent name.
	cb, _ := pem.Decode([]byte(bundle.ClientCert))
	if cb == nil {
		t.Fatal("client cert is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(bundle.CACert)) {
		t.Fatal("CA cert did not load")
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("cert did not verify against the CA: %v", err)
	}
	if cert.Subject.CommonName != name {
		t.Fatalf("cert CN = %q, want %q", cert.Subject.CommonName, name)
	}

	// Single-use token: a second enroll with the same token must fail.
	if _, err := s.Enroll(ctx, raw, name+"-2", "linux"); !errors.Is(err, ErrToken) {
		t.Fatalf("token must be single-use, got: %v", err)
	}

	// Re-enrolling a name that is taken by an ACTIVE agent must fail.
	raw2, _, err := s.CreateToken(ctx, "test")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if _, err := s.Enroll(ctx, raw2, name, "linux"); err == nil {
		t.Fatal("enrolling an active agent's name must fail")
	}

	// Revocation.
	if rev, _ := s.IsRevoked(ctx, name, ""); rev {
		t.Fatal("agent not yet revoked, IsRevoked must be false")
	}
	if err := s.Revoke(ctx, bundle.AgentID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if rev, _ := s.IsRevoked(ctx, name, ""); !rev {
		t.Fatal("after Revoke, IsRevoked must be true")
	}

	// A REVOKED name may be re-used: enrollment takes over the row (same id,
	// un-revoked, new certificate) and the superseded cert's serial stays dead.
	oldSerial := cert.SerialNumber.String()
	raw3, _, err := s.CreateToken(ctx, "test")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	bundle2, err := s.Enroll(ctx, raw3, name, "linux")
	if err != nil {
		t.Fatalf("re-enroll of a revoked name must succeed: %v", err)
	}
	if bundle2.AgentID != bundle.AgentID {
		t.Fatalf("re-enroll must take over the existing row (id %s), got new id %s", bundle.AgentID, bundle2.AgentID)
	}
	cb2, _ := pem.Decode([]byte(bundle2.ClientCert))
	cert2, err := x509.ParseCertificate(cb2.Bytes)
	if err != nil {
		t.Fatalf("parse re-enrolled cert: %v", err)
	}
	newSerial := cert2.SerialNumber.String()
	if newSerial == oldSerial {
		t.Fatal("re-enrollment must issue a NEW certificate serial")
	}
	if rev, _ := s.IsRevoked(ctx, name, newSerial); rev {
		t.Fatal("the re-enrolled agent's new cert must be accepted")
	}
	if rev, _ := s.IsRevoked(ctx, name, oldSerial); !rev {
		t.Fatal("the superseded (revoked-era) cert must STAY rejected after the name is re-used")
	}
	t.Logf("OK: enroll -> unique cert CN=%s; single-use token; revoke; name re-use with serial pinning", name)
}
