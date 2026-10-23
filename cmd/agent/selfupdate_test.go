package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"deuswatch/internal/signing"
)

// writeKeys generates a keypair, writes the public half where verifyUpdate will look for it, and
// returns the private PEM.
func writeKeys(t *testing.T) (privPEM []byte, pubFile string) {
	t.Helper()
	priv, pub, err := signing.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dir := t.TempDir()
	pubFile = filepath.Join(dir, "update.pub")
	if err := os.WriteFile(pubFile, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	return priv, pubFile
}

func writeArtifact(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "deuswatch-agent.new")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func signFile(t *testing.T, privPEM []byte, path string) string {
	t.Helper()
	priv, err := signing.ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return signing.Sign(priv, content)
}

// TestVerifyUpdateAcceptsAGenuineRelease is the happy path, and the only one where replacing a
// running root process is allowed to proceed on a host that requires signatures.
func TestVerifyUpdateAcceptsAGenuineRelease(t *testing.T) {
	privPEM, pubFile := writeKeys(t)
	t.Setenv("UPDATE_PUBKEY", "")
	t.Setenv("UPDATE_PUBKEY_FILE", pubFile)

	bin := writeArtifact(t, "the real v2.63.0 binary")
	if err := verifyUpdate(bin, signFile(t, privPEM, bin), "v2.63.0"); err != nil {
		t.Fatalf("a genuine signed release was refused: %v", err)
	}
}

// TestVerifyUpdateRefusesATamperedBinary is the whole point: a host holding a trusted key must
// not replace its own executable with bytes that key did not vouch for, whoever served them.
func TestVerifyUpdateRefusesATamperedBinary(t *testing.T) {
	privPEM, pubFile := writeKeys(t)
	t.Setenv("UPDATE_PUBKEY", "")
	t.Setenv("UPDATE_PUBKEY_FILE", pubFile)

	genuine := writeArtifact(t, "the real v2.63.0 binary")
	goodSig := signFile(t, privPEM, genuine)

	// The signature of the real release, served with a different payload. This is exactly what a
	// manager that has been taken over would do.
	malicious := writeArtifact(t, "a binary that opens a reverse shell as root")
	err := verifyUpdate(malicious, goodSig, "v2.63.0")
	if err == nil {
		t.Fatal("a tampered binary was accepted")
	}
	if !strings.Contains(err.Error(), "REFUSED") {
		t.Errorf("the refusal does not say so plainly: %v", err)
	}
	if !strings.Contains(err.Error(), "untouched") {
		t.Errorf("the message does not tell the operator the running agent survived: %v", err)
	}
}

// TestVerifyUpdateRefusesAnUnsignedRelease: a host that requires signatures must not accept an
// update merely because no signature arrived. "Verify if convenient" is not verifying, because
// the attacker picks the circumstances.
func TestVerifyUpdateRefusesAnUnsignedRelease(t *testing.T) {
	_, pubFile := writeKeys(t)
	t.Setenv("UPDATE_PUBKEY", "")
	t.Setenv("UPDATE_PUBKEY_FILE", pubFile)

	bin := writeArtifact(t, "an unsigned binary")
	err := verifyUpdate(bin, "", "v2.63.0")
	if err == nil {
		t.Fatal("an unsigned update was accepted on a host that holds a trusted key")
	}
	if !strings.Contains(err.Error(), "no signature") {
		t.Errorf("the reason is not stated: %v", err)
	}
}

// TestVerifyUpdateRefusesAnotherKey: the attacker generating their own keypair gets nowhere.
func TestVerifyUpdateRefusesAnotherKey(t *testing.T) {
	_, pubFile := writeKeys(t)
	attackerPriv, _, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("UPDATE_PUBKEY", "")
	t.Setenv("UPDATE_PUBKEY_FILE", pubFile)

	bin := writeArtifact(t, "a binary the attacker signed themselves")
	if err := verifyUpdate(bin, signFile(t, attackerPriv, bin), "v2.63.0"); err == nil {
		t.Fatal("a binary signed with a key this host does not trust was accepted")
	}
}

// TestVerifyUpdateWithNoKeyProceeds covers the migration path. Refusing here would brick
// self-update on every agent already deployed the moment this shipped, and an estate that cannot
// be patched is its own security problem. It must proceed, and it must say so.
func TestVerifyUpdateWithNoKeyProceeds(t *testing.T) {
	t.Setenv("UPDATE_PUBKEY", "")
	t.Setenv("UPDATE_PUBKEY_FILE", filepath.Join(t.TempDir(), "absent.pub"))

	bin := writeArtifact(t, "an unsigned binary on a host with no key")
	if err := verifyUpdate(bin, "", "v2.63.0"); err != nil {
		t.Fatalf("an unconfigured host cannot update itself: %v", err)
	}
}

// TestVerifyUpdateRefusesOnABrokenKey: a key that is configured but unusable must NOT degrade to
// "unverified". A typo in the key would otherwise switch this control off on the day somebody set
// it up, which is the worst possible moment for it to be silent.
func TestVerifyUpdateRefusesOnABrokenKey(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "update.pub")
	if err := os.WriteFile(broken, []byte("oops this is not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UPDATE_PUBKEY", "")
	t.Setenv("UPDATE_PUBKEY_FILE", broken)

	bin := writeArtifact(t, "anything")
	err := verifyUpdate(bin, "", "v2.63.0")
	if err == nil {
		t.Fatal("a broken key was treated as no key, silently disabling verification")
	}
	if !strings.Contains(err.Error(), "unusable") {
		t.Errorf("the message does not point at the key: %v", err)
	}
}

// TestUpdatePubKeyFileLocation pins where an installer must put the key, since the installer and
// the two readers of it (this self-updater and the benchmark collector) have to agree without
// any of them reading the others.
func TestUpdatePubKeyFileLocation(t *testing.T) {
	t.Setenv("UPDATE_PUBKEY_FILE", "")
	t.Setenv("CERT_DIR", "")
	if got := signing.DefaultPubKeyFile(); got != filepath.Join("/etc/deuswatch/certs", "update.pub") {
		t.Errorf("default = %q", got)
	}
	t.Setenv("CERT_DIR", "/opt/dw/certs")
	if got := signing.DefaultPubKeyFile(); got != filepath.Join("/opt/dw/certs", "update.pub") {
		t.Errorf("with CERT_DIR = %q", got)
	}
	t.Setenv("UPDATE_PUBKEY_FILE", "/somewhere/else.pub")
	if got := signing.DefaultPubKeyFile(); got != "/somewhere/else.pub" {
		t.Errorf("explicit override = %q", got)
	}
}
