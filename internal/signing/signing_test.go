package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func keypair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, string) {
	t.Helper()
	privPEM, pubPEM, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	priv, err := ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	pub, err := ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	return priv, pub, string(pubPEM)
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	priv, pub, _ := keypair(t)
	content := []byte("the agent binary bytes, pretend")

	sig := Sign(priv, content)
	if err := Verify(pub, content, sig); err != nil {
		t.Fatalf("a signature we just made does not verify: %v", err)
	}
}

// TestVerifyRejectsTampering is the property the whole package exists for: a byte changed in
// transit must not verify, whoever delivered it.
func TestVerifyRejectsTampering(t *testing.T) {
	priv, pub, _ := keypair(t)
	content := []byte("the agent binary bytes, pretend")
	sig := Sign(priv, content)

	for _, tc := range []struct {
		name    string
		content []byte
	}{
		{"one byte changed", []byte("the agent binary bytes, pretend!")},
		{"truncated", content[:len(content)-1]},
		{"empty", []byte{}},
		{"entirely different", []byte("a malicious binary")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Verify(pub, tc.content, sig); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("tampered content verified (err=%v)", err)
			}
		})
	}
}

// TestVerifyRejectsAnotherKey: a compromised manager generating its own keypair and signing with
// it must get nowhere, which is the entire threat this addresses.
func TestVerifyRejectsAnotherKey(t *testing.T) {
	_, trustedPub, _ := keypair(t)
	attackerPriv, _, _ := keypair(t)

	content := []byte("a binary the attacker wants root to run")
	sig := Sign(attackerPriv, content)

	if err := Verify(trustedPub, content, sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("content signed by a different key verified (err=%v)", err)
	}
}

func TestVerifyRejectsMalformedSignatures(t *testing.T) {
	_, pub, _ := keypair(t)
	content := []byte("x")
	for _, sig := range []string{
		"", "not base64 at all!!", base64.StdEncoding.EncodeToString([]byte("too short")),
		base64.StdEncoding.EncodeToString(make([]byte, 65)), // one byte over
		base64.StdEncoding.EncodeToString(make([]byte, 63)), // one byte under
	} {
		if err := Verify(pub, content, sig); !errors.Is(err, ErrBadSignature) {
			t.Errorf("signature %q was accepted (err=%v)", sig, err)
		}
	}
}

// TestPublicKeyAcceptsBothForms: a file wants PEM, an environment variable wants one line. Both
// are configured in practice, so both have to parse.
func TestPublicKeyAcceptsBothForms(t *testing.T) {
	priv, pub, pubPEM := keypair(t)
	bare := base64.StdEncoding.EncodeToString(pub)

	for name, form := range map[string]string{
		"PEM":                 pubPEM,
		"PEM with whitespace": "\n  " + pubPEM + "\n",
		"bare base64":         bare,
		"base64 padded":       "  " + bare + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParsePublicKey([]byte(form))
			if err != nil {
				t.Fatalf("%v", err)
			}
			sig := Sign(priv, []byte("content"))
			if err := Verify(got, []byte("content"), sig); err != nil {
				t.Fatalf("key parsed but does not verify: %v", err)
			}
		})
	}
}

func TestPublicKeyRejectsNonsense(t *testing.T) {
	privPEM, _, _ := GenerateKey()
	for name, in := range map[string]string{
		"a private key pasted into the public field": string(privPEM),
		"half a PEM block":                           "-----BEGIN DEUSWATCH UPDATE PUBLIC KEY-----\n",
		"base64 of the wrong length":                 base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"random text":                                "hello",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePublicKey([]byte(in)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// Empty is reported as ErrNoKey, not as a parse failure: "nobody configured one" and
	// "somebody configured a broken one" need different handling by the caller.
	if _, err := ParsePublicKey(nil); !errors.Is(err, ErrNoKey) {
		t.Errorf("empty key returned %v, want ErrNoKey", err)
	}
}

// TestPrivateKeyRejectsPublic guards the easy operator mistake of swapping the two files; the
// block headers are what catch it.
func TestPrivateKeyRejectsPublic(t *testing.T) {
	_, pubPEM, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivateKey(pubPEM); err == nil {
		t.Fatal("a public key was accepted as a private key")
	} else if !strings.Contains(err.Error(), "PUBLIC") {
		t.Errorf("error does not name the mix-up: %v", err)
	}
}

func TestLoadVerifier(t *testing.T) {
	_, _, pubPEM := keypair(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "update.pub")
	if err := os.WriteFile(keyFile, []byte(pubPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("from a file", func(t *testing.T) {
		v, err := LoadVerifier("", keyFile)
		if err != nil || !v.Enabled() {
			t.Fatalf("v=%+v err=%v", v, err)
		}
		if v.Source() != keyFile {
			t.Errorf("source = %q, want the file path", v.Source())
		}
	})

	t.Run("inline wins over the file", func(t *testing.T) {
		// A different key inline must be the one used, so an operator overriding the installed
		// key gets what they asked for rather than silently keeping the old one.
		_, other, _ := keypair(t)
		v, err := LoadVerifier(base64.StdEncoding.EncodeToString(other), keyFile)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Verify([]byte("x"), "irrelevant"); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("expected the inline key to be in use, got %v", err)
		}
		if v.Source() != "UPDATE_PUBKEY" {
			t.Errorf("source = %q, want UPDATE_PUBKEY", v.Source())
		}
	})

	t.Run("nothing configured is not an error", func(t *testing.T) {
		v, err := LoadVerifier("", filepath.Join(dir, "absent.pub"))
		if err != nil {
			t.Fatalf("a missing key file is an error: %v", err)
		}
		if v.Enabled() {
			t.Fatal("verifier reports enabled with no key")
		}
		if err := v.Verify([]byte("x"), "y"); !errors.Is(err, ErrNoKey) {
			t.Errorf("Verify returned %v, want ErrNoKey", err)
		}
	})

	// A MALFORMED key is an error rather than a quiet fallback to unverified. A typo in the key
	// must not silently switch off the control on the day somebody configures it.
	t.Run("a broken key is an error, not unverified", func(t *testing.T) {
		broken := filepath.Join(dir, "broken.pub")
		if err := os.WriteFile(broken, []byte("this is not a key"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadVerifier("", broken); err == nil {
			t.Fatal("a malformed key file was accepted")
		}
		if _, err := LoadVerifier("not-a-key", keyFile); err == nil {
			t.Fatal("a malformed inline key was accepted")
		}
	})

	t.Run("verifier accepts a real signature", func(t *testing.T) {
		priv, _, pem2 := keypair(t)
		f := filepath.Join(dir, "k2.pub")
		if err := os.WriteFile(f, []byte(pem2), 0o600); err != nil {
			t.Fatal(err)
		}
		v, err := LoadVerifier("", f)
		if err != nil {
			t.Fatal(err)
		}
		content := []byte("policy yaml")
		if err := v.Verify(content, Sign(priv, content)); err != nil {
			t.Fatalf("round trip through the verifier failed: %v", err)
		}
	})
}
