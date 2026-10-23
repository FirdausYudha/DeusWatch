// Package signing verifies that content came from whoever holds the operator's release key,
// rather than merely from whoever answers at the manager's address.
//
// WHY THIS EXISTS. Two paths let the manager put code on an endpoint and have it run as root:
// the agent's self-update, which downloads a binary and replaces the running executable, and a
// pushed CIS benchmark policy, whose `c:` rules are shell commands. Both were authenticated only
// by TLS to the manager's CA, which proves WHO answered, not WHAT they sent. A compromised
// manager therefore owned every endpoint in the estate.
//
// Signing moves the trust from the transport to the content. The operator holds a private key,
// each endpoint holds only the matching PUBLIC key, and the manager becomes a courier that cannot
// forge what it carries. Compromising the manager then yields the ability to withhold updates,
// which is a denial of service and recoverable, rather than the ability to execute code, which is
// not.
//
// Ed25519 rather than RSA or ECDSA-with-choices: one curve, one hash, no parameters to get wrong,
// 32-byte public keys that fit in an environment variable, and it is in the standard library.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// PEM block types. Named rather than generic so a key pasted into the wrong field is rejected by
// its own header instead of failing later as a bad signature.
const (
	privateBlock = "DEUSWATCH UPDATE PRIVATE KEY"
	publicBlock  = "DEUSWATCH UPDATE PUBLIC KEY"
)

// SignatureHeader carries a detached signature of a served artifact, base64 encoded.
//
// It lives in this package, not in the gateway that sets it, because the agent reads it too and
// the agent must not import the gateway: that would pull the NATS bus and the whole ingest path
// into a binary deployed on every endpoint, for the sake of one string.
const SignatureHeader = "X-Deuswatch-Signature"

// ErrNoKey means no trusted public key is configured, so verification cannot be performed. It is
// deliberately distinct from a failed verification: the caller has to be able to tell "I could not
// check this" from "I checked this and it is forged", because the safe response differs.
var ErrNoKey = errors.New("signing: no trusted update key configured")

// ErrBadSignature means the content did not verify against the trusted key.
var ErrBadSignature = errors.New("signing: signature does not match the trusted update key")

// GenerateKey returns a new keypair as PEM blocks. The private key is the operator's to keep; it
// must never reach the manager, because a manager holding it could sign its own payloads and the
// whole mechanism would be decoration.
func GenerateKey() (privPEM, pubPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("signing: generate key: %w", err)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: privateBlock, Bytes: priv})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: publicBlock, Bytes: pub})
	return privPEM, pubPEM, nil
}

// PublicFromPrivate derives the public key from a private one, as raw bytes and as PEM.
//
// An Ed25519 private key is the seed followed by its own public key, so this is extraction rather
// than computation. It exists so a lost update.pub can be recovered from the key that signs, and
// so a signing pipeline can verify its own output without being handed a second file to keep in
// step with the first.
func PublicFromPrivate(priv ed25519.PrivateKey) (ed25519.PublicKey, []byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("signing: private key is %d bytes, expected %d",
			len(priv), ed25519.PrivateKeySize)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("signing: private key does not yield an ed25519 public key")
	}
	return pub, pem.EncodeToMemory(&pem.Block{Type: publicBlock, Bytes: pub}), nil
}

// ParsePrivateKey reads a private key from PEM.
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, errors.New("signing: not a PEM block")
	}
	if blk.Type != privateBlock {
		return nil, fmt.Errorf("signing: expected a %q block, found %q", privateBlock, blk.Type)
	}
	if len(blk.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing: private key is %d bytes, expected %d",
			len(blk.Bytes), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(blk.Bytes), nil
}

// ParsePublicKey reads a public key from either PEM or bare base64 of the 32 raw bytes.
//
// Both forms are accepted because the two places a key is configured differ: a file wants PEM,
// which carries its own type header and survives being opened in an editor, while an environment
// variable or a Docker secret wants one line with no newlines in it.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, ErrNoKey
	}
	if strings.HasPrefix(trimmed, "-----BEGIN") {
		blk, _ := pem.Decode([]byte(trimmed))
		if blk == nil {
			return nil, errors.New("signing: not a valid PEM block")
		}
		if blk.Type != publicBlock {
			return nil, fmt.Errorf("signing: expected a %q block, found %q", publicBlock, blk.Type)
		}
		if len(blk.Bytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("signing: public key is %d bytes, expected %d",
				len(blk.Bytes), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(blk.Bytes), nil
	}
	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("signing: public key is neither PEM nor base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signing: public key is %d bytes, expected %d",
			len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// Sign returns a detached signature over content, base64 encoded so it travels in JSON, in a
// header, or in a `.sig` file beside the thing it signs.
func Sign(priv ed25519.PrivateKey, content []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, content))
}

// Verify checks a base64 detached signature over content.
//
// It returns ErrBadSignature for anything that does not verify, including a signature that is
// not valid base64 or is the wrong length. Those are not separate conditions worth separate
// handling: a caller must refuse the content either way, and reporting them differently would
// tell an attacker probing the endpoint which of their guesses was closer.
func Verify(pub ed25519.PublicKey, content []byte, signature string) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if !ed25519.Verify(pub, content, sig) {
		return ErrBadSignature
	}
	return nil
}

// Verifier holds the trusted public key for an endpoint, or nothing.
type Verifier struct {
	pub ed25519.PublicKey
	// src records where the key came from, so a log line can say which file or variable an
	// operator has to look at.
	src string
}

// Enabled reports whether a trusted key is configured. A caller that refuses unsigned content
// only when verification is possible uses this to tell the two states apart.
func (v *Verifier) Enabled() bool { return v != nil && len(v.pub) == ed25519.PublicKeySize }

// Source names where the key was loaded from.
func (v *Verifier) Source() string {
	if v == nil {
		return ""
	}
	return v.src
}

// Verify checks content against the trusted key, or returns ErrNoKey when there is none.
func (v *Verifier) Verify(content []byte, signature string) error {
	if !v.Enabled() {
		return ErrNoKey
	}
	return Verify(v.pub, content, signature)
}

// LoadVerifier resolves the trusted public key from, in order: the inline value, then the file.
//
// Inline first because it is the explicit per-deployment setting, usually a Docker environment
// variable or a secret, while the file is what the installer writes once and then leaves alone.
// An operator overriding the inline value expects it to win over whatever is on disk.
//
// A key that is PRESENT BUT MALFORMED is an error, not a fallback to "unverified". Treating a
// typo in the key as "signing is off" would silently disable the one control this package exists
// to provide, on the day somebody set it up.
func LoadVerifier(inline, file string) (*Verifier, error) {
	if s := strings.TrimSpace(inline); s != "" {
		pub, err := ParsePublicKey([]byte(s))
		if err != nil {
			return nil, fmt.Errorf("signing: UPDATE_PUBKEY is set but unusable: %w", err)
		}
		return &Verifier{pub: pub, src: "UPDATE_PUBKEY"}, nil
	}
	if file == "" {
		return &Verifier{}, nil
	}
	data, err := os.ReadFile(file) // #nosec G304 -- a deployment-configured path, read by root
	if err != nil {
		if os.IsNotExist(err) {
			return &Verifier{}, nil // no key installed: the caller decides what that means
		}
		return nil, fmt.Errorf("signing: read %s: %w", file, err)
	}
	pub, err := ParsePublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("signing: %s is present but unusable: %w", file, err)
	}
	return &Verifier{pub: pub, src: file}, nil
}

// DefaultPubKeyFile is where the installer leaves the operator's public key on an endpoint.
//
// It sits beside the mTLS material because that directory is already root-owned and already the
// agent's root of trust, so a host that can protect one can protect the other.
//
// It lives HERE rather than in each caller because the self-updater and the benchmark collector
// both need it, in different packages, and two copies that drift mean one path verifies while
// the other quietly does not. That is the worst way for this to fail: half-enforced, with
// nothing saying which half.
func DefaultPubKeyFile() string {
	if p := strings.TrimSpace(os.Getenv("UPDATE_PUBKEY_FILE")); p != "" {
		return p
	}
	dir := os.Getenv("CERT_DIR")
	if dir == "" {
		dir = "/etc/deuswatch/certs"
	}
	return filepath.Join(dir, "update.pub")
}

// ReportArtifactSignatures logs whether the binaries a manager serves carry signatures, once at
// startup.
//
// It exists because of a mismatch that would otherwise surface as a mystery. The container image
// COMPILES the agent binaries it serves, so they arrive unsigned, and signing them at image build
// time would mean shipping the private key into the build, which is the one thing this whole
// mechanism forbids. An operator who installs the public key on their endpoints and then waits
// for an update would see every agent refuse, with the reason only in each endpoint's own log.
//
// So the manager says it first, at the one moment somebody is watching: these are the binaries I
// will serve, and this is whether a host that requires signatures can accept them.
func ReportArtifactSignatures(binDir string) {
	entries, err := os.ReadDir(binDir)
	if err != nil {
		return // no binary directory is a separate concern, already reported by whoever needs it
	}
	var signed, unsigned []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasSuffix(name, ".sig") || !strings.HasPrefix(name, "deuswatch-agent-") {
			continue
		}
		if _, serr := os.Stat(filepath.Join(binDir, name+".sig")); serr == nil {
			signed = append(signed, name)
		} else {
			unsigned = append(unsigned, name)
		}
	}
	if len(signed) == 0 && len(unsigned) == 0 {
		return
	}
	if len(unsigned) == 0 {
		log.Printf("signing: all %d agent binaries in %s carry signatures", len(signed), binDir)
		return
	}
	log.Printf("signing: %d of %d agent binaries in %s have NO signature (%s). "+
		"Agents that hold a trusted release key will REFUSE to self-update from this manager. "+
		"These binaries are compiled into the image, and signing them here would require the "+
		"private key in the build. To serve signed updates, mount the signed release artifacts "+
		"and their .sig files over %s. See docs/signing.md.",
		len(unsigned), len(signed)+len(unsigned), binDir, strings.Join(unsigned, ", "), binDir)
}
