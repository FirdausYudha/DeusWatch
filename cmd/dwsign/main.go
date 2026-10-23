// Command dwsign generates the operator's release keypair and signs release artifacts.
//
// It is a SEPARATE binary from the manager and the agent on purpose. The private key it uses must
// never reach the manager: a manager that can sign its own payloads makes the signature
// decoration rather than a control, and the manager is precisely the component whose compromise
// this exists to survive.
//
//	# once, on a machine you trust, and keep the private key off the manager
//	dwsign -gen -out ./keys
//
//	# install keys/update.pub on each endpoint, then sign each release artifact
//	dwsign -key ./keys/update.key -in dist/deuswatch-agent-linux-amd64
//	dwsign -key ./keys/update.key -in policies/cis_debian10.yml
//
//	# verify what you just produced, before anybody depends on it
//	dwsign -verify -pub ./keys/update.pub -in dist/deuswatch-agent-linux-amd64
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"deuswatch/internal/signing"
)

func main() {
	gen := flag.Bool("gen", false, "generate a new keypair into -out")
	verify := flag.Bool("verify", false, "verify -in against its signature using -pub")
	out := flag.String("out", ".", "directory for -gen output")
	keyPath := flag.String("key", "", "private key PEM, for signing")
	pubPath := flag.String("pub", "", "public key PEM, for -verify")
	in := flag.String("in", "", "file to sign or verify")
	sigPath := flag.String("sig", "", "signature file (default: <in>.sig)")
	force := flag.Bool("force", false, "overwrite existing keys on -gen")
	flag.Parse()

	var err error
	switch {
	case *gen:
		err = generate(*out, *force)
	case *verify:
		err = doVerify(*pubPath, *in, *sigPath)
	case *in != "":
		err = sign(*keyPath, *in, *sigPath)
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dwsign:", err)
		os.Exit(1)
	}
}

func generate(dir string, force bool) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	privFile := filepath.Join(dir, "update.key")
	pubFile := filepath.Join(dir, "update.pub")

	// Refuse to overwrite without -force. Regenerating silently would orphan every endpoint
	// already carrying the old public key, and the symptom would be every agent refusing every
	// update at once with no obvious cause.
	if !force {
		for _, f := range []string{privFile, pubFile} {
			if _, err := os.Stat(f); err == nil {
				return fmt.Errorf("%s already exists; pass -force only if you accept that every "+
					"endpoint holding the old public key will reject signatures made with the new one", f)
			}
		}
	}

	privPEM, pubPEM, err := signing.GenerateKey()
	if err != nil {
		return err
	}
	// 0600: this file is the authority to run code as root on every endpoint that trusts it.
	if err := os.WriteFile(privFile, privPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(pubFile, pubPEM, 0o644); err != nil {
		return err
	}
	fmt.Printf("private key: %s  (keep this OFF the manager, back it up, 0600)\n", privFile)
	fmt.Printf("public key:  %s  (install on each endpoint, or set UPDATE_PUBKEY)\n", pubFile)
	fmt.Println()
	fmt.Println("UPDATE_PUBKEY one-liner for a container deployment:")
	fmt.Println(" ", oneLine(pubPEM))
	return nil
}

// oneLine renders a PEM public key as the bare base64 an environment variable wants, because a
// PEM block with newlines in it does not survive a .env file or a compose value.
func oneLine(pubPEM []byte) string {
	pub, err := signing.ParsePublicKey(pubPEM)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(pub)
}

func sign(keyPath, in, sigPath string) error {
	if keyPath == "" {
		return fmt.Errorf("-key is required to sign")
	}
	keyPEM, err := os.ReadFile(keyPath) // #nosec G304 -- operator-supplied path
	if err != nil {
		return err
	}
	priv, err := signing.ParsePrivateKey(keyPEM)
	if err != nil {
		return err
	}
	content, err := os.ReadFile(in) // #nosec G304 -- operator-supplied path
	if err != nil {
		return err
	}
	sig := signing.Sign(priv, content)
	if sigPath == "" {
		sigPath = in + ".sig"
	}
	if err := os.WriteFile(sigPath, []byte(sig+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("%s -> %s\n", in, sigPath)
	return nil
}

func doVerify(pubPath, in, sigPath string) error {
	if pubPath == "" || in == "" {
		return fmt.Errorf("-pub and -in are required to verify")
	}
	pubPEM, err := os.ReadFile(pubPath) // #nosec G304 -- operator-supplied path
	if err != nil {
		return err
	}
	pub, err := signing.ParsePublicKey(pubPEM)
	if err != nil {
		return err
	}
	content, err := os.ReadFile(in) // #nosec G304 -- operator-supplied path
	if err != nil {
		return err
	}
	if sigPath == "" {
		sigPath = in + ".sig"
	}
	sig, err := os.ReadFile(sigPath) // #nosec G304 -- operator-supplied path
	if err != nil {
		return err
	}
	if err := signing.Verify(pub, content, string(sig)); err != nil {
		return fmt.Errorf("%s: %w", in, err)
	}
	fmt.Printf("%s: signature OK\n", in)
	return nil
}
