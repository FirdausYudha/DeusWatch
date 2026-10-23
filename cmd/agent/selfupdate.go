package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"deuswatch/internal/agent"
	"deuswatch/internal/signing"
)

// performSelfUpdate downloads the binary the manager pointed at, atomically replaces the
// currently-running executable, and returns nil. The caller is responsible for exiting so
// systemd (or the Windows Service Manager, or a supervisor) can restart the process, the
// new binary picks up on the next start.
//
// URL from the directive may contain the literal token "{arch}", which is substituted for
// the running GOARCH ("amd64" / "arm64") before the fetch. The manager builds one binary
// per (os, arch) pair so a fleet with mixed CPUs still works from a single button click.
//
// TLS trust: since the update URL is served by the manager's API port (plain HTTP unless
// the operator has a TLS reverse proxy), we accept either HTTP or HTTPS. When HTTPS, we
// pin against the CA the agent already trusts for gateway mTLS, so a compromised
// intermediate can't hijack the update flow.
func performSelfUpdate(ctx context.Context, shipper *agent.Shipper, directive *agent.UpdateDirective) error {
	if directive == nil {
		return fmt.Errorf("nil directive")
	}
	url := strings.ReplaceAll(directive.URL, "{arch}", runtime.GOARCH)
	if runtime.GOOS == "windows" && !strings.Contains(url, ".exe") {
		// Windows binaries carry the .exe suffix on disk on the manager. Best-effort append
		// so an operator's manually-crafted directive URL still works.
		url += ".exe"
	}

	// Client selection:
	//   - Relative URL (v2.14.1+): agent's own mTLS gateway client. No extra network path,
	//     agent already trusts the gateway, and the gateway image bundles the binary at
	//     /agents thanks to the Dockerfile fix.
	//   - Absolute URL (pre-v2.14.1 servers, or a hand-crafted directive): pin to the CA
	//     the agent already trusts; the installer curls the binary the same way.
	var client *http.Client
	if strings.HasPrefix(url, "/") {
		client = shipper.GatewayClient()
		url = strings.TrimRight(shipper.GatewayURL(), "/") + url
	} else {
		client = &http.Client{Timeout: 5 * time.Minute}
		if strings.HasPrefix(url, "https://") {
			if pool, err := loadCACertPool(); err == nil {
				client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
			}
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}

	// Where does the current binary live? os.Executable is the reliable way, installer paths
	// vary (Linux /usr/local/bin/deuswatch-agent, Windows Program Files\DeusWatch\agent.exe).
	current, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate self: %w", err)
	}
	current, _ = filepath.EvalSymlinks(current) // resolve any symlink so the mv lands on the real file
	dir := filepath.Dir(current)
	tmp, err := os.CreateTemp(dir, "deuswatch-agent.new-*")
	if err != nil {
		return fmt.Errorf("create tmp in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup on any failure path, an orphaned .new-* file is harmless but ugly.
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()
	// 64MB rather than 200. A statically linked Go agent is about 7MB, so this is eight times
	// the headroom it needs, and the whole download has to be read back into memory below to be
	// verified. A 200MB "agent binary" is already wrong, and allocating 200MB as root to find
	// that out is the wrong way to discover it.
	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, 64<<20)); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tmp: %w", err)
	}

	// VERIFY BEFORE THE SWAP. Up to here nothing distinguishes the real manager from anyone who
	// has taken it over: TLS pinning proves which host answered, not what it sent, and this
	// function's next act is to replace the running executable of a root process. The signature
	// is what moves that trust from the transport to the content.
	if err := verifyUpdate(tmpPath, resp.Header.Get(signing.SignatureHeader), directive.Version); err != nil {
		return err
	}
	// #nosec G302 -- this is the agent binary about to replace the running one. It has to be
	// executable, and 0600 would brick the update.
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return fmt.Errorf("chmod tmp: %w", err)
	}

	// Atomic swap. On POSIX rename(2) is atomic within a single filesystem, which is why we
	// created the temp file in the same directory as the current binary above. On Windows
	// os.Rename over an EXISTING file is not permitted while it's running, so we rename the
	// current binary aside first, then rename the new one into place, the just-moved old
	// binary can then be deleted once the process exits.
	if runtime.GOOS == "windows" {
		aside := current + ".old"
		_ = os.Remove(aside) // stale from a previous update, remove or Rename will fail
		if err := os.Rename(current, aside); err != nil {
			return fmt.Errorf("rename current aside: %w", err)
		}
		if err := os.Rename(tmpPath, current); err != nil {
			// Best-effort rollback, swap the old binary back into place before returning.
			_ = os.Rename(aside, current)
			return fmt.Errorf("rename new into place: %w", err)
		}
	} else {
		if err := os.Rename(tmpPath, current); err != nil {
			return fmt.Errorf("rename: %w", err)
		}
	}
	success = true
	return nil
}

// loadCACertPool reads the CA the agent already trusts for gateway mTLS (installer places
// it next to the client cert), so HTTPS downloads pin to the same manager the agent enrolled
// with. Empty pool on error → falls back to the system trust store.
func loadCACertPool() (*x509.CertPool, error) {
	certDir := os.Getenv("CERT_DIR")
	if certDir == "" {
		certDir = "/etc/deuswatch/certs"
	}
	// #nosec G703 -- CERT_DIR is a deployment setting and the filename is a constant.
	pem, err := os.ReadFile(filepath.Join(certDir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no valid PEM in ca.pem")
	}
	return pool, nil
}

// verifyUpdate checks a downloaded binary against the endpoint's trusted release key.
//
// The two outcomes that matter:
//
//   - A trusted key IS installed. The binary must verify, full stop. An unsigned or wrongly
//     signed download is refused and the running agent keeps running, which is the safe failure:
//     an agent one version behind still collects, still alerts, still responds.
//   - NO trusted key is installed. The update proceeds, because refusing would brick self-update
//     for every agent already deployed the moment this shipped, and an estate that cannot be
//     patched is its own security problem. It says so on every update, at WARNING volume, naming
//     the variable that fixes it.
//
// There is no third mode where a key is installed and a signature is merely preferred. "Verify if
// convenient" is the same as not verifying, because the attacker chooses the circumstances.
func verifyUpdate(path, signature, version string) error {
	v, err := signing.LoadVerifier(os.Getenv("UPDATE_PUBKEY"), updatePubKeyFile())
	if err != nil {
		// A key that is configured but unreadable is NOT treated as "no key". Falling back to
		// unverified on a typo would switch off this control on the day somebody set it up.
		return fmt.Errorf("self-update refused, the trusted release key is unusable: %w", err)
	}
	if !v.Enabled() {
		log.Printf("agent: WARNING self-update %s is NOT verified: no trusted release key on this host. "+
			"Anyone who controls the manager can replace this binary and run code as root. "+
			"Install the operator's public key (UPDATE_PUBKEY, or %s) to require signatures.",
			version, updatePubKeyFile())
		return nil
	}
	if signature == "" {
		return fmt.Errorf("self-update refused: this host requires signed releases (key from %s) "+
			"but the manager served %s with no signature", v.Source(), version)
	}
	content, err := os.ReadFile(path) // #nosec G304 -- our own temp file, written just above
	if err != nil {
		return fmt.Errorf("self-update refused, cannot re-read the download to verify it: %w", err)
	}
	if err := v.Verify(content, signature); err != nil {
		return fmt.Errorf("self-update REFUSED: %s did not verify against the trusted release key "+
			"from %s. The running agent is untouched. Either the release was not signed with that "+
			"key, or the download was altered: %w", version, v.Source(), err)
	}
	log.Printf("agent: self-update %s verified against the trusted release key (%s)", version, v.Source())
	return nil
}

// updatePubKeyFile is where the installer leaves the operator's public key. It sits beside the
// mTLS material because that directory is already root-owned and already the agent's root of
// trust, so an endpoint that can protect one can protect the other.
func updatePubKeyFile() string {
	if p := strings.TrimSpace(os.Getenv("UPDATE_PUBKEY_FILE")); p != "" {
		return p
	}
	dir := os.Getenv("CERT_DIR")
	if dir == "" {
		dir = "/etc/deuswatch/certs"
	}
	return filepath.Join(dir, "update.pub")
}
