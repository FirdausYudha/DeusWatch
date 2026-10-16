package respond

// A generic SSH/CLI responder: block an address by running the commands the operator gives us on
// whatever network device they own.
//
// Why generic rather than a Ruijie driver. The hospital this came from runs full Ruijie at the
// edge, and DeusWatch could reach none of it: the responders were nftables, MikroTik REST and
// CrowdSec, so auto-block, one of the headline capabilities, was inert at that site. The obvious
// answer is a Ruijie responder. It is the wrong one, and the field engineer said why without being
// asked: "switch kita biasanya pakai Ruijie, terus nanti ada perubahan kontrak, ada Aruba." A
// driver per vendor is a driver that expires with the procurement contract.
//
// So the commands are configuration, not code. This is the same bet the SNMP work made and for the
// same reason: there is no standard here, the operator already has the exact command (they
// configure these switches by script today), and shipping a guess about hardware nobody here can
// test against is worse than shipping a blank the operator fills in. It also means the feature
// works the day a site swaps vendors, with no release from us.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHCLIConfig is one network device plus the commands that block and unblock on it.
type SSHCLIConfig struct {
	Address string // host or host:port; port defaults to 22
	User    string
	Pass    string
	// PrivateKey is an optional PEM key used instead of Pass.
	PrivateKey string
	// HostKey pins the device's public key, as the "SHA256:..." fingerprint ssh-keyscan prints.
	HostKey string
	// Insecure skips host-key verification. See dialConfig for why this is not the default.
	Insecure bool

	// BlockCmd and UnblockCmd are command templates. {{ip}} is substituted with the address.
	// Several lines run as one session, so a device needing config mode gets it.
	BlockCmd   string
	UnblockCmd string
	// VerifyCmd is a READ-ONLY command used by the health probe. Empty means the probe only opens
	// a session and closes it, which still proves credentials and reachability.
	VerifyCmd string

	Timeout time.Duration
}

// SSHCLIResponder applies blocks to one device over SSH.
type SSHCLIResponder struct {
	cfg SSHCLIConfig
	// run is the transport, swapped in tests. Returns the device's combined output.
	run func(ctx context.Context, cfg SSHCLIConfig, script string) (string, error)
}

func NewSSHCLIResponder(cfg SSHCLIConfig) *SSHCLIResponder {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	return &SSHCLIResponder{cfg: cfg, run: runOverSSH}
}

func (s *SSHCLIResponder) Name() string { return "ssh-cli(" + hostOf(s.cfg.Address) + ")" }

func (s *SSHCLIResponder) Block(ctx context.Context, ip string, _ time.Duration) error {
	return s.apply(ctx, s.cfg.BlockCmd, ip, "block")
}

func (s *SSHCLIResponder) Unblock(ctx context.Context, ip string) error {
	return s.apply(ctx, s.cfg.UnblockCmd, ip, "unblock")
}

// Verify proves the device is reachable and the credentials work, without changing anything.
func (s *SSHCLIResponder) Verify(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	out, err := s.run(ctx, s.cfg, s.cfg.VerifyCmd)
	if err != nil {
		return fmt.Errorf("ssh-cli %s: %w", hostOf(s.cfg.Address), err)
	}
	if bad := deviceRefusal(out); bad != "" {
		return fmt.Errorf("ssh-cli %s: device refused the check: %s", hostOf(s.cfg.Address), bad)
	}
	return nil
}

func (s *SSHCLIResponder) apply(ctx context.Context, tmpl, ip, what string) error {
	script, err := renderCommand(tmpl, ip)
	if err != nil {
		return fmt.Errorf("ssh-cli %s: %s: %w", hostOf(s.cfg.Address), what, err)
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	out, err := s.run(ctx, s.cfg, script)
	if err != nil {
		return fmt.Errorf("ssh-cli %s: %s %s: %w", hostOf(s.cfg.Address), what, ip, err)
	}
	// A network device almost never exits non-zero. It prints "% Invalid input" and carries on, so
	// trusting the exit status alone reports success for a command the device rejected, and the
	// operator believes an address is blocked when nothing happened.
	if bad := deviceRefusal(out); bad != "" {
		return fmt.Errorf("ssh-cli %s: %s %s rejected by the device: %s", hostOf(s.cfg.Address), what, ip, bad)
	}
	return nil
}

// renderCommand substitutes the address into the template.
//
// The address is re-rendered from the PARSED value, never from the caller's string. This responder
// is the last gate before a command runs with privilege on a network device, and a string that
// reached here as "1.2.3.4; reboot" must not become one. net.ParseIP rejects it, and what is
// substituted is ip.String(), which can only ever hold hex digits, dots, colons and a zone, so no
// template can be made to carry a second command through this function.
func renderCommand(tmpl, ip string) (string, error) {
	t := strings.TrimSpace(tmpl)
	if t == "" {
		return "", fmt.Errorf("no command configured")
	}
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return "", fmt.Errorf("refusing to run a command for %q: not an IP address", ip)
	}
	if !strings.Contains(t, "{{ip}}") {
		// A block command that never mentions the address either does nothing or does it to
		// everything. Both are worse than refusing, and both look like success from here.
		return "", fmt.Errorf("the command must contain {{ip}}, or it does not act on the address")
	}
	return strings.ReplaceAll(t, "{{ip}}", parsed.String()), nil
}

// deviceRefusal looks for the way CLI devices say no: a line of output, with a zero exit status.
// Returns the offending line, or "" when nothing looks like a refusal.
func deviceRefusal(out string) string {
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		low := strings.ToLower(l)
		// "%" opens an error line on IOS-like CLIs, which is what Ruijie, Aruba and Cisco all
		// present. The words cover the rest without matching ordinary banner text.
		if strings.HasPrefix(l, "%") ||
			strings.Contains(low, "invalid input") ||
			strings.Contains(low, "unknown command") ||
			strings.Contains(low, "incomplete command") ||
			strings.Contains(low, "syntax error") ||
			strings.Contains(low, "permission denied") {
			return l
		}
	}
	return ""
}

// hostOf trims credentials and port noise for log and error messages.
func hostOf(addr string) string {
	a := strings.TrimSpace(addr)
	if h, _, err := net.SplitHostPort(a); err == nil {
		return h
	}
	return a
}

// withPort defaults the SSH port.
func withPort(addr string) string {
	a := strings.TrimSpace(addr)
	if _, _, err := net.SplitHostPort(a); err == nil {
		return a
	}
	return net.JoinHostPort(a, "22")
}

// dialConfig builds the SSH client config.
//
// Host-key verification is ON unless the operator explicitly turns it off, and that default is the
// point. An unverified SSH connection to the device that enforces your blocks is a machine-in-the-
// middle away from an attacker who can watch every address you ban and answer as the switch while
// blocking nothing. The deployment this is built for reaches its switches over a management VLAN,
// which is why the opt-out exists at all; it is named Insecure so nobody enables it by accident.
func dialConfig(cfg SSHCLIConfig) (*ssh.ClientConfig, error) {
	var auth []ssh.AuthMethod
	if cfg.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(cfg.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if cfg.Pass != "" {
		auth = append(auth, ssh.Password(cfg.Pass))
		// Many switch CLIs answer password auth as keyboard-interactive instead.
		auth = append(auth, ssh.KeyboardInteractive(
			func(_, _ string, questions []string, _ []bool) ([]string, error) {
				ans := make([]string, len(questions))
				for i := range ans {
					ans[i] = cfg.Pass
				}
				return ans, nil
			}))
	}
	if len(auth) == 0 {
		return nil, fmt.Errorf("no password and no private key configured")
	}

	var hostKey ssh.HostKeyCallback
	switch {
	case cfg.HostKey != "":
		want := strings.TrimSpace(cfg.HostKey)
		hostKey = func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if got := ssh.FingerprintSHA256(key); got != want {
				return fmt.Errorf("host key mismatch: device presented %s, configured %s", got, want)
			}
			return nil
		}
	case cfg.Insecure:
		// #nosec G106 -- opt-in only: the operator ticked "skip host key check" for a device on a
		// management VLAN. The default path above pins the fingerprint.
		hostKey = ssh.InsecureIgnoreHostKey()
	default:
		return nil, fmt.Errorf("no host key fingerprint configured: run `ssh-keyscan -t rsa %s` and paste the SHA256 fingerprint, or tick the insecure option", hostOf(cfg.Address))
	}

	return &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auth,
		HostKeyCallback: hostKey,
		Timeout:         cfg.Timeout,
		Config:          legacyFriendlyAlgorithms(),
	}, nil
}

// legacyFriendlyAlgorithms ADDS the algorithms old switch firmware offers to the library's secure
// defaults. It does not replace them, and the difference is the whole function: a zero ssh.Config
// has nil algorithm lists, so appending to one leaves a client that negotiates ONLY the weak
// algorithms, with every modern one gone. SetDefaults fills the lists first, and the extras go on
// the end where they are reached only when the device offers nothing better.
func legacyFriendlyAlgorithms() ssh.Config {
	var c ssh.Config
	c.SetDefaults()
	c.KeyExchanges = append(c.KeyExchanges, "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha256")
	c.Ciphers = append(c.Ciphers, "aes128-cbc", "aes256-cbc")
	return c
}

// runOverSSH opens one session and feeds it the whole script.
//
// A shell, not one exec per line: a device that needs `configure terminal` before the rule and
// `end` after it has to see those in the same session, and running them as separate commands
// silently drops the rule between them.
func runOverSSH(ctx context.Context, cfg SSHCLIConfig, script string) (string, error) {
	clientCfg, err := dialConfig(cfg)
	if err != nil {
		return "", err
	}
	d := net.Dialer{Timeout: cfg.Timeout}
	conn, err := d.DialContext(ctx, "tcp", withPort(cfg.Address))
	if err != nil {
		return "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	c, chans, reqs, err := ssh.NewClientConn(conn, withPort(cfg.Address), clientCfg)
	if err != nil {
		return "", fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("open session: %w", err)
	}
	defer sess.Close()

	// ssh.Session copies stdout and stderr in SEPARATE goroutines, so pointing both at one
	// bytes.Buffer is a data race: the race detector caught it on the first CI run that executed
	// these tests. A device interleaves its prompt and its error text across both streams, and we
	// judge the result by what it printed, so they must land in one buffer. Hence the lock rather
	// than two buffers.
	out := &syncBuffer{}
	sess.Stdout = out
	sess.Stderr = out
	stdin, err := sess.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("stdin: %w", err)
	}
	if err := sess.Shell(); err != nil {
		return "", fmt.Errorf("shell: %w", err)
	}

	lines := append(scriptLines(script), "exit")
	for _, l := range lines {
		if _, err := fmt.Fprintf(stdin, "%s\n", l); err != nil {
			break // the device closed on us; Wait below reports why
		}
	}
	_ = stdin.Close()

	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-ctx.Done():
		return out.String(), ctx.Err()
	case err := <-done:
		// What the device PRINTED is the verdict, not how the session ended. CLI devices close on
		// `exit` without sending an exit status, and the ones that do send a status use it
		// inconsistently, so both of those are normal here and deviceRefusal reads the output
		// instead. Anything else (a transport failure mid-session) is a real error.
		//
		// This used to key off whether any output had arrived yet, which made the result depend on
		// timing: the same device produced a pass or a failure depending on how fast it answered.
		var missing *ssh.ExitMissingError
		var exitErr *ssh.ExitError
		if err != nil && !errors.As(err, &missing) && !errors.As(err, &exitErr) {
			return out.String(), fmt.Errorf("session: %w", err)
		}
		return out.String(), nil
	}
}

// syncBuffer is a bytes.Buffer that two goroutines may write to at once.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// scriptLines splits a template into the lines to send, dropping blanks and comments.
func scriptLines(script string) []string {
	var out []string
	for _, l := range strings.Split(script, "\n") {
		l = strings.TrimSpace(strings.TrimSuffix(l, "\r"))
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}
