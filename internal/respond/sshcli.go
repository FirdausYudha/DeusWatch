package respond

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strings"
	"text/template"
	"time"

	"golang.org/x/crypto/ssh"
)

// Generic SSH/CLI responder (gap 3 of the hospital field insight).
//
// The hospital's whole network is Ruijie, and DeusWatch could only block through nftables,
// MikroTik's REST API and CrowdSec — so auto-block could not touch their edge at all. Their wider
// complaint was the same shape: "switch kita biasanya pakai Ruijie, terus nanti ada perubahan
// kontrak, ada Aruba. Nah itu sinkronisasi teknologinya."
//
// So this does not implement Ruijie. It implements SSH plus a command template, and the operator
// supplies the commands their device actually takes — the same split that works for the SNMP
// sensors, and for the same reason: a vendor command list I cannot test against real hardware is
// a list of guesses, and a guess that silently does nothing is worse than no feature, because the
// operator believes they are protected.
//
// Templates get {{.IP}}, {{.Seconds}}, {{.Duration}} and {{.Comment}}. For example, on a device
// whose CLI takes an ACL line:
//
//	Block:   configure terminal ; ip access-list extended DEUSWATCH ; deny ip host {{.IP}} any
//	Unblock: configure terminal ; ip access-list extended DEUSWATCH ; no deny ip host {{.IP}} any
//	List:    show ip access-list DEUSWATCH
//	Verify:  show version
//
// SAFETY, and the reason this file is careful rather than short: the IP reaches a command line on
// a network device, and it originates from an attacker-influenced alert. A "source IP" of
// `1.2.3.4; reload` would reboot the hospital's core switch. Every address is therefore parsed and
// RE-RENDERED from the parsed form before substitution — the operator's string never reaches the
// device, only a canonical address does.

// SSHCLIConfig describes one device reachable over SSH.
type SSHCLIConfig struct {
	Address  string // host or host:port
	Username string
	Password string
	// PrivateKey is an optional PEM private key, used in preference to the password.
	PrivateKey string
	// HostKeyFingerprint pins the device's host key, in the SHA256:base64 form ssh-keyscan and
	// OpenSSH print. Empty means unverified, which is only allowed with InsecureSkipHostKey.
	HostKeyFingerprint string
	// InsecureSkipHostKey disables host-key verification. An unauthenticated SSH session to a
	// device that accepts blocking commands is a machine-in-the-middle away from an attacker
	// unblocking themselves, so this is an explicit, documented opt-in and never a default.
	InsecureSkipHostKey bool

	// Command templates. BlockCmd is required; the others are optional and switch off the
	// capability they serve.
	BlockCmd   string
	UnblockCmd string
	// ListCmd and ListPattern power Sync. Without them the responder still blocks and unblocks,
	// it just cannot reconcile after a device reboot.
	ListCmd     string
	ListPattern string
	// VerifyCmd is a READ-ONLY command used to prove the device is reachable and the credentials
	// work. It must not change anything: health code calls it on a timer.
	VerifyCmd string

	Timeout time.Duration
	// Label distinguishes several devices in logs and in the responder's name.
	Label string
}

// SSHCLIResponder blocks by running operator-supplied commands over SSH.
type SSHCLIResponder struct {
	cfg  SSHCLIConfig
	list *regexp.Regexp
	// dial is swappable in tests.
	dial func(ctx context.Context, cfg SSHCLIConfig) (cliSession, error)
}

// cliSession is one connection that can run commands. Narrow so a fake is small.
type cliSession interface {
	Run(ctx context.Context, cmd string) (string, error)
	Close() error
}

// NewSSHCLIResponder builds the responder. An invalid list pattern is an error rather than a
// silently disabled Sync: the operator asked for reconciliation and would otherwise never learn
// it was not happening.
func NewSSHCLIResponder(cfg SSHCLIConfig) (*SSHCLIResponder, error) {
	if strings.TrimSpace(cfg.BlockCmd) == "" {
		return nil, fmt.Errorf("respond: ssh-cli needs a block command")
	}
	if cfg.HostKeyFingerprint == "" && !cfg.InsecureSkipHostKey {
		return nil, fmt.Errorf("respond: ssh-cli needs the device's host key fingerprint, " +
			"or an explicit opt-out; an unverified SSH session to a device that takes blocking " +
			"commands can be intercepted")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	r := &SSHCLIResponder{cfg: cfg, dial: dialSSH}
	if cfg.ListPattern != "" {
		re, err := regexp.Compile(cfg.ListPattern)
		if err != nil {
			return nil, fmt.Errorf("respond: ssh-cli list pattern: %w", err)
		}
		r.list = re
	}
	return r, nil
}

func (r *SSHCLIResponder) Name() string {
	if r.cfg.Label != "" {
		return "ssh-cli(" + r.cfg.Label + ")"
	}
	return "ssh-cli"
}

// cmdVars is everything a command template may substitute. Deliberately a fixed struct: a map
// would let a template reach for a field nobody vetted.
type cmdVars struct {
	IP       string
	Seconds  int
	Duration string
	Comment  string
}

// renderCommand validates the address and fills the template.
//
// The address is parsed and re-rendered, so what reaches the device is a canonical address and
// never the operator's or the alert's original string. This is the whole defence against a
// crafted "IP" carrying a command separator.
func renderCommand(tmpl, rawIP string, d time.Duration) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(rawIP))
	if ip == nil {
		return "", fmt.Errorf("respond: %q is not an IP address, refusing to build a device command", rawIP)
	}
	t, err := template.New("cmd").Option("missingkey=error").Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("respond: command template: %w", err)
	}
	v := cmdVars{
		IP:       ip.String(), // canonical form, not the input
		Seconds:  int(d.Seconds()),
		Duration: "permanent",
		Comment:  "deuswatch",
	}
	if d > 0 {
		v.Duration = d.String()
	}
	var b bytes.Buffer
	if err := t.Execute(&b, v); err != nil {
		return "", fmt.Errorf("respond: command template: %w", err)
	}
	cmd := strings.TrimSpace(b.String())
	if cmd == "" {
		return "", fmt.Errorf("respond: command template produced nothing")
	}
	return cmd, nil
}

// run opens a session, runs one command and closes it.
func (r *SSHCLIResponder) run(ctx context.Context, cmd string) (string, error) {
	sess, err := r.dial(ctx, r.cfg)
	if err != nil {
		return "", fmt.Errorf("respond: %s: %w", r.Name(), err)
	}
	defer sess.Close()
	out, err := sess.Run(ctx, cmd)
	if err != nil {
		return out, fmt.Errorf("respond: %s: %w", r.Name(), err)
	}
	return out, nil
}

func (r *SSHCLIResponder) Block(ctx context.Context, ip string, d time.Duration) error {
	cmd, err := renderCommand(r.cfg.BlockCmd, ip, d)
	if err != nil {
		return err
	}
	_, err = r.run(ctx, cmd)
	return err
}

func (r *SSHCLIResponder) Unblock(ctx context.Context, ip string) error {
	if strings.TrimSpace(r.cfg.UnblockCmd) == "" {
		// Saying so is the point: a deployment that can block but not unblock is a deployment
		// where a mistaken ban has to be undone by hand on the device, and the operator needs to
		// know that before it happens rather than during.
		return fmt.Errorf("respond: %s has no unblock command configured", r.Name())
	}
	cmd, err := renderCommand(r.cfg.UnblockCmd, ip, 0)
	if err != nil {
		return err
	}
	_, err = r.run(ctx, cmd)
	return err
}

// Verify runs the read-only check, so health code can tell "configured" from "working".
func (r *SSHCLIResponder) Verify(ctx context.Context) error {
	cmd := strings.TrimSpace(r.cfg.VerifyCmd)
	if cmd == "" {
		// No command to run, but reaching and authenticating to the device already proves the
		// half that usually fails: the address, the credentials and the host key.
		sess, err := r.dial(ctx, r.cfg)
		if err != nil {
			return fmt.Errorf("respond: %s: %w", r.Name(), err)
		}
		return sess.Close()
	}
	_, err := r.run(ctx, cmd)
	return err
}

// Sync reconciles the device's managed list to `desired`, when the operator configured a list
// command and a pattern to read it with.
func (r *SSHCLIResponder) Sync(ctx context.Context, desired []string) error {
	if strings.TrimSpace(r.cfg.ListCmd) == "" || r.list == nil {
		return nil // reconciliation not configured; Block/Unblock still work
	}
	out, err := r.run(ctx, r.cfg.ListCmd)
	if err != nil {
		return err
	}
	current := parseIPList(out, r.list)

	want := make(map[string]bool, len(desired))
	for _, raw := range desired {
		if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
			want[ip.String()] = true
		}
	}

	var firstErr error
	for ip := range want {
		if !current[ip] {
			if err := r.Block(ctx, ip, 0); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	// Only remove what is no longer wanted. An entry the device has that DeusWatch never added
	// is still removed here, because the operator's list command is what defines "managed" — the
	// documentation says to point it at a DeusWatch-only ACL for exactly this reason.
	for ip := range current {
		if !want[ip] {
			if err := r.Unblock(ctx, ip); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// parseIPList pulls addresses out of CLI output. Only text the pattern matches AND that parses as
// an address is kept: device output is full of version numbers and interface names that look
// enough like addresses to poison a diff.
func parseIPList(out string, re *regexp.Regexp) map[string]bool {
	found := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(out, -1) {
		candidate := m[0]
		if len(m) > 1 && m[1] != "" {
			candidate = m[1] // a capture group wins, so a pattern can anchor on surrounding text
		}
		if ip := net.ParseIP(strings.TrimSpace(candidate)); ip != nil {
			found[ip.String()] = true
		}
	}
	return found
}

// ── real SSH transport ───────────────────────────────────────────────────────

type sshSession struct {
	client *ssh.Client
}

func (s *sshSession) Run(ctx context.Context, cmd string) (string, error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("open session: %w", err)
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()

	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		return stdout.String(), ctx.Err()
	case err := <-done:
		if err != nil {
			// Network gear reports refusals on stderr and then exits non-zero; the message is the
			// difference between "wrong command for this model" and "no privilege".
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = strings.TrimSpace(stdout.String())
			}
			if msg != "" {
				return stdout.String(), fmt.Errorf("%w: %s", err, clipLine(msg, 200))
			}
			return stdout.String(), err
		}
		return stdout.String(), nil
	}
}

func (s *sshSession) Close() error { return s.client.Close() }

func dialSSH(ctx context.Context, cfg SSHCLIConfig) (cliSession, error) {
	auths, err := sshAuths(cfg)
	if err != nil {
		return nil, err
	}
	hostKey, err := hostKeyCallback(cfg)
	if err != nil {
		return nil, err
	}

	addr := cfg.Address
	if !strings.Contains(addr, ":") {
		addr += ":22"
	}

	cc := &ssh.ClientConfig{
		User:            cfg.Username,
		Auth:            auths,
		HostKeyCallback: hostKey,
		Timeout:         cfg.Timeout,
	}

	d := net.Dialer{Timeout: cfg.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to %s: %w", addr, err)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cc)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake with %s: %w", addr, err)
	}
	return &sshSession{client: ssh.NewClient(c, chans, reqs)}, nil
}

func sshAuths(cfg SSHCLIConfig) ([]ssh.AuthMethod, error) {
	var auths []ssh.AuthMethod
	if key := strings.TrimSpace(cfg.PrivateKey); key != "" {
		signer, err := ssh.ParsePrivateKey([]byte(key))
		if err != nil {
			return nil, fmt.Errorf("private key: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if cfg.Password != "" {
		auths = append(auths, ssh.Password(cfg.Password))
		// Several network OSes present password auth as keyboard-interactive instead; without
		// this the same password fails on exactly those devices, for no visible reason.
		auths = append(auths, ssh.KeyboardInteractive(
			func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = cfg.Password
				}
				return answers, nil
			}))
	}
	if len(auths) == 0 {
		return nil, fmt.Errorf("no password or private key configured")
	}
	return auths, nil
}

// hostKeyCallback pins the device's key, or explicitly opts out.
func hostKeyCallback(cfg SSHCLIConfig) (ssh.HostKeyCallback, error) {
	if cfg.InsecureSkipHostKey {
		// #nosec G106 -- opt-in only, refused by NewSSHCLIResponder unless the operator set it,
		// and documented as unsafe. Default is a pinned fingerprint.
		return ssh.InsecureIgnoreHostKey(), nil
	}
	want := strings.TrimSpace(cfg.HostKeyFingerprint)
	if want == "" {
		return nil, fmt.Errorf("no host key fingerprint configured")
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		got := ssh.FingerprintSHA256(key)
		if subtleEqual(got, want) {
			return nil
		}
		return fmt.Errorf("host key mismatch: device presented %s, expected %s "+
			"(the device was replaced or reinstalled, or this is not the device)", got, want)
	}, nil
}

// subtleEqual compares fingerprints, tolerating a missing "SHA256:" prefix and base64 padding,
// because operators paste these from several tools that print them slightly differently.
func subtleEqual(got, want string) bool {
	norm := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimPrefix(s, "SHA256:")
		s = strings.TrimRight(s, "=")
		return s
	}
	g, w := norm(got), norm(want)
	if g == w {
		return true
	}
	// Also accept a fingerprint pasted as standard base64 where the other is raw.
	if db, err := base64.StdEncoding.DecodeString(w + strings.Repeat("=", (4-len(w)%4)%4)); err == nil {
		if gb, err2 := base64.StdEncoding.DecodeString(g + strings.Repeat("=", (4-len(g)%4)%4)); err2 == nil {
			return bytes.Equal(db, gb)
		}
	}
	return false
}

func clipLine(s string, n int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
