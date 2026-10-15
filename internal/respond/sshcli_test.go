package respond

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// THE test for this file. The address reaching a device's command line comes from an alert, so it
// is attacker-influenced: a "source IP" carrying a command separator would run that command on the
// hospital's core switch.
func TestRenderCommandRefusesAnythingThatIsNotAnAddress(t *testing.T) {
	tmpl := "deny ip host {{.IP}} any"
	for _, bad := range []string{
		"1.2.3.4; reload",
		"1.2.3.4 && write erase",
		"1.2.3.4\nreload",
		"1.2.3.4 | sh",
		"$(reload)",
		"`reload`",
		"1.2.3.4/24", // a CIDR is not an address; the template expects a host
		"",
		"   ",
		"example.com",
	} {
		if got, err := renderCommand(tmpl, bad, 0); err == nil {
			t.Errorf("%q was accepted and produced %q", bad, got)
		}
	}
}

// What reaches the device is re-rendered from the parsed address, never the input string.
func TestRenderCommandCanonicalisesTheAddress(t *testing.T) {
	got, err := renderCommand("deny {{.IP}}", "  2001:0db8:0000:0000:0000:0000:0000:0001  ", 0)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if got != "deny 2001:db8::1" {
		t.Fatalf("address should be re-rendered canonically, got %q", got)
	}
}

func TestRenderCommandSubstitutions(t *testing.T) {
	got, err := renderCommand(
		"block {{.IP}} for {{.Seconds}}s ({{.Duration}}) note {{.Comment}}",
		"10.0.0.9", 10*time.Minute)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	want := "block 10.0.0.9 for 600s (10m0s) note deuswatch"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	// A permanent ban has to read as permanent, not as "0s", or the operator reading the device
	// config sees a ban that looks like it already expired.
	perm, err := renderCommand("block {{.IP}} {{.Duration}}", "10.0.0.9", 0)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.HasSuffix(perm, "permanent") {
		t.Fatalf("a permanent ban should say so, got %q", perm)
	}
}

// A template reaching for a field nobody vetted must fail loudly, not render an empty string into
// a device command.
func TestRenderCommandRejectsUnknownField(t *testing.T) {
	if _, err := renderCommand("deny {{.Password}}", "10.0.0.9", 0); err == nil {
		t.Fatal("a template referencing an unknown field should fail")
	}
}

// An unauthenticated SSH session to a device that accepts blocking commands is a
// machine-in-the-middle away from an attacker unblocking themselves.
func TestConstructorRequiresHostKeyOrExplicitOptOut(t *testing.T) {
	_, err := NewSSHCLIResponder(SSHCLIConfig{Address: "10.0.0.1", BlockCmd: "deny {{.IP}}"})
	if err == nil {
		t.Fatal("a responder with no host key and no opt-out must be refused")
	}
	if _, err := NewSSHCLIResponder(SSHCLIConfig{
		Address: "10.0.0.1", BlockCmd: "deny {{.IP}}", InsecureSkipHostKey: true,
	}); err != nil {
		t.Fatalf("an explicit opt-out should be accepted: %v", err)
	}
	if _, err := NewSSHCLIResponder(SSHCLIConfig{
		Address: "10.0.0.1", BlockCmd: "deny {{.IP}}", HostKeyFingerprint: "SHA256:abc",
	}); err != nil {
		t.Fatalf("a pinned fingerprint should be accepted: %v", err)
	}
}

func TestConstructorRequiresABlockCommand(t *testing.T) {
	if _, err := NewSSHCLIResponder(SSHCLIConfig{Address: "10.0.0.1", InsecureSkipHostKey: true}); err == nil {
		t.Fatal("a responder that cannot block is not a responder")
	}
}

// A bad list pattern must be an error, not a silently disabled Sync: the operator asked for
// reconciliation and would otherwise never learn it was not happening.
func TestConstructorRejectsABadListPattern(t *testing.T) {
	_, err := NewSSHCLIResponder(SSHCLIConfig{
		Address: "10.0.0.1", BlockCmd: "x {{.IP}}", InsecureSkipHostKey: true,
		ListCmd: "show acl", ListPattern: "([unclosed",
	})
	if err == nil {
		t.Fatal("an invalid list pattern should fail construction")
	}
}

// ── fake session ─────────────────────────────────────────────────────────────

type fakeSession struct {
	mu   sync.Mutex
	ran  []string
	out  map[string]string
	fail map[string]bool
}

func (f *fakeSession) Run(_ context.Context, cmd string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ran = append(f.ran, cmd)
	if f.fail[cmd] {
		return "", errors.New("device refused")
	}
	return f.out[cmd], nil
}
func (f *fakeSession) Close() error { return nil }

func withFake(t *testing.T, cfg SSHCLIConfig, f *fakeSession) *SSHCLIResponder {
	t.Helper()
	cfg.InsecureSkipHostKey = true
	r, err := NewSSHCLIResponder(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	r.dial = func(context.Context, SSHCLIConfig) (cliSession, error) { return f, nil }
	return r
}

// A deployment that can block but not unblock leaves a mistaken ban to be undone by hand on the
// device. The operator needs to know that before it happens.
func TestUnblockWithoutACommandSaysSo(t *testing.T) {
	f := &fakeSession{out: map[string]string{}}
	r := withFake(t, SSHCLIConfig{BlockCmd: "deny {{.IP}}"}, f)

	err := r.Unblock(context.Background(), "10.0.0.9")
	if err == nil || !strings.Contains(err.Error(), "no unblock command") {
		t.Fatalf("expected a clear refusal, got %v", err)
	}
	if len(f.ran) != 0 {
		t.Errorf("nothing should have been sent to the device, got %v", f.ran)
	}
}

// Device output is full of version numbers and interface names that look enough like addresses to
// poison a diff.
func TestParseIPList(t *testing.T) {
	out := `Extended IP access list DEUSWATCH
    10 deny ip host 10.0.0.9 any
    20 deny ip host 203.0.113.7 any
  Software version 12.4.1.3
  Interface Gi0/1 description uplink`
	re := regexp.MustCompile(`deny ip host (\S+) any`)
	got := parseIPList(out, re)

	if len(got) != 2 || !got["10.0.0.9"] || !got["203.0.113.7"] {
		t.Fatalf("expected exactly the two denied addresses, got %v", got)
	}
	// The version number matches nothing because the capture group anchors on surrounding text.
	if got["12.4.1.3"] {
		t.Error("a version number was mistaken for a blocked address")
	}
}

func TestSyncAddsAndRemoves(t *testing.T) {
	listCmd := "show ip access-list DEUSWATCH"
	f := &fakeSession{out: map[string]string{
		listCmd: "deny ip host 10.0.0.9 any\ndeny ip host 10.0.0.50 any\n",
	}}
	r := withFake(t, SSHCLIConfig{
		BlockCmd:    "add {{.IP}}",
		UnblockCmd:  "remove {{.IP}}",
		ListCmd:     listCmd,
		ListPattern: `deny ip host (\S+) any`,
	}, f)

	// Want 10.0.0.9 (already there) and 10.0.0.77 (missing); 10.0.0.50 is stale.
	if err := r.Sync(context.Background(), []string{"10.0.0.9", "10.0.0.77"}); err != nil {
		t.Fatalf("sync: %v", err)
	}

	ran := strings.Join(f.ran, "\n")
	if !strings.Contains(ran, "add 10.0.0.77") {
		t.Errorf("the missing address should have been added: %v", f.ran)
	}
	if !strings.Contains(ran, "remove 10.0.0.50") {
		t.Errorf("the stale address should have been removed: %v", f.ran)
	}
	if strings.Contains(ran, "add 10.0.0.9") {
		t.Errorf("an address already on the device must not be re-added: %v", f.ran)
	}
}

// Without a list command the responder still blocks; it just cannot reconcile. Sync must be a
// no-op rather than an error, or every sync cycle logs a failure for a working deployment.
func TestSyncWithoutAListCommandIsANoOp(t *testing.T) {
	f := &fakeSession{out: map[string]string{}}
	r := withFake(t, SSHCLIConfig{BlockCmd: "add {{.IP}}"}, f)
	if err := r.Sync(context.Background(), []string{"10.0.0.9"}); err != nil {
		t.Fatalf("sync without a list command should be a no-op, got %v", err)
	}
	if len(f.ran) != 0 {
		t.Errorf("nothing should have run: %v", f.ran)
	}
}

// Verify must prove reachability without changing anything.
func TestVerifyRunsTheReadOnlyCommand(t *testing.T) {
	f := &fakeSession{out: map[string]string{"show version": "RGOS 11.4"}}
	r := withFake(t, SSHCLIConfig{BlockCmd: "add {{.IP}}", VerifyCmd: "show version"}, f)
	if err := r.Verify(context.Background()); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(f.ran) != 1 || f.ran[0] != "show version" {
		t.Fatalf("verify should run exactly the read-only command, got %v", f.ran)
	}
}

func TestVerifyReportsADeviceThatRefuses(t *testing.T) {
	f := &fakeSession{out: map[string]string{}, fail: map[string]bool{"show version": true}}
	r := withFake(t, SSHCLIConfig{BlockCmd: "add {{.IP}}", VerifyCmd: "show version"}, f)
	if err := r.Verify(context.Background()); err == nil {
		t.Fatal("a refused verify command must surface as an error")
	}
}

// ── a real in-process SSH server ─────────────────────────────────────────────

// testSSHServer accepts one password login and records the exec'd command.
type testSSHServer struct {
	addr        string
	fingerprint string
	mu          sync.Mutex
	commands    []string
	ln          net.Listener
}

func startSSHServer(t *testing.T) *testSSHServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == "s3cret" {
				return nil, nil
			}
			return nil, errors.New("bad password")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &testSSHServer{
		addr:        ln.Addr().String(),
		fingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
		ln:          ln,
	}
	go s.serve(cfg)
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *testSSHServer) serve(cfg *ssh.ServerConfig) {
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(nc, cfg)
	}
}

func (s *testSSHServer) handle(nc net.Conn, cfg *ssh.ServerConfig) {
	defer nc.Close()
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			return
		}
		go func() {
			defer ch.Close()
			for req := range chReqs {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				// "exec" payload: 4-byte length then the command.
				var payload struct{ Command string }
				_ = ssh.Unmarshal(req.Payload, &payload)
				s.mu.Lock()
				s.commands = append(s.commands, payload.Command)
				s.mu.Unlock()
				_ = req.Reply(true, nil)
				_, _ = ch.Write([]byte("ok\n"))
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				return
			}
		}()
	}
}

func (s *testSSHServer) ran() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}

func TestBlockOverRealSSH(t *testing.T) {
	srv := startSSHServer(t)
	r, err := NewSSHCLIResponder(SSHCLIConfig{
		Address:            srv.addr,
		Username:           "admin",
		Password:           "s3cret",
		HostKeyFingerprint: srv.fingerprint,
		BlockCmd:           "configure terminal ; ip access-list extended DEUSWATCH ; deny ip host {{.IP}} any",
		Timeout:            5 * time.Second,
		Label:              "sw-core",
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := r.Block(context.Background(), "203.0.113.7", time.Hour); err != nil {
		t.Fatalf("block: %v", err)
	}

	got := srv.ran()
	if len(got) != 1 {
		t.Fatalf("expected one command, got %v", got)
	}
	want := "configure terminal ; ip access-list extended DEUSWATCH ; deny ip host 203.0.113.7 any"
	if got[0] != want {
		t.Fatalf("the device received %q, want %q", got[0], want)
	}
	if r.Name() != "ssh-cli(sw-core)" {
		t.Errorf("the label should identify the device in logs, got %q", r.Name())
	}
}

// The device was replaced, or this is not the device. Either way, do not hand it blocking commands.
func TestHostKeyMismatchRefusesToConnect(t *testing.T) {
	srv := startSSHServer(t)
	r, err := NewSSHCLIResponder(SSHCLIConfig{
		Address:            srv.addr,
		Username:           "admin",
		Password:           "s3cret",
		HostKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), // a different key
		BlockCmd:           "deny ip host {{.IP}} any",
		Timeout:            5 * time.Second,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	err = r.Block(context.Background(), "203.0.113.7", 0)
	if err == nil {
		t.Fatal("a host key mismatch must refuse the connection")
	}
	if !strings.Contains(err.Error(), "host key mismatch") {
		t.Fatalf("the error should name the cause, got %v", err)
	}
	if len(srv.ran()) != 0 {
		t.Error("no command may reach a device that failed host key verification")
	}
}

func TestWrongPasswordIsReported(t *testing.T) {
	srv := startSSHServer(t)
	r, err := NewSSHCLIResponder(SSHCLIConfig{
		Address: srv.addr, Username: "admin", Password: "wrong",
		HostKeyFingerprint: srv.fingerprint,
		BlockCmd:           "deny {{.IP}}", Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := r.Block(context.Background(), "203.0.113.7", 0); err == nil {
		t.Fatal("bad credentials must surface as an error")
	}
}

// Operators paste fingerprints from several tools that print them slightly differently.
func TestFingerprintComparisonToleratesFormatting(t *testing.T) {
	srv := startSSHServer(t)
	bare := strings.TrimPrefix(srv.fingerprint, "SHA256:")
	for _, form := range []string{srv.fingerprint, bare, bare + "=", "  " + srv.fingerprint + "  "} {
		r, err := NewSSHCLIResponder(SSHCLIConfig{
			Address: srv.addr, Username: "admin", Password: "s3cret",
			HostKeyFingerprint: form, BlockCmd: "deny {{.IP}}", Timeout: 5 * time.Second,
		})
		if err != nil {
			t.Fatalf("new(%q): %v", form, err)
		}
		if err := r.Block(context.Background(), "203.0.113.7", 0); err != nil {
			t.Errorf("fingerprint %q should have been accepted: %v", form, err)
		}
	}
}
