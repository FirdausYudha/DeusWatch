package respond

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// renderCommand is the last gate before a command runs with privilege on a switch, so it is tested
// as an injection boundary rather than as string formatting. Everything here is a string that must
// never reach a device.
func TestRenderCommandRefusesInjection(t *testing.T) {
	const tmpl = "configure terminal\nip access-list deny {{ip}}\nend"

	for _, bad := range []string{
		"1.2.3.4; reboot",
		"1.2.3.4 && write erase",
		"1.2.3.4\nno ip access-list",
		"1.2.3.4`reboot`",
		"1.2.3.4$(reboot)",
		"1.2.3.4 | sh",
		"$(curl evil)",
		"", "   ",
		"not-an-ip",
		"1.2.3.4.5.6",
		"999.999.999.999",
	} {
		if got, err := renderCommand(tmpl, bad); err == nil {
			t.Errorf("rendered a command for %q: %q", bad, got)
		}
	}
}

func TestRenderCommand(t *testing.T) {
	got, err := renderCommand("ip access-list deny {{ip}}", " 45.134.26.9 ")
	if err != nil {
		t.Fatalf("a valid address must render: %v", err)
	}
	if got != "ip access-list deny 45.134.26.9" {
		t.Errorf("got %q", got)
	}

	// Rendered from the PARSED address, not the caller's text, so a non-canonical form is
	// normalised on the way to the device rather than passed through.
	if got, _ := renderCommand("deny {{ip}}", "2001:0db8:0000::0001"); got != "deny 2001:db8::1" {
		t.Errorf("IPv6 should be canonicalised, got %q", got)
	}
	// Every occurrence, since a device usually needs the address in both directions.
	if got, _ := renderCommand("in {{ip}}\nout {{ip}}", "10.0.0.1"); got != "in 10.0.0.1\nout 10.0.0.1" {
		t.Errorf("got %q", got)
	}

	// A command that never names the address either does nothing or does it to everything, and
	// both look like success from here.
	if _, err := renderCommand("write memory", "1.2.3.4"); err == nil {
		t.Error("a template without {{ip}} must be refused")
	}
	if _, err := renderCommand("", "1.2.3.4"); err == nil {
		t.Error("an empty template must be refused")
	}
}

// A switch answers a bad command with text and a zero exit status, so trusting the exit status
// reports success for a rule the device never accepted.
func TestDeviceRefusal(t *testing.T) {
	for _, out := range []string{
		"% Invalid input detected at '^' marker.",
		"switch# ip access-list deny 1.2.3.4\n% Unknown command\nswitch#",
		"Syntax error: unexpected token",
		"Permission denied.",
		"% Incomplete command.",
	} {
		if deviceRefusal(out) == "" {
			t.Errorf("missed a refusal in: %q", out)
		}
	}
	for _, out := range []string{
		"",
		"switch# configure terminal\nswitch(config)# ip access-list deny 1.2.3.4\nswitch(config)# end\nswitch#",
		"Building configuration...\nOK",
	} {
		if bad := deviceRefusal(out); bad != "" {
			t.Errorf("false refusal %q in ordinary output: %q", bad, out)
		}
	}
}

func TestWithPortAndHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.1": "10.0.0.1:22", "10.0.0.1:2222": "10.0.0.1:2222", " sw1.local ": "sw1.local:22",
	} {
		if got := withPort(in); got != want {
			t.Errorf("withPort(%q) = %q, want %q", in, got, want)
		}
	}
	if got := hostOf("10.0.0.1:2222"); got != "10.0.0.1" {
		t.Errorf("hostOf = %q", got)
	}
}

// The library's secure defaults must survive the compatibility additions. A zero ssh.Config has
// nil lists, so appending to one leaves a client that negotiates ONLY the weak algorithms, which
// is the opposite of the intent and invisible until someone reads a packet capture.
func TestLegacyAlgorithmsExtendRatherThanReplace(t *testing.T) {
	var def ssh.Config
	def.SetDefaults()
	got := legacyFriendlyAlgorithms()

	if len(got.KeyExchanges) <= len(def.KeyExchanges) {
		t.Fatalf("key exchanges shrank: %d vs the default %d", len(got.KeyExchanges), len(def.KeyExchanges))
	}
	for _, want := range def.KeyExchanges {
		if !containsStr(got.KeyExchanges, want) {
			t.Errorf("dropped the default key exchange %q", want)
		}
	}
	for _, want := range def.Ciphers {
		if !containsStr(got.Ciphers, want) {
			t.Errorf("dropped the default cipher %q", want)
		}
	}
	// And the old algorithms come last, so a modern device never negotiates down to them.
	if got.Ciphers[len(got.Ciphers)-1] != "aes256-cbc" {
		t.Errorf("the legacy ciphers should be last, got %v", got.Ciphers)
	}
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// Host-key verification is the difference between talking to the switch and talking to whoever is
// between you and it, so the default with nothing configured must be a refusal, not a connection.
func TestDialConfigRequiresAHostKey(t *testing.T) {
	base := SSHCLIConfig{Address: "10.0.0.1", User: "admin", Pass: "x"}
	if _, err := dialConfig(base); err == nil {
		t.Error("a device with no fingerprint and no opt-out must be refused")
	} else if !strings.Contains(err.Error(), "ssh-keyscan") {
		t.Errorf("the refusal should say how to get the fingerprint: %v", err)
	}

	withKey := base
	withKey.HostKey = "SHA256:abc"
	if _, err := dialConfig(withKey); err != nil {
		t.Errorf("a pinned fingerprint must be accepted: %v", err)
	}

	insecure := base
	insecure.Insecure = true
	if _, err := dialConfig(insecure); err != nil {
		t.Errorf("the explicit opt-out must be accepted: %v", err)
	}

	noAuth := SSHCLIConfig{Address: "10.0.0.1", User: "admin", HostKey: "SHA256:abc"}
	if _, err := dialConfig(noAuth); err == nil {
		t.Error("no password and no key must be refused")
	}
}

// ── a real SSH server, in process ────────────────────────────────────────────────────────────
//
// The transport is not mocked, because the thing worth proving is that the exact lines the
// operator configured arrive at the device in ONE session. A device needing `configure terminal`
// before the rule and `end` after it sees nothing useful if those run as separate commands, and a
// fake transport would happily report that they did.

type fakeDevice struct {
	addr   string
	signer ssh.Signer
	mu     sync.Mutex
	got    []string // lines received
	reply  string   // what the device prints back
}

func startFakeDevice(t *testing.T, reply string) *fakeDevice {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeDevice{signer: signer, reply: reply}

	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
		return nil, nil
	}}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d.addr = ln.Addr().String()
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			go d.serve(nConn, cfg)
		}
	}()
	return d
}

func (d *fakeDevice) serve(nConn net.Conn, cfg *ssh.ServerConfig) {
	defer nConn.Close()
	_, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			return
		}
		go func() {
			for r := range chReqs {
				// "shell" is what runOverSSH asks for.
				_ = r.Reply(r.Type == "shell" || r.Type == "pty-req", nil)
			}
		}()
		go func(ch ssh.Channel) {
			defer ch.Close()
			if d.reply != "" {
				_, _ = io.WriteString(ch, d.reply+"\n")
			}
			buf := make([]byte, 4096)
			var acc strings.Builder
			for {
				n, err := ch.Read(buf)
				if n > 0 {
					acc.Write(buf[:n])
				}
				if err != nil {
					break
				}
			}
			d.mu.Lock()
			for _, l := range strings.Split(acc.String(), "\n") {
				if l = strings.TrimSpace(l); l != "" {
					d.got = append(d.got, l)
				}
			}
			d.mu.Unlock()
		}(ch)
	}
}

func (d *fakeDevice) lines() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, len(d.got))
	copy(out, d.got)
	return out
}

func (d *fakeDevice) responder(cmd string) *SSHCLIResponder {
	return NewSSHCLIResponder(SSHCLIConfig{
		Address: d.addr, User: "admin", Pass: "secret",
		HostKey:  ssh.FingerprintSHA256(d.signer.PublicKey()),
		BlockCmd: cmd, Timeout: 10 * time.Second,
	})
}

func TestBlockSendsEveryLineInOneSession(t *testing.T) {
	d := startFakeDevice(t, "switch#")
	r := d.responder("configure terminal\nip access-list extended DW\n deny ip host {{ip}} any\nend\nwrite memory")

	if err := r.Block(context.Background(), "45.134.26.9", time.Hour); err != nil {
		t.Fatalf("Block: %v", err)
	}
	// Give the server goroutine a moment to drain the channel after the client closes it.
	deadline := time.Now().Add(3 * time.Second)
	for len(d.lines()) < 6 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	got := strings.Join(d.lines(), "|")
	for _, want := range []string{
		"configure terminal", "ip access-list extended DW",
		"deny ip host 45.134.26.9 any", "end", "write memory", "exit",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the device never received %q\n  received: %s", want, got)
		}
	}
}

// The device accepted nothing but exited zero. Reporting success here is how an operator comes to
// believe an address is blocked when the rule was never installed.
func TestBlockFailsWhenTheDeviceRejectsTheCommand(t *testing.T) {
	d := startFakeDevice(t, "% Invalid input detected at '^' marker.")
	err := d.responder("deny {{ip}}").Block(context.Background(), "45.134.26.9", time.Hour)
	if err == nil {
		t.Fatal("a device refusal must be an error, not a silent success")
	}
	if !strings.Contains(err.Error(), "Invalid input") {
		t.Errorf("the error should quote what the device said: %v", err)
	}
}

func TestVerifyProvesReachability(t *testing.T) {
	d := startFakeDevice(t, "switch#")
	r := NewSSHCLIResponder(SSHCLIConfig{
		Address: d.addr, User: "admin", Pass: "secret",
		HostKey: ssh.FingerprintSHA256(d.signer.PublicKey()),
		// Read-only: the probe runs on a timer and must never change the device.
		VerifyCmd: "show version", Timeout: 10 * time.Second,
	})
	if err := r.Verify(context.Background()); err != nil {
		t.Errorf("Verify against a healthy device: %v", err)
	}

	bad := NewSSHCLIResponder(SSHCLIConfig{
		Address: "127.0.0.1:1", User: "admin", Pass: "x", Insecure: true, Timeout: 2 * time.Second,
	})
	if err := bad.Verify(context.Background()); err == nil {
		t.Error("an unreachable device must fail Verify")
	}
}

// The pin is the control. A device presenting a different key is a different device.
func TestHostKeyMismatchIsRefused(t *testing.T) {
	d := startFakeDevice(t, "switch#")
	r := NewSSHCLIResponder(SSHCLIConfig{
		Address: d.addr, User: "admin", Pass: "secret",
		HostKey:  "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		BlockCmd: "deny {{ip}}", Timeout: 5 * time.Second,
	})
	err := r.Block(context.Background(), "1.2.3.4", time.Hour)
	if err == nil {
		t.Fatal("a mismatched host key must refuse the connection")
	}
	if !strings.Contains(err.Error(), "host key mismatch") {
		t.Errorf("unexpected error: %v", err)
	}
}

var _ = fmt.Sprintf // keep fmt imported for future cases
