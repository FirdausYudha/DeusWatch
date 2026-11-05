package agent

import "testing"

// TestDefaultSourcesFor pins the per-OS default source sets the manager seeds into a newly-enrolled
// agent. It runs anywhere (no build tags, no host dependency), so the manager-seeding contract is
// covered even on a CI box whose own GOOS differs from the agents it enrolls.
func TestDefaultSourcesFor(t *testing.T) {
	linux := DefaultSourcesFor("linux")
	// The whole point of this release: a fresh Linux agent watches SSH out of the box.
	if !hasSource(linux, "sshd", "/var/log/auth.log") {
		t.Fatalf("linux defaults must include the sshd/auth.log source; got %+v", linux)
	}
	if !hasSource(linux, "web", "/var/log/nginx/access.log") {
		t.Fatalf("linux defaults must include the web access log; got %+v", linux)
	}
	// CIS benchmarks run daily by default so the scorecard's benchmark indicator stays live.
	if !hasSource(linux, "sca", "") {
		t.Fatalf("linux defaults must include the sca source; got %+v", linux)
	}
	if len(linux) != 5 {
		t.Fatalf("expected 5 linux default sources (sshd/syslog/firewall/web/sca), got %d", len(linux))
	}

	win := DefaultSourcesFor("windows")
	if !hasSource(win, "windows-security", "Security") {
		t.Fatalf("windows defaults must include the Security event log; got %+v", win)
	}
	if !hasSource(win, "sca", "") {
		t.Fatalf("windows defaults must include the sca source; got %+v", win)
	}

	// An unknown OS must yield nil rather than a wrong guess, the agent then has no seeded config
	// and its own runtime defaults apply.
	if got := DefaultSourcesFor("plan9"); got != nil {
		t.Fatalf("unknown OS must return nil, got %+v", got)
	}
	if got := DefaultSourcesFor(""); got != nil {
		t.Fatalf("empty OS must return nil, got %+v", got)
	}
}

func hasSource(srcs []Source, dataset, path string) bool {
	for _, s := range srcs {
		if s.Dataset == dataset && s.Path == path {
			return true
		}
	}
	return false
}
