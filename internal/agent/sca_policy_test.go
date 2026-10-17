package agent

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// fakeSystem is a scripted host.
type fakeSystem struct {
	files    map[string]string
	dirs     map[string][]string
	commands map[string]string
	procs    map[string]bool
	registry map[string]string // "key\x00value" -> data
	// ranCommands records what was executed, so a test can prove a rule did not shell out when
	// it should not have.
	ranCommands []string
}

func (f *fakeSystem) FileContent(p string) (string, bool)  { c, ok := f.files[p]; return c, ok }
func (f *fakeSystem) DirEntries(d string) ([]string, bool) { n, ok := f.dirs[d]; return n, ok }
func (f *fakeSystem) RunCommand(c string) (string, bool) {
	f.ranCommands = append(f.ranCommands, c)
	out, ok := f.commands[c]
	return out, ok
}
func (f *fakeSystem) ProcessRunning(n string) bool { return f.procs[n] }
func (f *fakeSystem) RegistryValue(k, v string) (string, bool) {
	d, ok := f.registry[k+"\x00"+v]
	return d, ok
}

func TestEvalRuleFile(t *testing.T) {
	sys := &fakeSystem{files: map[string]string{
		"/etc/debian_version":  "10.13\n",
		"/etc/ssh/sshd_config": "Port 22\nPermitRootLogin no\nX11Forwarding yes\n",
		"/etc/empty":           "",
		"/etc/login.defs":      "PASS_MAX_DAYS 90\nUMASK 027\n",
	}}
	for _, tc := range []struct {
		rule string
		want bool
	}{
		{"f:/etc/debian_version", true},
		{"f:/etc/redhat-release", false},
		// An EMPTY file exists. A naive implementation that tested the content for emptiness
		// would answer false here and silently fail every check that only asks for presence.
		{"f:/etc/empty", true},
		{"not f:/etc/redhat-release", true},
		{"not f:/etc/debian_version", false},
		{"f:/etc/ssh/sshd_config -> r:^PermitRootLogin\\s+no", true},
		{"f:/etc/ssh/sshd_config -> r:^PermitRootLogin\\s+yes", false},
		{"f:/etc/ssh/sshd_config -> !r:^PermitRootLogin\\s+yes", true},
		{"f:/etc/ssh/sshd_config -> PermitRootLogin no", true},
		{"f:/etc/ssh/sshd_config -> Protocol 1", false},
		// A content test against a file that does not exist is false, never an error: an absent
		// file is an ordinary answer for a hardening check.
		{"f:/etc/nope -> r:anything", false},
		{"f:/etc/login.defs -> n:PASS_MAX_DAYS\\s*(\\d+) compare <= 90", true},
		{"f:/etc/login.defs -> n:PASS_MAX_DAYS\\s*(\\d+) compare < 90", false},
		{"f:/etc/login.defs -> n:PASS_MAX_DAYS\\s*(\\d+) compare >= 365", false},
		{"f:/etc/login.defs -> r:^UMASK && !r:UMASK\\s+000", true},
		{"f:/etc/login.defs -> r:^UMASK && r:UMASK\\s+000", false},
	} {
		got, err := evalRule(tc.rule, sys)
		if err != nil {
			t.Errorf("%s: %v", tc.rule, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s = %v, want %v", tc.rule, got, tc.want)
		}
	}
}

func TestEvalRuleCommandAndProcess(t *testing.T) {
	sys := &fakeSystem{
		commands: map[string]string{
			"sysctl net.ipv4.ip_forward": "net.ipv4.ip_forward = 0\n",
			"modprobe -n -v cramfs":      "install /bin/true\n",
			"lsmod":                      "ext4 123456 1\n",
			"grep ^x /etc/passwd":        "", // exits non-zero, finds nothing: still evaluable
		},
		procs: map[string]bool{"sshd": true},
	}
	for _, tc := range []struct {
		rule string
		want bool
	}{
		{"c:sysctl net.ipv4.ip_forward -> r:= 0", true},
		{"c:sysctl net.ipv4.ip_forward -> r:= 1", false},
		{"c:modprobe -n -v cramfs -> r:install /bin/true", true},
		{"not c:lsmod -> r:cramfs", true},
		{"not c:lsmod -> r:ext4", false},
		// A command that produced NO output ran fine. Treating empty output as unevaluable would
		// skip every "grep finds nothing, which is the hardened state" check, and CIS is full of
		// them.
		{"c:grep ^x /etc/passwd -> r:root", false},
		{"not c:grep ^x /etc/passwd -> r:root", true},
		// A command that could not be run at all is false, not an error.
		{"c:no-such-binary -> r:anything", false},
		{"p:sshd", true},
		{"p:telnetd", false},
		{"not p:telnetd", true},
	} {
		got, err := evalRule(tc.rule, sys)
		if err != nil {
			t.Errorf("%s: %v", tc.rule, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s = %v, want %v", tc.rule, got, tc.want)
		}
	}
}

func TestEvalRuleDirectory(t *testing.T) {
	sys := &fakeSystem{
		dirs: map[string][]string{
			"/etc/cron.d":     {"e2scrub_all", "logrotate"},
			"/etc/rc3.d":      {"S01sysstat", "K02telnet"},
			"/etc/modprobe.d": {"CIS.conf", "blacklist.conf"},
		},
		files: map[string]string{
			"/etc/modprobe.d/CIS.conf":       "install cramfs /bin/true\n",
			"/etc/modprobe.d/blacklist.conf": "blacklist pcspkr\n",
		},
	}
	for _, tc := range []struct {
		rule string
		want bool
	}{
		{"d:/etc/cron.d", true},
		{"d:/etc/nope", false},
		{"d:/etc/rc3.d -> r:^S", true},
		{"d:/etc/rc3.d -> r:^Z", false},
		// Three-part form: a file in the directory whose CONTENT matches.
		{"d:/etc/modprobe.d -> r:\\.conf$ -> r:install cramfs", true},
		{"d:/etc/modprobe.d -> r:\\.conf$ -> r:install squashfs", false},
		{"not d:/etc/modprobe.d -> r:\\.conf$ -> r:install squashfs", true},
	} {
		got, err := evalRule(tc.rule, sys)
		if err != nil {
			t.Errorf("%s: %v", tc.rule, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s = %v, want %v", tc.rule, got, tc.want)
		}
	}
}

func TestEvalRuleRegistry(t *testing.T) {
	sys := &fakeSystem{registry: map[string]string{
		`HKLM\System\CurrentControlSet\Control\Lsa` + "\x00" + "LimitBlankPasswordUse": "1",
		`HKLM\Software\Policies` + "\x00" + "":                                         "",
	}}
	for _, tc := range []struct {
		rule string
		want bool
	}{
		{`r:HKLM\Software\Policies`, true},
		{`r:HKLM\Software\Missing`, false},
		{`r:HKLM\System\CurrentControlSet\Control\Lsa -> LimitBlankPasswordUse -> 1`, true},
		{`r:HKLM\System\CurrentControlSet\Control\Lsa -> LimitBlankPasswordUse -> 0`, false},
		{`r:HKLM\System\CurrentControlSet\Control\Lsa -> MissingValue -> 1`, false},
	} {
		got, err := evalRule(tc.rule, sys)
		if err != nil {
			t.Errorf("%s: %v", tc.rule, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s = %v, want %v", tc.rule, got, tc.want)
		}
	}
}

func TestEvalConditions(t *testing.T) {
	sys := &fakeSystem{files: map[string]string{"/yes": "x"}}
	yes, no := "f:/yes", "f:/no"
	for _, tc := range []struct {
		cond  string
		rules []string
		want  bool
	}{
		{"all", []string{yes, yes}, true},
		{"all", []string{yes, no}, false},
		{"any", []string{no, yes}, true},
		{"any", []string{no, no}, false},
		{"none", []string{no, no}, true},
		{"none", []string{no, yes}, false},
		// An absent condition means all, which is the format's default.
		{"", []string{yes, yes}, true},
		{"", []string{yes, no}, false},
	} {
		got, err := evalCondition(tc.cond, tc.rules, sys)
		if err != nil {
			t.Errorf("condition %q: %v", tc.cond, err)
			continue
		}
		if got != tc.want {
			t.Errorf("condition %q over %v = %v, want %v", tc.cond, tc.rules, got, tc.want)
		}
	}
	if _, err := evalCondition("sometimes", []string{yes}, sys); err == nil {
		t.Error("an unknown condition was accepted")
	}
	if _, err := evalCondition("all", nil, sys); err == nil {
		t.Error("a check with no rules was accepted")
	}
}

// TestUnparseableRuleIsNotAFailure is the safety property of the whole engine. A failed CIS check
// tells an operator to go change something on a production host. Reporting a failure because this
// engine could not parse a rule, or because Wazuh's regex dialect differs from RE2 on that
// pattern, would send somebody to make a real change for no reason. It must say
// not_applicable and name the gap.
func TestUnparseableRuleIsNotAFailure(t *testing.T) {
	sys := &fakeSystem{files: map[string]string{"/etc/thing": "content"}}
	p := &SCAPolicy{}
	p.Policy.ID = "test"
	p.Checks = []SCACheck{
		{ID: 1, Title: "unsupported rule type", Condition: "all", Rules: []string{"x:something"}},
		{ID: 2, Title: "no prefix at all", Condition: "all", Rules: []string{"just text"}},
		// Lookahead: valid in Wazuh's OS_Regex and in PCRE, refused by RE2. A named group would
		// NOT do as the example here, Go has accepted (?<name>...) since 1.22.
		{ID: 3, Title: "a pattern RE2 rejects", Condition: "all",
			Rules: []string{`f:/etc/thing -> r:(?=content)`}},
		{ID: 4, Title: "a rule that genuinely fails", Condition: "all", Rules: []string{"f:/etc/absent"}},
	}
	got := p.Evaluate(sys)
	if len(got) != 4 {
		t.Fatalf("got %d results, want 4", len(got))
	}
	for _, r := range got[:3] {
		if r.Result != SCANotApplicable {
			t.Errorf("check %d (%s) = %q, want not_applicable", r.CheckID, r.Title, r.Result)
		}
		if r.Reason == "" {
			t.Errorf("check %d reported not_applicable with no reason", r.CheckID)
		}
	}
	if got[3].Result != SCAFailed {
		t.Errorf("a genuinely failing check reported %q, want failed", got[3].Result)
	}
}

// TestPolicyAppliesGatesTheWholeFile: a Debian policy on a RHEL box must be SKIPPED, not reported
// as several hundred failures. That distinction is the difference between a compliance score and
// a wall of noise.
func TestPolicyApplies(t *testing.T) {
	debian := &SCAPolicy{}
	debian.Requirements.Condition = "any"
	debian.Requirements.Rules = []string{"f:/etc/debian_version"}

	if !debian.Applies(&fakeSystem{files: map[string]string{"/etc/debian_version": "10"}}) {
		t.Error("the Debian policy does not apply to a Debian host")
	}
	if debian.Applies(&fakeSystem{files: map[string]string{"/etc/redhat-release": "9"}}) {
		t.Error("the Debian policy applies to a RHEL host; it would report hundreds of false failures")
	}
	// No requirements at all means it applies everywhere, which is the format's default.
	if !(&SCAPolicy{}).Applies(&fakeSystem{}) {
		t.Error("a policy with no requirements was skipped")
	}
}

// TestParseWazuhPolicyShape parses the real format, including the compliance block that is a list
// of single-key maps rather than a map, which is the part most likely to be modelled wrongly.
func TestParseWazuhPolicyShape(t *testing.T) {
	const src = `
policy:
  id: "cis_debian10"
  file: "cis_debian10.yml"
  name: "CIS Debian Linux 10 Benchmark v1.0.0"
  description: "Hardening guide"

requirements:
  title: "Check Debian 10"
  description: "Requirements for running the policy"
  condition: any
  rules:
    - 'f:/etc/debian_version'

checks:
  - id: 3000
    title: "Ensure mounting of cramfs filesystems is disabled"
    description: "The cramfs filesystem type is a compressed read-only filesystem."
    rationale: "Removing support reduces the local attack surface."
    remediation: "Edit /etc/modprobe.d/CIS.conf and add: install cramfs /bin/true"
    compliance:
      - cis: ["1.1.1.1"]
      - cis_csc: ["5.1"]
      - pci_dss: ["2.2.5"]
    condition: all
    rules:
      - 'c:modprobe -n -v cramfs -> r:install /bin/true'
      - 'not c:lsmod -> r:cramfs'
`
	var p SCAPolicy
	if err := yaml.Unmarshal([]byte(src), &p); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Policy.ID != "cis_debian10" {
		t.Errorf("policy id = %q", p.Policy.ID)
	}
	if len(p.Requirements.Rules) != 1 || p.Requirements.Condition != "any" {
		t.Errorf("requirements = %+v", p.Requirements)
	}
	if len(p.Checks) != 1 {
		t.Fatalf("got %d checks, want 1", len(p.Checks))
	}
	c := p.Checks[0]
	if c.ID != 3000 || c.Condition != "all" || len(c.Rules) != 2 {
		t.Errorf("check = %+v", c)
	}
	if c.Remediation == "" {
		t.Error("remediation was dropped; a failing check with no remediation is not actionable")
	}
	if clauses := c.CISClauses(); len(clauses) != 1 || clauses[0] != "1.1.1.1" {
		t.Errorf("CIS clauses = %v, want [1.1.1.1]", clauses)
	}

	// And it evaluates against a host that satisfies it.
	sys := &fakeSystem{
		files:    map[string]string{"/etc/debian_version": "10.13"},
		commands: map[string]string{"modprobe -n -v cramfs": "install /bin/true", "lsmod": "ext4 1 1"},
	}
	if !p.Applies(sys) {
		t.Fatal("the parsed policy does not apply to a Debian host")
	}
	res := p.Evaluate(sys)
	if len(res) != 1 || res[0].Result != SCAPassed {
		t.Fatalf("got %+v, want one passed check", res)
	}
	if !strings.Contains(res[0].Remediation, "CIS.conf") {
		t.Errorf("remediation = %q", res[0].Remediation)
	}
}

// TestSummariseScoreExcludesSkipped pins the scoring rule. Counting a check the engine could not
// evaluate as a failure would send an operator to change a production host for no reason;
// counting it in the denominator at all would let a host improve its score by becoming LESS
// assessable, which is the one thing a compliance number must never reward.
func TestSummariseScoreExcludesSkipped(t *testing.T) {
	p := &SCAPolicy{}
	p.Policy.ID = "p"
	results := []SCAResult{
		{Result: SCAPassed}, {Result: SCAPassed}, {Result: SCAPassed},
		{Result: SCAFailed},
		{Result: SCANotApplicable}, {Result: SCANotApplicable},
	}
	a := summarise(p, results)
	if a.Passed != 3 || a.Failed != 1 || a.NotApplicab != 2 {
		t.Fatalf("counts = %d/%d/%d, want 3/1/2", a.Passed, a.Failed, a.NotApplicab)
	}
	// 3 of 4 evaluable, not 3 of 6.
	if a.Score != 75 {
		t.Errorf("score = %d, want 75 (skipped checks excluded from the denominator)", a.Score)
	}

	// A policy where nothing could be evaluated scores 0 rather than dividing by zero.
	none := summarise(p, []SCAResult{{Result: SCANotApplicable}})
	if none.Score != 0 {
		t.Errorf("score with no evaluable checks = %d, want 0", none.Score)
	}
	if empty := summarise(p, nil); empty.Score != 0 {
		t.Errorf("score with no checks = %d, want 0", empty.Score)
	}
}
