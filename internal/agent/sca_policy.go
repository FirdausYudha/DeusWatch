package agent

// Configuration-benchmark assessment: CIS hardening checks evaluated on the endpoint.
//
// This reads WAZUH'S policy format rather than inventing one, and that is the whole point of the
// feature. The value in a CIS benchmark is not the engine, it is the several hundred checks per
// platform that somebody keeps current as distributions change. Writing a format of our own would
// mean maintaining that content here, which is a promise this project cannot keep: the comparison
// against Wazuh already lists "a ruleset nobody updates but us" as a real weakness, and inventing
// a second content format would add another.
//
// The same call was made twice before in this codebase and was right both times. The 465 imported
// decoders came from Wazuh's, Ruijie got a generic SSH responder instead of a vendor API, and the
// SNMP sensors take operator-supplied OIDs. All of them still work when the upstream moves.
//
// Format reference: a policy is `policy:` metadata, optional `requirements:` that gate whether
// the policy applies to this host at all, and `checks:` each with a `condition` and `rules`.
//
//	checks:
//	  - id: 3000
//	    title: "Ensure mounting of cramfs filesystems is disabled"
//	    remediation: "Edit /etc/modprobe.d/CIS.conf and add: install cramfs /bin/true"
//	    compliance:
//	      - cis: ["1.1.1.1"]
//	    condition: all
//	    rules:
//	      - 'c:modprobe -n -v cramfs -> r:install /bin/true'
//	      - 'not c:lsmod -> r:cramfs'

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SCAPolicy is one benchmark file.
type SCAPolicy struct {
	Policy struct {
		ID          string `yaml:"id"`
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	} `yaml:"policy"`
	// Requirements decide whether this policy applies to the host at all, e.g. "is this actually
	// Debian 10". A policy whose requirements fail is SKIPPED rather than failed: reporting 230
	// failed Debian checks on a RHEL box is not a finding, it is the wrong policy.
	Requirements struct {
		Title     string   `yaml:"title"`
		Condition string   `yaml:"condition"`
		Rules     []string `yaml:"rules"`
	} `yaml:"requirements"`
	Checks []SCACheck `yaml:"checks"`
}

// SCACheck is one hardening control.
type SCACheck struct {
	ID          int      `yaml:"id"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Rationale   string   `yaml:"rationale"`
	Remediation string   `yaml:"remediation"`
	Condition   string   `yaml:"condition"` // all | any | none
	Rules       []string `yaml:"rules"`
	// Compliance maps the check onto the framework clauses it satisfies. Wazuh writes it as a
	// list of single-key maps, each value a list of strings, which is why it is not a plain map.
	Compliance []map[string][]string `yaml:"compliance"`
}

// SCAResult is one evaluated check.
type SCAResult struct {
	PolicyID    string   `json:"policy_id"`
	CheckID     int      `json:"check_id"`
	Title       string   `json:"title"`
	Result      string   `json:"result"` // passed | failed | not_applicable
	Remediation string   `json:"remediation,omitempty"`
	Reason      string   `json:"reason,omitempty"` // why it could not be evaluated
	CIS         []string `json:"cis,omitempty"`    // the CIS clause numbers this check covers
}

// SCA result values.
const (
	SCAPassed        = "passed"
	SCAFailed        = "failed"
	SCANotApplicable = "not_applicable"
)

// System is everything a rule needs from the host. An interface because the whole value of this
// engine is in being able to test it: the rule syntax has enough corners that a bug is likely and
// a bug here means a wrong compliance score, which is worse than no score at all.
type System interface {
	// FileContent returns the file's contents. ok=false when it does not exist or cannot be read,
	// which a rule must be able to tell apart from an empty file.
	FileContent(path string) (content string, ok bool)
	// DirEntries returns the names directly inside dir. ok=false when dir does not exist.
	DirEntries(dir string) (names []string, ok bool)
	// RunCommand returns a command's combined output. ok=false when it could not be run at all.
	// A non-zero exit is NOT a failure here: half of CIS checks read the output of a command that
	// exits non-zero (grep finding nothing, modprobe refusing), and treating that as unevaluable
	// would skip them.
	RunCommand(cmdline string) (output string, ok bool)
	// ProcessRunning reports whether a process with this name is running.
	ProcessRunning(name string) bool
	// RegistryValue returns a registry value as text (Windows). ok=false off Windows or when the
	// key or value is absent.
	RegistryValue(keyPath, value string) (string, bool)
}

// CISClauses pulls the CIS clause numbers out of a check's compliance block.
func (c SCACheck) CISClauses() []string {
	var out []string
	for _, m := range c.Compliance {
		for k, v := range m {
			if strings.EqualFold(k, "cis") {
				out = append(out, v...)
			}
		}
	}
	return out
}

// Applies reports whether the policy's requirements hold on this host, so a policy for the wrong
// distribution is skipped rather than reported as hundreds of failures.
func (p *SCAPolicy) Applies(sys System) bool {
	if len(p.Requirements.Rules) == 0 {
		return true
	}
	ok, _ := evalCondition(p.Requirements.Condition, p.Requirements.Rules, sys)
	return ok
}

// Evaluate runs every check in the policy.
func (p *SCAPolicy) Evaluate(sys System) []SCAResult {
	out := make([]SCAResult, 0, len(p.Checks))
	for _, c := range p.Checks {
		r := SCAResult{
			PolicyID:    p.Policy.ID,
			CheckID:     c.ID,
			Title:       c.Title,
			Remediation: c.Remediation,
			CIS:         c.CISClauses(),
		}
		passed, err := evalCondition(c.Condition, c.Rules, sys)
		switch {
		case err != nil:
			// A rule this engine cannot parse must NOT be reported as a failure. A failed CIS
			// check tells an operator to go change something on a production host, and sending
			// them to do that because of a syntax gap here would be worse than admitting the gap.
			r.Result = SCANotApplicable
			r.Reason = err.Error()
		case passed:
			r.Result = SCAPassed
		default:
			r.Result = SCAFailed
		}
		out = append(out, r)
	}
	return out
}

// evalCondition applies the all/any/none combinator over a check's rules.
func evalCondition(condition string, rules []string, sys System) (bool, error) {
	if len(rules) == 0 {
		return false, fmt.Errorf("check has no rules")
	}
	results := make([]bool, 0, len(rules))
	for _, raw := range rules {
		got, err := evalRule(raw, sys)
		if err != nil {
			return false, err
		}
		results = append(results, got)
	}
	switch strings.ToLower(strings.TrimSpace(condition)) {
	case "", "all":
		for _, r := range results {
			if !r {
				return false, nil
			}
		}
		return true, nil
	case "any":
		for _, r := range results {
			if r {
				return true, nil
			}
		}
		return false, nil
	case "none":
		for _, r := range results {
			if r {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("unknown condition %q", condition)
	}
}

// evalRule evaluates one rule expression.
//
// Shapes handled:
//
//	f:/etc/passwd                        the file exists
//	f:/etc/ssh/sshd_config -> r:^Port    its contents match
//	d:/etc/cron.d                        the directory exists
//	d:/etc/rc.d -> r:^S                  it holds an entry matching
//	p:sshd                               a process is running
//	c:sysctl net.ipv4.ip_forward -> r:= 0   a command's output matches
//	r:HKLM\Software\Foo -> Bar           a registry value exists (Windows)
//	not <any of the above>               negated
func evalRule(raw string, sys System) (bool, error) {
	rule := strings.TrimSpace(raw)
	negate := false
	if rest, found := cutPrefixFold(rule, "not "); found {
		negate = true
		rule = strings.TrimSpace(rest)
	}
	got, err := evalPositive(rule, sys)
	if err != nil {
		return false, err
	}
	if negate {
		return !got, nil
	}
	return got, nil
}

func evalPositive(rule string, sys System) (bool, error) {
	kind, rest, found := strings.Cut(rule, ":")
	if !found {
		return false, fmt.Errorf("rule %q has no type prefix", rule)
	}
	// The arrow separates the subject from the test applied to it. Only the FIRST arrow splits
	// the subject, because a test may itself contain one (a directory rule is
	// `d:<dir> -> <file> -> <content test>`).
	subject, test, hasTest := cutArrow(rest)
	subject = strings.TrimSpace(subject)

	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "f":
		content, ok := sys.FileContent(subject)
		if !ok {
			return false, nil // absent file: the rule is false, not unevaluable
		}
		if !hasTest {
			return true, nil
		}
		return matchTest(content, test)

	case "d":
		names, ok := sys.DirEntries(subject)
		if !ok {
			return false, nil
		}
		if !hasTest {
			return true, nil
		}
		// `d:<dir> -> <file test> [-> <content test>]`. With a content test, every matching file
		// is opened and the content test applied; the rule is true if any file satisfies it.
		filePart, contentTest, hasContent := cutArrow(test)
		filePart = strings.TrimSpace(filePart)
		for _, name := range names {
			nameOK, err := matchTest(name, filePart)
			if err != nil {
				return false, err
			}
			if !nameOK {
				continue
			}
			if !hasContent {
				return true, nil
			}
			content, ok := sys.FileContent(strings.TrimRight(subject, `/\`) + "/" + name)
			if !ok {
				continue
			}
			contentOK, err := matchTest(content, contentTest)
			if err != nil {
				return false, err
			}
			if contentOK {
				return true, nil
			}
		}
		return false, nil

	case "p":
		return sys.ProcessRunning(subject), nil

	case "c":
		output, ok := sys.RunCommand(subject)
		if !ok {
			return false, nil
		}
		if !hasTest {
			return true, nil
		}
		return matchTest(output, test)

	case "r":
		// Windows registry. `r:<key>` or `r:<key> -> <value name>`.
		if !hasTest {
			_, ok := sys.RegistryValue(subject, "")
			return ok, nil
		}
		valueName, valueTest, hasValueTest := cutArrow(test)
		valueName = strings.TrimSpace(valueName)
		got, ok := sys.RegistryValue(subject, valueName)
		if !ok {
			return false, nil
		}
		if !hasValueTest {
			return true, nil
		}
		return matchTest(got, valueTest)

	default:
		return false, fmt.Errorf("unsupported rule type %q in %q", kind, rule)
	}
}

// numCompare matches `n:<regex with one capture> compare <op> <number>`, the shape CIS uses for
// "at least 90 days" and friends.
var numCompare = regexp.MustCompile(`(?i)^n:(.*?)\s+compare\s+(<=|>=|==|!=|<|>|=)\s+(-?\d+)\s*$`)

// matchTest applies one content test to a subject string.
//
// Forms: `r:<regex>`, `!r:<regex>`, `n:<regex> compare <op> <n>`, or a literal substring.
// Several may be chained with `&&`, which Wazuh uses for "matches this and not that".
func matchTest(subject, test string) (bool, error) {
	test = strings.TrimSpace(test)
	if test == "" {
		return true, nil
	}
	for _, part := range strings.Split(test, "&&") {
		ok, err := matchOne(subject, strings.TrimSpace(part))
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func matchOne(subject, test string) (bool, error) {
	if test == "" {
		return true, nil
	}
	if m := numCompare.FindStringSubmatch(test); m != nil {
		return compareNumber(subject, m[1], m[2], m[3])
	}
	if rest, found := cutPrefixFold(test, "!r:"); found {
		ok, err := matchRegex(subject, rest)
		return !ok, err
	}
	if rest, found := cutPrefixFold(test, "r:"); found {
		return matchRegex(subject, rest)
	}
	if rest, found := cutPrefixFold(test, "n:"); found {
		// `n:` without a compare clause is still a regex, just one whose capture nobody uses.
		return matchRegex(subject, rest)
	}
	if rest, found := cutPrefixFold(test, "!"); found {
		return !strings.Contains(subject, rest), nil
	}
	return strings.Contains(subject, test), nil
}

// matchRegex compiles a rule's pattern and applies it to the subject.
//
// Patterns are compiled MULTILINE, which is not a nicety: Wazuh matches a policy's patterns
// against each LINE of a file, and CIS policies are written on that assumption. Half of them are
// anchored, `r:^PermitRootLogin\s+no`, and under Go's default semantics `^` only matches at the
// start of the whole file, so those checks would never match and every hardened host would be
// reported as failing. A wrong compliance score is worse than no compliance score.
//
// Negation stays at the subject level, not the line level. `!r:UMASK\s+000` has to mean "no line
// sets UMASK 000", because "some line does not set it" is true of almost any file and would make
// the test meaningless.
//
// Wazuh's OS_Regex overlaps RE2 for the vast majority of CIS checks but is not identical: it
// allows constructs RE2 refuses, such as lookahead. A pattern RE2 rejects yields an error, which
// Evaluate turns into not_applicable rather than a failure, because telling an operator to go
// change a production host over a regex dialect gap would be worse than admitting the check could
// not be run.
func matchRegex(subject, pattern string) (bool, error) {
	re, err := regexp.Compile("(?m)" + pattern)
	if err != nil {
		return false, fmt.Errorf("pattern %q is not supported: %w", pattern, err)
	}
	return re.MatchString(subject), nil
}

// compareNumber extracts a number with the pattern's first capture group and compares it.
func compareNumber(subject, pattern, op, want string) (bool, error) {
	re, err := regexp.Compile("(?m)" + pattern)
	if err != nil {
		return false, fmt.Errorf("pattern %q is not supported: %w", pattern, err)
	}
	m := re.FindStringSubmatch(subject)
	if m == nil {
		return false, nil
	}
	// The captured group when there is one, else the whole match: a pattern written without
	// parentheses still has a number to compare.
	text := m[0]
	if len(m) > 1 {
		text = m[1]
	}
	got, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
	if err != nil {
		return false, nil // matched something that is not a number: the comparison is just false
	}
	target, err := strconv.ParseInt(want, 10, 64)
	if err != nil {
		return false, fmt.Errorf("compare target %q is not a number", want)
	}
	switch op {
	case "<":
		return got < target, nil
	case "<=":
		return got <= target, nil
	case ">":
		return got > target, nil
	case ">=":
		return got >= target, nil
	case "==", "=":
		return got == target, nil
	case "!=":
		return got != target, nil
	default:
		return false, fmt.Errorf("unknown comparison %q", op)
	}
}

// cutArrow splits on the first "->" separator.
func cutArrow(s string) (before, after string, found bool) {
	b, a, f := strings.Cut(s, "->")
	return b, strings.TrimSpace(a), f
}

// cutPrefixFold is strings.CutPrefix, case-insensitively, because policies in the wild write
// "NOT c:..." as well as "not c:...".
func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return "", false
}
