package agent

// The real host behind the SCA engine's System interface, plus the collector that loads policies
// and ships results.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"deuswatch/internal/signing"
)

// scaInterval is the default period between assessments. Benchmarks measure configuration, which
// changes when somebody changes it, so a daily pass is the right order of magnitude. Running
// hundreds of shell commands every few minutes on every endpoint is how a monitoring agent earns
// a reputation for being the thing that slows the servers down.
const scaInterval = 24 * time.Hour

// scaCommandTimeout bounds one check's command. A hung command must not stall the assessment:
// several CIS checks shell out to tools that can block on a broken mount or an unreachable LDAP
// server, and one of those would otherwise stop every later check from running at all.
const scaCommandTimeout = 30 * time.Second

// scaMaxFileBytes caps a file read. Policies read config files, which are small; a rule pointed at
// a log file by accident must not pull hundreds of megabytes into memory to regex it.
const scaMaxFileBytes = 4 << 20

// hostSystem implements System against the real machine.
type hostSystem struct {
	ctx context.Context
}

func (h hostSystem) FileContent(path string) (string, bool) {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return "", false
	}
	if fi.Size() > scaMaxFileBytes {
		return "", false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(b), true
}

func (h hostSystem) DirEntries(dir string) ([]string, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out, true
}

// RunCommand executes a policy's command through the platform shell.
//
// A shell is required rather than avoidable: CIS rules are written as pipelines
// ("grep x /etc/y | awk ..."), and splitting them on whitespace would break most of them. That
// makes a policy file a code-execution vector, which is why loading them is gated, see
// scaPolicyDir.
func (h hostSystem) RunCommand(cmdline string) (string, bool) {
	ctx, cancel := context.WithTimeout(h.ctx, scaCommandTimeout)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", cmdline)
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", cmdline)
	}
	out, err := cmd.CombinedOutput()
	// A non-zero exit is NOT a failure to run. Half of CIS depends on the output of a command
	// that exits non-zero: grep finding nothing, modprobe refusing to load. Only a command that
	// could not be started at all, or that timed out, is unevaluable.
	if ctx.Err() != nil {
		return "", false
	}
	if err != nil {
		if _, isExit := err.(*exec.ExitError); !isExit {
			return "", false
		}
	}
	return string(out), true
}

func (h hostSystem) ProcessRunning(name string) bool {
	procs, err := collectProcesses()
	if err != nil {
		return false
	}
	for _, p := range procs {
		if strings.EqualFold(p.Name, name) {
			return true
		}
	}
	return false
}

// SCAAssessment is one policy's result set, shipped as a single line so the manager stores a
// policy's score atomically rather than reconstructing it from hundreds of separate events.
type SCAAssessment struct {
	PolicyID    string      `json:"sca_policy_id"`
	PolicyName  string      `json:"sca_policy_name"`
	Passed      int         `json:"passed"`
	Failed      int         `json:"failed"`
	NotApplicab int         `json:"not_applicable"`
	Score       int         `json:"score"` // percent of evaluable checks that passed
	Results     []SCAResult `json:"results"`
}

// scaPolicyDir is where policies are read from. An absolute path under the agent's own config
// directory, never a path the manager can set.
//
// This is a deliberate limit on the config-push feature. A policy's `c:` rules run through a
// shell as the agent's user, which is usually root, so a policy file IS executable content. If the
// manager could push one, a compromised manager would own every endpoint, and the whole point of
// giving each agent its own certificate is that the manager is not implicitly trusted with
// arbitrary code on the host. Policies are placed on the endpoint by whoever administers the
// endpoint.
const scaPolicyDir = "/etc/deuswatch/sca"

// scaPolicyDirWindows is the same thing on Windows.
const scaPolicyDirWindows = `C:\ProgramData\DeusWatch\sca`

func policyDir() string {
	if dir := strings.TrimSpace(os.Getenv("SCA_POLICY_DIR")); dir != "" {
		return dir
	}
	if runtime.GOOS == "windows" {
		return scaPolicyDirWindows
	}
	return scaPolicyDir
}

// loadPolicies reads every *.yml in dir. A file that will not parse is logged and skipped rather
// than aborting the run: one malformed policy must not cost an operator the other five.
func loadPolicies(dir string) ([]*SCAPolicy, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []*SCAPolicy
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if ext := strings.ToLower(filepath.Ext(name)); ext != ".yml" && ext != ".yaml" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			log.Printf("agent: sca: read %s: %v", name, err)
			continue
		}
		var p SCAPolicy
		if err := yaml.Unmarshal(b, &p); err != nil {
			log.Printf("agent: sca: %s is not a valid policy, skipping: %v", name, err)
			continue
		}
		if p.Policy.ID == "" {
			log.Printf("agent: sca: %s has no policy.id, skipping", name)
			continue
		}
		if len(p.Checks) == 0 {
			log.Printf("agent: sca: %s has no checks, skipping", name)
			continue
		}
		pc := p
		out = append(out, &pc)
	}
	return out, nil
}

// benchmarkSink ships a completed assessment to the manager. Set once at startup via
// SetBenchmarkSink, following the same shape as the FIM snapshot sink; nil means the source has
// nothing to ship to and says so rather than assessing a host and throwing the answer away.
var benchmarkSink func(SCAAssessment)

// SetBenchmarkSink wires the uploader that ships assessments to the manager.
func SetBenchmarkSink(fn func(SCAAssessment)) { benchmarkSink = fn }

// policyFetcher pulls the centrally managed policies. nil means this agent runs local policies
// only, which is also what SCA_ALLOW_PUSHED=0 produces.
var policyFetcher func(context.Context) ([]PushedPolicy, error)

// SetSCAPolicyFetcher wires the fetch for centrally managed policies.
func SetSCAPolicyFetcher(fn func(context.Context) ([]PushedPolicy, error)) { policyFetcher = fn }

// pushedAllowed reports whether this endpoint accepts benchmark policies from the manager.
//
// The opt-out exists because a policy's `c:` rules run through a shell as the agent's user. The
// manager can already replace the agent binary itself, so refusing policies does not make a
// compromised manager harmless, but an administrator hardening one specific machine should still
// have a way to say that this host runs only what was placed on it.
func pushedAllowed() bool { return os.Getenv("SCA_ALLOW_PUSHED") != "0" }

// cacheDir is where fetched policies are kept so a manager outage does not silently stop
// benchmark assessment. A compliance page that goes blank because the network blipped looks
// exactly like a compliance page for an estate nobody is assessing.
func cacheDir() string { return filepath.Join(policyDir(), "cache") }

// fetchAndCachePolicies pulls the managed policies and writes them to the cache, returning what
// to assess. On a fetch failure it falls back to the cache and says so.
func fetchAndCachePolicies(ctx context.Context) []*SCAPolicy {
	if policyFetcher == nil || !pushedAllowed() {
		return nil
	}
	pushed, err := policyFetcher(ctx)
	if err != nil {
		cached := readCachedPolicies()
		if len(cached) > 0 {
			log.Printf("agent: sca: could not reach the manager for policies (%v); assessing the %d cached ones", err, len(cached))
		}
		return cached
	}
	pushed = verifiedPolicies(pushed)
	writeCachedPolicies(pushed)
	out := make([]*SCAPolicy, 0, len(pushed))
	for _, pp := range pushed {
		var p SCAPolicy
		if uerr := yaml.Unmarshal([]byte(pp.YAML), &p); uerr != nil {
			// The manager validates on upload, so this means the stored YAML was corrupted in
			// transit or by hand. Name the policy rather than failing the whole assessment.
			log.Printf("agent: sca: managed policy %s will not parse, skipping: %v", pp.PolicyID, uerr)
			continue
		}
		pc := p
		out = append(out, &pc)
	}
	return out
}

// writeCachedPolicies replaces the cache with what the manager just served. Written as a whole
// directory replace rather than file by file, so a policy the manager has disabled or deleted
// disappears from the cache too; otherwise an agent that lost its connection would keep assessing
// against a benchmark the operator had already withdrawn.
func writeCachedPolicies(pushed []PushedPolicy) {
	dir := cacheDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("agent: sca: cannot write the policy cache at %s: %v", dir, err)
		return
	}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".yml") {
				_ = os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
	for _, pp := range pushed {
		name := safePolicyFilename(pp.PolicyID)
		if name == "" {
			continue
		}
		// 0600: a policy is executable content, so it must not be readable or writable by a
		// non-root user who could then change what root runs on the next assessment.
		if err := os.WriteFile(filepath.Join(dir, name), []byte(pp.YAML), 0o600); err != nil {
			log.Printf("agent: sca: cannot cache policy %s: %v", pp.PolicyID, err)
		}
	}
}

func readCachedPolicies() []*SCAPolicy {
	policies, err := loadPolicies(cacheDir())
	if err != nil {
		return nil
	}
	return policies
}

// safePolicyFilename turns a policy id into a filename, refusing anything that is not a plain
// name. The id comes from the manager, so it is attacker-controlled if the manager is
// compromised, and joining it into a path unchecked is a directory traversal that writes
// root-owned files anywhere on the host.
func safePolicyFilename(policyID string) string {
	if policyID == "" || len(policyID) > 120 {
		return ""
	}
	for _, r := range policyID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_', r == '-', r == '.':
		default:
			return ""
		}
	}
	if strings.Contains(policyID, "..") {
		return ""
	}
	return policyID + ".yml"
}

// collectSCA is the "sca" source collector: configuration-benchmark assessment.
func collectSCA(ctx context.Context, s Source, out chan<- Line) error {
	dir := policyDir()
	if _, err := os.Stat(dir); err != nil && !pushedAllowed() {
		// Only worth saying when there is nowhere else policies could come from. An operator may
		// drop them in later, and a source that exited would never pick them up.
		log.Printf("agent: sca %q: no policies in %s and pushed policies are disabled (see docs/benchmarks.md)",
			s.Dataset, dir)
	}

	if benchmarkSink == nil {
		return fmt.Errorf("sca source %q: no manager connection to report assessments to", s.Dataset)
	}
	if !pushedAllowed() {
		log.Printf("agent: sca %q: SCA_ALLOW_PUSHED=0, this host runs only the policies placed on it", s.Dataset)
	}

	run := func() {
		local, err := loadPolicies(dir)
		if err != nil && !os.IsNotExist(err) {
			log.Printf("agent: sca %q: %v", s.Dataset, err)
		}
		policies := mergePolicies(local, fetchAndCachePolicies(ctx))
		if len(policies) == 0 {
			return
		}
		sys := hostSystem{ctx: ctx}
		for _, p := range policies {
			if ctx.Err() != nil {
				return
			}
			if !p.Applies(sys) {
				// The wrong policy for this host. Skipped, not failed: a Debian benchmark on a
				// RHEL box would otherwise report several hundred failures that are not findings.
				log.Printf("agent: sca %q: policy %s does not apply to this host, skipping",
					s.Dataset, p.Policy.ID)
				continue
			}
			a := summarise(p, p.Evaluate(sys))
			benchmarkSink(a)
			// A one-line summary also goes down the log pipeline, so the assessment appears in
			// the event timeline and can be alerted on. The results themselves do NOT: a few
			// hundred of them per host per day would drown the timeline, and they are already
			// stored as current state where a score can be read off them.
			body, err := json.Marshal(struct {
				SCAAssessment
				Results []SCAResult `json:"results,omitempty"`
			}{SCAAssessment: a})
			if err != nil {
				continue
			}
			select {
			case out <- Line{Dataset: s.Dataset, Message: string(body)}:
			case <-ctx.Done():
				return
			}
		}
	}

	run() // assess once at startup rather than waiting a day to say anything
	tick := time.NewTicker(s.scanInterval(scaInterval))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			run()
		}
	}
}

// summarise counts a policy's results into the shipped assessment.
func summarise(p *SCAPolicy, results []SCAResult) SCAAssessment {
	a := SCAAssessment{
		PolicyID:   p.Policy.ID,
		PolicyName: p.Policy.Name,
		Results:    results,
	}
	for _, r := range results {
		switch r.Result {
		case SCAPassed:
			a.Passed++
		case SCAFailed:
			a.Failed++
		default:
			a.NotApplicab++
		}
	}
	// The score counts only the checks that could actually be evaluated. Including the skipped
	// ones in the denominator would let a host improve its score by becoming less assessable,
	// which is the one thing a compliance number must never reward.
	if evaluable := a.Passed + a.Failed; evaluable > 0 {
		a.Score = a.Passed * 100 / evaluable
	}
	return a
}

var _ System = hostSystem{}

// mergePolicies combines the policies placed on this endpoint with the ones the manager serves.
//
// A LOCAL policy wins over a managed one carrying the same policy.id. That is the whole of the
// endpoint administrator's remaining authority over what runs as root on their machine: central
// management is the default and the convenient path, and dropping a file in /etc/deuswatch/sca
// still overrides it without having to argue with whoever runs the console.
func mergePolicies(local, managed []*SCAPolicy) []*SCAPolicy {
	out := make([]*SCAPolicy, 0, len(local)+len(managed))
	seen := make(map[string]bool, len(local))
	for _, p := range local {
		if p.Policy.ID == "" || seen[p.Policy.ID] {
			continue
		}
		seen[p.Policy.ID] = true
		out = append(out, p)
	}
	for _, p := range managed {
		if p.Policy.ID == "" || seen[p.Policy.ID] {
			continue
		}
		seen[p.Policy.ID] = true
		out = append(out, p)
	}
	return out
}

// verifiedPolicies drops every managed policy this endpoint cannot vouch for.
//
// A policy's `c:` rules are shell commands run as the agent's user, usually root, so a served
// policy is the manager handing code to an endpoint. It gets the same treatment as the agent
// binary, and for the same reason:
//
//   - A trusted key is installed: a policy must verify against it or it is DROPPED. Dropped, not
//     failed: a benchmark that is not assessed leaves the previous score standing, whereas
//     evaluating an unverified policy would run whatever the attacker wrote.
//   - No trusted key: everything runs, with one warning naming the variable that would change
//     that. Refusing would silently stop benchmarks on every endpoint already deployed.
//
// Filtering happens BEFORE the cache is written, so a rejected policy is not left on disk to be
// picked up by the offline fallback on the next pass.
func verifiedPolicies(pushed []PushedPolicy) []PushedPolicy {
	v, err := signing.LoadVerifier(os.Getenv("UPDATE_PUBKEY"), signing.DefaultPubKeyFile())
	if err != nil {
		// Configured but unusable. Dropping everything is the safe reading: the operator asked
		// for verification and this host cannot perform it.
		log.Printf("agent: sca: the trusted release key is unusable, no managed policy will run: %v", err)
		return nil
	}
	if !v.Enabled() {
		if len(pushed) > 0 {
			log.Printf("agent: sca: WARNING %d managed policies are running UNVERIFIED. A policy runs "+
				"shell commands as this agent's user, so anyone who controls the manager can run code "+
				"here. Install the operator's public key (UPDATE_PUBKEY, or %s) to require signatures.",
				len(pushed), signing.DefaultPubKeyFile())
		}
		return pushed
	}
	out := make([]PushedPolicy, 0, len(pushed))
	for _, pp := range pushed {
		if pp.Signature == "" {
			log.Printf("agent: sca: DROPPED managed policy %s: this host requires signed policies "+
				"(key from %s) and it arrived unsigned", pp.PolicyID, v.Source())
			continue
		}
		if verr := v.Verify([]byte(pp.YAML), pp.Signature); verr != nil {
			log.Printf("agent: sca: DROPPED managed policy %s: it does not verify against the trusted "+
				"key from %s. Either it was signed with a different key or it was altered: %v",
				pp.PolicyID, v.Source(), verr)
			continue
		}
		out = append(out, pp)
	}
	return out
}
