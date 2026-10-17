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

// collectSCA is the "sca" source collector: configuration-benchmark assessment.
func collectSCA(ctx context.Context, s Source, out chan<- Line) error {
	dir := policyDir()
	if _, err := os.Stat(dir); err != nil {
		// Not an error worth stopping the source for: an operator may drop policies in later, and
		// a source that exited would then never pick them up. Say exactly what is missing.
		log.Printf("agent: sca %q: no policies in %s yet (see docs/benchmarks.md); will keep checking",
			s.Dataset, dir)
	}

	if benchmarkSink == nil {
		return fmt.Errorf("sca source %q: no manager connection to report assessments to", s.Dataset)
	}

	run := func() {
		policies, err := loadPolicies(dir)
		if err != nil {
			log.Printf("agent: sca %q: %v", s.Dataset, err)
			return
		}
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
