//go:build darwin

package agent

import (
	"fmt"
	"os/exec"
	"strings"
)

// collectProcesses is the platform-specific implementation for macOS.
//
// macOS has no /proc. The supported way to enumerate processes without cgo is `ps`, which is in
// the base system and whose output format for these fields has been stable for decades. The
// alternative, libproc through cgo, would cost the agent its CGO_ENABLED=0 cross-compile and buy
// nothing this collector needs.
func collectProcesses() ([]ProcessSnapshot, error) {
	return collectProcessesDarwin()
}

// psFields are requested in a fixed order with `-o`, so the parser indexes rather than guesses.
// comm is LAST because it is the only field that can contain spaces: everything before it is
// split on whitespace and the remainder is the command path.
const psFields = "pid=,ppid=,user=,rss=,lstart=,comm="

// collectProcessesDarwin shells out to ps once for every process.
func collectProcessesDarwin() ([]ProcessSnapshot, error) {
	out, err := exec.Command("ps", "-axwwo", psFields).Output()
	if err != nil {
		return nil, fmt.Errorf("run ps: %w", err)
	}
	var snapshots []ProcessSnapshot
	for _, line := range strings.Split(string(out), "\n") {
		if snap := parsePSLine(line); snap != nil {
			snapshots = append(snapshots, *snap)
		}
	}
	if len(snapshots) == 0 {
		// ps succeeded and produced nothing parseable, which means its output format moved under
		// us. Reporting an empty process list as success would look like a quiet host.
		return nil, fmt.Errorf("ps returned no parseable processes; its output format may have changed")
	}
	return snapshots, nil
}
