//go:build !linux

package agent

import (
	"context"
	"fmt"
)

// collectRootcheck is a stub off Linux. The checks it performs read /proc and rely on POSIX mode
// bits and /dev semantics, none of which exist on Windows and all of which would need a different
// implementation on macOS. It returns an error rather than silently doing nothing, so a rootcheck
// source pushed to the wrong platform shows up in that agent's log instead of looking like a
// scanner that is running.
func collectRootcheck(_ context.Context, s Source, _ chan<- Line) error {
	return fmt.Errorf("rootcheck source %q: rootkit checks are only available on Linux", s.Dataset)
}
