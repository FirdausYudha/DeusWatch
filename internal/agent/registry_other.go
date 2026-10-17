//go:build !windows

package agent

import (
	"context"
	"fmt"
)

// collectRegistry is a stub off Windows. It returns an error rather than silently doing nothing,
// so a registry source pushed to a Linux endpoint by mistake shows up in that agent's log instead
// of looking like a monitor that is running.
func collectRegistry(_ context.Context, s Source, _ chan<- Line) error {
	return fmt.Errorf("registry source %q: registry monitoring is only available on Windows", s.Dataset)
}
