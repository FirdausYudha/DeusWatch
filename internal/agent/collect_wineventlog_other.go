//go:build !windows

package agent

import (
	"context"
	"fmt"
)

// collectWinEventLog stub: the Windows Event Log is only available on Windows.
func collectWinEventLog(_ context.Context, _ Source, _ chan<- Line) error {
	return fmt.Errorf("the wineventlog source is only supported on Windows")
}
