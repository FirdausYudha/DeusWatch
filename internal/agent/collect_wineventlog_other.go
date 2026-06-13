//go:build !windows

package agent

import (
	"context"
	"fmt"
)

// collectWinEventLog stub: Windows Event Log hanya tersedia di Windows.
func collectWinEventLog(_ context.Context, _ Source, _ chan<- Line) error {
	return fmt.Errorf("source wineventlog hanya didukung di Windows")
}
