//go:build !linux

package agent

import (
	"context"
	"fmt"
)

// collectJournald stub: journald hanya tersedia di Linux.
func collectJournald(_ context.Context, _ Source, _ chan<- Line) error {
	return fmt.Errorf("source journald hanya didukung di Linux")
}
