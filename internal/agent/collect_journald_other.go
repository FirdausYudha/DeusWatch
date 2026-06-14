//go:build !linux

package agent

import (
	"context"
	"fmt"
)

// collectJournald stub: journald is only available on Linux.
func collectJournald(_ context.Context, _ Source, _ chan<- Line) error {
	return fmt.Errorf("the journald source is only supported on Linux")
}
