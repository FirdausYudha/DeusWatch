//go:build !linux

package agent

import (
	"context"
	"fmt"
)

// StartWhoData is a no-op off Linux: who-data relies on the Linux audit subsystem. FIM still
// works everywhere; only the "who changed it" attribution is Linux-only for now.
func StartWhoData(_ context.Context, _ []string, _ string) (WhoDataSource, error) {
	return nil, fmt.Errorf("who-data is only available on Linux (audit subsystem)")
}
