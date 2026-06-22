//go:build !linux

package agent

import "fmt"

// ApplyBlocklist is a stub on non-Linux: agent-side nftables auto-block is Linux-only.
func ApplyBlocklist(_, _ string, _ []string) error {
	return fmt.Errorf("agent: nftables auto-block is only supported on Linux")
}
