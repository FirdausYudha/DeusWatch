//go:build !linux && !windows

package agent

import "fmt"

// ApplyIsolation is a stub on unsupported OSes (host containment is Linux/Windows only).
func ApplyIsolation(_ []string) error {
	return fmt.Errorf("agent: host isolation is only supported on Linux and Windows")
}

// ClearIsolation is a no-op stub on unsupported OSes.
func ClearIsolation() error { return nil }
