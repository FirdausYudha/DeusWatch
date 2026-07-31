//go:build !linux,!windows

package agent

// collectProcesses is a no-op fallback for unsupported operating systems.
func collectProcesses() ([]ProcessSnapshot, error) {
	return []ProcessSnapshot{}, nil
}
