//go:build !linux && !windows

package agent

// DefaultSources for other OSes (e.g. macOS): no built-in defaults yet; use
// LOG_FILE or explicit source configuration.
func DefaultSources() []Source {
	return nil
}
