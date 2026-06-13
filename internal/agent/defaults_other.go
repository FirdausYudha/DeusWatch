//go:build !linux && !windows

package agent

// DefaultSources untuk OS lain (mis. macOS): belum ada default bawaan; pakai
// LOG_FILE atau konfigurasi source eksplisit.
func DefaultSources() []Source {
	return nil
}
