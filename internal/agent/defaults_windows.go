//go:build windows

package agent

// DefaultSources untuk Windows: channel Event Log Security & System.
func DefaultSources() []Source {
	return []Source{
		{Dataset: "windows-security", Type: "wineventlog", Path: "Security"},
		{Dataset: "windows-system", Type: "wineventlog", Path: "System"},
	}
}
