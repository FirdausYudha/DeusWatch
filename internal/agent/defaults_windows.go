//go:build windows

package agent

// DefaultSources for Windows: the Security & System Event Log channels.
func DefaultSources() []Source {
	return []Source{
		{Dataset: "windows-security", Type: "wineventlog", Path: "Security"},
		{Dataset: "windows-system", Type: "wineventlog", Path: "System"},
	}
}
