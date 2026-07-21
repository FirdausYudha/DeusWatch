package agent

import "runtime"

// DefaultSources returns the sensible default log sources for the OS this agent is running on.
// Used when the manager has not pushed a config (a brand-new or unmanaged agent).
func DefaultSources() []Source {
	return DefaultSourcesFor(runtime.GOOS)
}

// DefaultSourcesFor returns the default log sources for a given OS, identified by its runtime.GOOS
// string ("linux", "windows", "darwin", ...). This is deliberately NOT build-tagged: the MANAGER
// calls it to seed a newly-enrolled agent's config with the right defaults for THAT agent's OS,
// and the manager may run on a different OS than the agent it is enrolling. The agent's own
// DefaultSources() above routes here with its local GOOS.
//
// An unknown OS returns nil (no defaults) rather than guessing — the agent then simply has no
// sources until one is configured, which surfaces clearly rather than watching the wrong files.
func DefaultSourcesFor(goos string) []Source {
	switch goos {
	case "linux":
		return []Source{
			{Dataset: "sshd", Type: "file", Path: "/var/log/auth.log"},
			{Dataset: "syslog", Type: "file", Path: "/var/log/syslog"},
			// Firewall drops for port-scan detection. Requires the firewall to log (UFW logging
			// on, or an iptables/nftables LOG rule). Missing file = simply no events.
			{Dataset: "firewall", Type: "file", Path: "/var/log/ufw.log"},
			// Web access log for the web-defacement / judi-online / path-scan rules. nginx default;
			// for apache add /var/log/apache2/access.log via config. Missing file = no events.
			{Dataset: "web", Type: "file", Path: "/var/log/nginx/access.log"},
		}
	case "windows":
		return []Source{
			{Dataset: "windows-security", Type: "wineventlog", Path: "Security"},
			{Dataset: "windows-system", Type: "wineventlog", Path: "System"},
		}
	default:
		return nil
	}
}
