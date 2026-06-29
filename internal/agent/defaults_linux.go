//go:build linux

package agent

// DefaultSources for Linux: auth & syslog files. journald is available via config
// (Type "journald") if the distro does not write to files.
func DefaultSources() []Source {
	return []Source{
		{Dataset: "sshd", Type: "file", Path: "/var/log/auth.log"},
		{Dataset: "syslog", Type: "file", Path: "/var/log/syslog"},
		// Firewall drops for port-scan detection. Requires the firewall to log (UFW logging
		// on, or an iptables/nftables LOG rule). Missing file = simply no events.
		{Dataset: "firewall", Type: "file", Path: "/var/log/ufw.log"},
	}
}
