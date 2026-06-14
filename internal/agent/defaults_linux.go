//go:build linux

package agent

// DefaultSources for Linux: auth & syslog files. journald is available via config
// (Type "journald") if the distro does not write to files.
func DefaultSources() []Source {
	return []Source{
		{Dataset: "sshd", Type: "file", Path: "/var/log/auth.log"},
		{Dataset: "syslog", Type: "file", Path: "/var/log/syslog"},
	}
}
