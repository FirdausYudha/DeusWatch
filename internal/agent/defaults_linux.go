//go:build linux

package agent

// DefaultSources untuk Linux: berkas auth & syslog. journald tersedia via config
// (Type "journald") bila distro tidak menulis ke berkas.
func DefaultSources() []Source {
	return []Source{
		{Dataset: "sshd", Type: "file", Path: "/var/log/auth.log"},
		{Dataset: "syslog", Type: "file", Path: "/var/log/syslog"},
	}
}
