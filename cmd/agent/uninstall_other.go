//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// Paths created by internal/agentinstall/install.sh.
const (
	linuxBinary  = "/usr/local/bin/deuswatch-agent"
	linuxUnit    = "/etc/systemd/system/deuswatch-agent.service"
	linuxConfig  = "/etc/deuswatch"
	linuxData    = "/var/lib/deuswatch"
	linuxService = "deuswatch-agent"
)

// spawnUninstaller launches a detached cleaner that disables & removes the systemd service
// and deletes all installed files. It runs as a transient systemd unit (systemd-run) so it
// lives in its own cgroup and survives stopping the agent's own unit; if systemd-run is
// unavailable (non-systemd host) it falls back to a session-detached shell.
func spawnUninstaller() error {
	script := "sleep 1; " +
		"systemctl disable --now " + linuxService + " 2>/dev/null; " +
		"rm -f " + linuxUnit + "; systemctl daemon-reload 2>/dev/null; " +
		"rm -f " + linuxBinary + "; rm -rf " + linuxConfig + " " + linuxData

	if path, err := exec.LookPath("systemd-run"); err == nil {
		cmd := exec.Command(path, "--collect", "--unit=deuswatch-uninstall", "/bin/sh", "-c", script)
		if runErr := cmd.Run(); runErr == nil {
			return nil
		}
	}
	// Fallback for non-systemd hosts: detach into a new session so it outlives the agent.
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}
