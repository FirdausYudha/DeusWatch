//go:build !windows

package main

import "fmt"

// On non-Windows, supervision is handled by systemd (see deploy/agent). This stub
// ensures the Windows service path is not compiled in.

// setupServiceLogging is a no-op on non-Windows: systemd/journald already captures
// the agent's stdout/stderr.
func setupServiceLogging() {}

func runningAsService() bool { return false }

func runService() {}

func controlService(string) error {
	return fmt.Errorf("service control is only available on Windows (use systemd on Linux)")
}
