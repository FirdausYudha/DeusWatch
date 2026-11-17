//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// spawnUninstaller writes a batch cleaner and launches it detached, so the still-running
// agent can remove its own service and binary. It stops the service and WAITS for it to
// actually stop (the .exe stays locked until the process exits), deletes the service, then
// retries removing the install dirs until the lock on the binary clears. Finally it clears
// the machine env vars and firewall rule and deletes itself. Paths mirror
// internal/agentinstall/install.ps1.
//
// The earlier version used a fixed 3-second sleep before rmdir; when the service took longer
// than that to stop, rmdir hit a locked deuswatch-agent.exe and left the service and files
// behind. Polling the service state and retrying the removal makes it reliable regardless of
// how long shutdown takes.
func spawnUninstaller() error {
	bat := filepath.Join(os.TempDir(), "deuswatch-uninstall.bat")
	lines := []string{
		"@echo off",
		"sc stop DeusWatchAgent >nul 2>&1",
		// Wait up to ~30s for the service to reach STOPPED (or vanish, error 1060) so its
		// .exe unlocks before we try to delete the directory it lives in.
		"set /a tries=0",
		":waitstop",
		`sc query DeusWatchAgent | find "STOPPED" >nul 2>&1 && goto stopped`,
		`sc query DeusWatchAgent | find "1060" >nul 2>&1 && goto stopped`,
		"set /a tries+=1",
		"if %tries% geq 30 goto stopped",
		"timeout /t 1 /nobreak >nul",
		"goto waitstop",
		":stopped",
		"sc delete DeusWatchAgent >nul 2>&1",
		// Retry the directory removal: the binary's lock can linger a moment after the
		// process exits, and the first rmdir would otherwise leave the .exe behind.
		"set /a dtries=0",
		":delloop",
		`rmdir /s /q "C:\Program Files\DeusWatch" >nul 2>&1`,
		`if not exist "C:\Program Files\DeusWatch" goto deldone`,
		"set /a dtries+=1",
		"if %dtries% geq 20 goto deldone",
		"timeout /t 1 /nobreak >nul",
		"goto delloop",
		":deldone",
		`rmdir /s /q "C:\ProgramData\DeusWatch" >nul 2>&1`,
		"powershell -NoProfile -Command \"[Environment]::SetEnvironmentVariable('GATEWAY_URL',$null,'Machine'); " +
			"[Environment]::SetEnvironmentVariable('CERT_DIR',$null,'Machine'); " +
			"Remove-NetFirewallRule -DisplayName 'DeusWatch agent (outbound)' -ErrorAction SilentlyContinue\"",
		`del "%~f0" >nul 2>&1`,
	}
	script := strings.Join(lines, "\r\n") + "\r\n"
	if err := os.WriteFile(bat, []byte(script), 0o644); err != nil {
		return err
	}
	// `start` spawns an independent process that outlives the agent; Windows does not
	// kill it when the parent exits.
	cmd := exec.Command("cmd.exe", "/C", "start", "DeusWatch Uninstall", "/MIN", bat)
	return cmd.Start()
}
