//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
)

// spawnUninstaller writes a batch cleaner and launches it detached. After a short delay
// (so the agent process exits first) it stops & deletes the Windows service, removes the
// install dirs, machine env vars, and the firewall rule — then deletes itself. Paths mirror
// internal/agentinstall/install.ps1.
func spawnUninstaller() error {
	bat := filepath.Join(os.TempDir(), "deuswatch-uninstall.bat")
	script := "@echo off\r\n" +
		"timeout /t 3 /nobreak >nul\r\n" +
		"sc stop DeusWatchAgent >nul 2>&1\r\n" +
		"sc delete DeusWatchAgent >nul 2>&1\r\n" +
		"rmdir /s /q \"C:\\Program Files\\DeusWatch\" >nul 2>&1\r\n" +
		"rmdir /s /q \"C:\\ProgramData\\DeusWatch\" >nul 2>&1\r\n" +
		"powershell -NoProfile -Command \"[Environment]::SetEnvironmentVariable('GATEWAY_URL',$null,'Machine'); " +
		"[Environment]::SetEnvironmentVariable('CERT_DIR',$null,'Machine'); " +
		"Remove-NetFirewallRule -DisplayName 'DeusWatch agent (outbound)' -ErrorAction SilentlyContinue\"\r\n" +
		"del \"%~f0\" >nul 2>&1\r\n"
	if err := os.WriteFile(bat, []byte(script), 0o644); err != nil {
		return err
	}
	// `start` spawns an independent process that outlives the agent; Windows does not
	// kill it when the parent exits.
	cmd := exec.Command("cmd.exe", "/C", "start", "DeusWatch Uninstall", "/MIN", bat)
	return cmd.Start()
}
