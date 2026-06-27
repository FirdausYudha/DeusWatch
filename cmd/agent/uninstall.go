package main

import "log"

// selfUninstall removes everything the installer placed — the agent binary, certificates,
// config, the auto-start service, and the firewall rule — and stops the service. The actual
// deletion runs in a DETACHED helper (a transient systemd unit on Linux, a background batch
// on Windows) so the still-running agent can remove its own binary and service cleanly.
//
// It is invoked by the `-uninstall` flag and automatically when the manager reports this
// agent as revoked (heartbeat → HTTP 410). Paths mirror internal/agentinstall/install.{sh,ps1}.
func selfUninstall() {
	if err := spawnUninstaller(); err != nil {
		log.Printf("agent: self-uninstall failed: %v", err)
		return
	}
	log.Printf("agent: self-uninstall scheduled — service & files will be removed shortly")
}
