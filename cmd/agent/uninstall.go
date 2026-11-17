package main

import (
	"log"
	"sync/atomic"
)

// uninstalling is set the moment a self-uninstall is scheduled. On Windows the service's
// Execute loop reads it to exit cleanly (code 0) instead of asking the SCM for a restart,
// so the recovery action does not relaunch the agent into a race with the cleaner.
var uninstalling atomic.Bool

// selfUninstall removes everything the installer placed, the agent binary, certificates,
// config, the auto-start service, and the firewall rule, and stops the service. The actual
// deletion runs in a DETACHED helper (a transient systemd unit on Linux, a background batch
// on Windows) so the still-running agent can remove its own binary and service cleanly.
//
// It is invoked by the `-uninstall` flag and automatically when the manager reports this
// agent as revoked (heartbeat → HTTP 410). Paths mirror internal/agentinstall/install.{sh,ps1}.
func selfUninstall() {
	uninstalling.Store(true)
	if err := spawnUninstaller(); err != nil {
		log.Printf("agent: self-uninstall failed: %v", err)
		return
	}
	log.Printf("agent: self-uninstall scheduled, service & files will be removed shortly")
}
