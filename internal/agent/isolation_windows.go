//go:build windows

package agent

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// isolationRule is the name of the Windows Firewall allow rules DeusWatch installs while a
// host is contained (used so ClearIsolation can remove exactly them).
const isolationRule = "DeusWatch-Containment-Allow"

// ApplyIsolation isolates the host via Windows Firewall (netsh advfirewall): it sets the
// default policy to block inbound AND outbound on all profiles, then adds allow rules for the
// manager/gateway + allow-list IPs so the agent keeps its link to the manager. Everything else
// is cut off. Idempotent. Requires Administrator.
func ApplyIsolation(allowIPs []string) error {
	remote := joinIPs(allowIPs)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Refresh our allow rules from scratch so re-applying with a new allow-list is clean.
	_ = netsh(ctx, "advfirewall", "firewall", "delete", "rule", "name="+isolationRule)

	// Block everything by default on every profile.
	if err := netsh(ctx, "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"); err != nil {
		return err
	}
	if remote == "" {
		return nil // no allow-list — fully blocked (caller normally includes the gateway IP)
	}
	// Permit the manager/allow-list in both directions so the agent↔manager channel survives.
	if err := netsh(ctx, "advfirewall", "firewall", "add", "rule", "name="+isolationRule,
		"dir=out", "action=allow", "remoteip="+remote); err != nil {
		return err
	}
	if err := netsh(ctx, "advfirewall", "firewall", "add", "rule", "name="+isolationRule,
		"dir=in", "action=allow", "remoteip="+remote); err != nil {
		return err
	}
	return nil
}

// ClearIsolation removes the containment allow rules and restores the default firewall policy
// (block inbound, allow outbound — the Windows default). Safe to call when not isolated.
func ClearIsolation() error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = netsh(ctx, "advfirewall", "firewall", "delete", "rule", "name="+isolationRule)
	return netsh(ctx, "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound")
}

func netsh(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "netsh", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// joinIPs validates and comma-joins IPs for a netsh remoteip= argument.
func joinIPs(ips []string) string {
	var valid []string
	for _, s := range ips {
		if net.ParseIP(strings.TrimSpace(s)) != nil {
			valid = append(valid, strings.TrimSpace(s))
		}
	}
	return strings.Join(valid, ",")
}
