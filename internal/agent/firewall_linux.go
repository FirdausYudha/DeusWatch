//go:build linux

package agent

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ApplyBlocklist syncs the given IPs into local nftables sets, so matching source traffic is
// dropped before it reaches any service on the host. Covers IPv4 and IPv6. Idempotent: the
// table is replaced atomically on every call, so this both installs and reconciles.
// Requires root / CAP_NET_ADMIN. Linux only.
func ApplyBlocklist(table, set string, ips []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(blocklistRuleset(table, set, ips))
	// CombinedOutput rather than Run: `nft` explains every refusal on stderr, and throwing that
	// away was what reduced a real diagnosis to a bare "exit status 1" plus a manual-reproduction
	// checklist in the docs.
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft apply blocklist: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
