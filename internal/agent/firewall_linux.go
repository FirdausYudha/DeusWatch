//go:build linux

package agent

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ApplyBlocklist syncs the given IPs into a local nftables set, ensuring the table,
// set, input chain and a drop rule referencing the set exist (idempotent) so matching
// source traffic is dropped. Requires root / CAP_NET_ADMIN. Linux only.
func ApplyBlocklist(table, set string, ips []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Ensure table / set / chain exist (errors when already present are ignored).
	_ = nft(ctx, "add", "table", "inet", table)
	_ = nft(ctx, "add", "set", "inet", table, set, "{", "type", "ipv4_addr;", "}")
	_ = nft(ctx, "add", "chain", "inet", table, "input", "{", "type", "filter", "hook", "input", "priority", "0;", "policy", "accept;", "}")

	// Add the drop rule only if the chain doesn't already reference the set.
	if out, _ := nftOutput(ctx, "list", "chain", "inet", table, "input"); !strings.Contains(out, "@"+set) {
		_ = nft(ctx, "add", "rule", "inet", table, "input", "ip", "saddr", "@"+set, "drop")
	}

	// Sync set contents: flush then re-add the current IPs.
	if err := nft(ctx, "flush", "set", "inet", table, set); err != nil {
		return fmt.Errorf("nft flush set: %w", err)
	}
	if len(ips) > 0 {
		if err := nft(ctx, "add", "element", "inet", table, set, "{", strings.Join(ips, ", "), "}"); err != nil {
			return fmt.Errorf("nft add element: %w", err)
		}
	}
	return nil
}

func nft(ctx context.Context, args ...string) error {
	return exec.CommandContext(ctx, "nft", args...).Run()
}

func nftOutput(ctx context.Context, args ...string) (string, error) {
	b, err := exec.CommandContext(ctx, "nft", args...).Output()
	return string(b), err
}
