//go:build linux

package agent

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// isolationTable is the dedicated nftables table for host containment. It is separate from
// the auto-block table so isolation can be applied/cleared without touching the blocklist.
const isolationTable = "deuswatch_containment"

// ApplyIsolation isolates the host from the network: it installs base chains (input/output/
// forward) with a DROP policy that permit ONLY loopback, established/related flows, and the
// allowIPs (the manager/gateway + allow-list) — everything else on the LAN is cut off. This
// stops a compromised host from reaching servers, storage or peers while keeping its link to
// the manager alive. Idempotent (re-applying replaces the ruleset atomically). Linux only,
// requires root / CAP_NET_ADMIN.
func ApplyIsolation(allowIPs []string) error {
	var v4, v6 []string
	for _, s := range allowIPs {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}

	var b strings.Builder
	// Atomic idempotent flush: ensure the table exists, delete it, then recreate — all in one
	// `nft -f` transaction so there is never a window with half a ruleset.
	fmt.Fprintf(&b, "add table inet %s\n", isolationTable)
	fmt.Fprintf(&b, "delete table inet %s\n", isolationTable)
	fmt.Fprintf(&b, "table inet %s {\n", isolationTable)
	b.WriteString("  set allow4 { type ipv4_addr; ")
	if len(v4) > 0 {
		fmt.Fprintf(&b, "elements = { %s }; ", strings.Join(v4, ", "))
	}
	b.WriteString("}\n")
	b.WriteString("  set allow6 { type ipv6_addr; ")
	if len(v6) > 0 {
		fmt.Fprintf(&b, "elements = { %s }; ", strings.Join(v6, ", "))
	}
	b.WriteString("}\n")
	// priority -150: run before ordinary filter chains so the DROP policy governs the host.
	b.WriteString("  chain input { type filter hook input priority -150; policy drop;\n")
	b.WriteString("    iif lo accept\n    ct state established,related accept\n")
	b.WriteString("    ip saddr @allow4 accept\n    ip6 saddr @allow6 accept\n  }\n")
	b.WriteString("  chain output { type filter hook output priority -150; policy drop;\n")
	b.WriteString("    oif lo accept\n    ct state established,related accept\n")
	b.WriteString("    ip daddr @allow4 accept\n    ip6 daddr @allow6 accept\n  }\n")
	b.WriteString("  chain forward { type filter hook forward priority -150; policy drop; }\n")
	b.WriteString("}\n")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(b.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft apply isolation: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ClearIsolation removes the containment table, restoring normal connectivity. Safe to call
// when not isolated (a missing table is not an error).
func ClearIsolation() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Ignore the error: the table is simply absent when the host was never isolated.
	_ = exec.CommandContext(ctx, "nft", "delete", "table", "inet", isolationTable).Run()
	return nil
}
