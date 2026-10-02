package agent

import (
	"fmt"
	"net"
	"strings"
)

// splitBlockIPs sorts the manager's block list into IPv4 and IPv6 literals, dropping anything
// that does not parse as an address.
//
// Both halves matter. An nftables set is single-family (`type ipv4_addr` cannot hold an IPv6
// address) and a reconcile adds every element in ONE transaction, so a single IPv6 entry in a
// v4-only set failed the whole batch and left the host blocking NOTHING at all. The manager
// stores blocks in a Postgres `inet` column, so an IPv6 source is ordinary rather than exotic.
func splitBlockIPs(ips []string) (v4, v6 []string) {
	for _, s := range ips {
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
	return v4, v6
}

// blocklistRuleset renders the complete nftables table for the agent-side block list, to be fed
// to `nft -f -`. It lives here, apart from the Linux-only exec, so the generated ruleset is
// testable on any platform.
//
// The table is replaced wholesale (add, delete, recreate) inside one transaction. That is both
// shorter than the previous add-set / flush-set / add-element sequence and strictly safer: there
// is never a window where the host is unprotected, a reconcile cannot half-apply, and a set left
// behind by an older agent with the wrong element type is repaired instead of silently rejected.
func blocklistRuleset(table, set string, ips []string) string {
	v4, v6 := splitBlockIPs(ips)
	set6 := set + "6"

	var b strings.Builder
	// `add` before `delete` so the delete cannot fail on a table that does not exist yet, which
	// would abort the whole transaction on a first run.
	fmt.Fprintf(&b, "add table inet %s\n", table)
	fmt.Fprintf(&b, "delete table inet %s\n", table)
	fmt.Fprintf(&b, "table inet %s {\n", table)
	writeBlockSet(&b, set, "ipv4_addr", v4)
	writeBlockSet(&b, set6, "ipv6_addr", v6)
	// policy accept with an explicit drop: this table blocks exactly what the manager listed and
	// must never become the thing that decides what else the host is allowed to do.
	b.WriteString("  chain input { type filter hook input priority 0; policy accept;\n")
	fmt.Fprintf(&b, "    ip saddr @%s drop\n", set)
	fmt.Fprintf(&b, "    ip6 saddr @%s drop\n", set6)
	b.WriteString("  }\n}\n")
	return b.String()
}

func writeBlockSet(b *strings.Builder, name, typ string, elems []string) {
	fmt.Fprintf(b, "  set %s { type %s; ", name, typ)
	if len(elems) > 0 {
		fmt.Fprintf(b, "elements = { %s }; ", strings.Join(elems, ", "))
	}
	b.WriteString("}\n")
}
