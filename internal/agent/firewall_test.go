package agent

import (
	"strings"
	"testing"
)

func TestSplitBlockIPs(t *testing.T) {
	v4, v6 := splitBlockIPs([]string{
		"1.2.3.4",
		" 5.6.7.8 ", // the manager's values arrive untrimmed often enough to matter
		"2001:db8::1",
		"::ffff:9.9.9.9", // v4-mapped: belongs in the v4 set, not the v6 one
		"not-an-ip",      // must be skipped, not passed to nft
		"",
	})
	if got := strings.Join(v4, ","); got != "1.2.3.4,5.6.7.8,9.9.9.9" {
		t.Errorf("v4 = %q", got)
	}
	if got := strings.Join(v6, ","); got != "2001:db8::1" {
		t.Errorf("v6 = %q", got)
	}
}

// The regression this guards: one IPv6 address used to go into an `ipv4_addr` set in a single
// transaction, nft rejected the batch, and the host blocked NOTHING while the UI showed the
// block as applied. Both families must land in their own set.
func TestBlocklistRulesetSeparatesFamilies(t *testing.T) {
	rs := blocklistRuleset("deuswatch", "blocklist", []string{"1.2.3.4", "2001:db8::1"})
	for _, want := range []string{
		"set blocklist { type ipv4_addr; elements = { 1.2.3.4 }; }",
		"set blocklist6 { type ipv6_addr; elements = { 2001:db8::1 }; }",
		"ip saddr @blocklist drop",
		"ip6 saddr @blocklist6 drop",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset missing %q:\n%s", want, rs)
		}
	}
	// `add` must precede `delete`, or the first run on a host without the table aborts.
	if strings.Index(rs, "add table inet deuswatch") > strings.Index(rs, "delete table inet deuswatch") {
		t.Errorf("delete comes before add:\n%s", rs)
	}
}

// An empty block list is the steady state on a quiet deployment: it must still produce a valid
// ruleset (empty sets, drop rules in place) rather than a set declaration with a dangling
// `elements = { }`, which nft rejects.
func TestBlocklistRulesetEmpty(t *testing.T) {
	rs := blocklistRuleset("deuswatch", "blocklist", nil)
	if strings.Contains(rs, "elements") {
		t.Errorf("empty list should emit no elements:\n%s", rs)
	}
	if !strings.Contains(rs, "set blocklist { type ipv4_addr; }") {
		t.Errorf("ruleset missing empty v4 set:\n%s", rs)
	}
}
