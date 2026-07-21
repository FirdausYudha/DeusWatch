package store

import (
	"context"
	"testing"
	"time"

	"deuswatch/internal/agent"
)

// TestInventoryRoundTrip proves the store side of VA phase 1: an agent's inventory is stored,
// summarized, filtered, and — crucially — REPLACED wholesale on re-report (a removed package must
// vanish, not linger, or phase-2 matching would flag vulnerabilities that are no longer installed).
func TestInventoryRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := Connect(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable — skipping: %v", err)
	}
	defer st.Close()

	const agentName = "invtest01"
	cleanup := func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM agent_packages WHERE agent_name=$1`, agentName)
		_, _ = st.pool.Exec(ctx, `DELETE FROM agent_os_inventory WHERE agent_name=$1`, agentName)
	}
	cleanup()
	defer cleanup()

	inv := agent.Inventory{
		OSID: "ubuntu", OSVersion: "22.04", OSCodename: "jammy",
		Kernel: "5.15.0-101-generic", Arch: "amd64", PkgManager: "dpkg",
		Packages: []agent.Package{
			{Name: "libssl3", Version: "3.0.2-0ubuntu1.15", Arch: "amd64", Source: "openssl"},
			{Name: "nginx-core", Version: "1.18.0-6ubuntu14.4", Arch: "amd64", Source: "nginx"},
			{Name: "bash", Version: "5.1-6ubuntu1", Arch: "amd64"},
		},
	}
	if err := st.ReplaceInventory(ctx, agentName, inv); err != nil {
		t.Fatalf("ReplaceInventory: %v", err)
	}

	// Summary reflects the OS row + package count.
	sums, err := st.ListInventorySummaries(ctx)
	if err != nil {
		t.Fatalf("ListInventorySummaries: %v", err)
	}
	var got *InventorySummary
	for i := range sums {
		if sums[i].AgentName == agentName {
			got = &sums[i]
		}
	}
	if got == nil {
		t.Fatalf("inventory summary not found for %s", agentName)
	}
	if got.OSCodename != "jammy" || got.PkgManager != "dpkg" || got.PkgCount != 3 {
		t.Fatalf("summary wrong: %+v", got)
	}

	// The source-package filter is what phase-2 matching keys on: searching "openssl" must find
	// libssl3 even though its binary name doesn't contain it.
	byOpenssl, err := st.GetAgentPackages(ctx, agentName, "openssl")
	if err != nil {
		t.Fatalf("GetAgentPackages(openssl): %v", err)
	}
	if len(byOpenssl) != 1 || byOpenssl[0].Name != "libssl3" {
		t.Fatalf("source filter failed: %+v", byOpenssl)
	}

	// Re-report WITHOUT nginx: it must disappear (snapshot semantics), and the count must drop.
	inv2 := inv
	inv2.Packages = []agent.Package{
		{Name: "libssl3", Version: "3.0.2-0ubuntu1.16", Arch: "amd64", Source: "openssl"}, // patched
		{Name: "bash", Version: "5.1-6ubuntu1", Arch: "amd64"},
	}
	if err := st.ReplaceInventory(ctx, agentName, inv2); err != nil {
		t.Fatalf("ReplaceInventory (2): %v", err)
	}
	all, err := st.GetAgentPackages(ctx, agentName, "")
	if err != nil {
		t.Fatalf("GetAgentPackages(all): %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 packages after re-report, got %d: %+v", len(all), all)
	}
	for _, p := range all {
		if p.Name == "nginx-core" {
			t.Fatal("a removed package must not linger after re-report")
		}
		if p.Name == "libssl3" && p.Version != "3.0.2-0ubuntu1.16" {
			t.Fatalf("re-report must update the version, got %q", p.Version)
		}
	}
}
