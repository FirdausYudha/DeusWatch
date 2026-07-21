package store

import (
	"context"
	"testing"
	"time"

	"deuswatch/internal/agent"
	"deuswatch/internal/vuln"
)

// TestVulnMatchRoundTrip is the end-to-end store side of VA phase 2: load an agent's inventory,
// cache advisories, run the matcher, and read back the findings — proving the whole join
// (inventory × advisories → findings) against real Postgres and the dpkg version comparison.
func TestVulnMatchRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := Connect(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable — skipping: %v", err)
	}
	defer st.Close()

	const agentName = "vulntest01"
	cleanup := func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM agent_packages WHERE agent_name=$1`, agentName)
		_, _ = st.pool.Exec(ctx, `DELETE FROM agent_os_inventory WHERE agent_name=$1`, agentName)
		_, _ = st.pool.Exec(ctx, `DELETE FROM agent_vulnerabilities WHERE agent_name=$1`, agentName)
		_, _ = st.pool.Exec(ctx, `DELETE FROM advisories WHERE source='test-feed'`)
	}
	cleanup()
	defer cleanup()

	// Inventory: an Ubuntu jammy host with an out-of-date openssl and an up-to-date nginx.
	inv := agent.Inventory{
		OSID: "ubuntu", OSVersion: "22.04", OSCodename: "jammy", Arch: "amd64", PkgManager: "dpkg",
		Packages: []agent.Package{
			{Name: "libssl3", Version: "3.0.2-0ubuntu1.15", Arch: "amd64", Source: "openssl"},
			{Name: "nginx-core", Version: "1.18.0-6ubuntu14.5", Arch: "amd64", Source: "nginx"},
		},
	}
	if err := st.ReplaceInventory(ctx, agentName, inv); err != nil {
		t.Fatalf("ReplaceInventory: %v", err)
	}

	// Advisories: openssl vulnerable (fix newer than installed), nginx already patched.
	advs := []vuln.Advisory{
		{Source: "test-feed", CVE: "CVE-2023-0286", Package: "openssl", Release: "jammy", FixedVersion: "3.0.2-0ubuntu1.16", Severity: "high"},
		{Source: "test-feed", CVE: "CVE-2021-23017", Package: "nginx", Release: "jammy", FixedVersion: "1.18.0-6ubuntu14.4", Severity: "critical"},
		// A different release must NOT match this jammy host.
		{Source: "test-feed", CVE: "CVE-2099-0001", Package: "openssl", Release: "focal", FixedVersion: "9.9.9", Severity: "critical"},
	}
	if err := st.ReplaceAdvisories(ctx, "test-feed", advs); err != nil {
		t.Fatalf("ReplaceAdvisories: %v", err)
	}

	n, err := st.RematchAgent(ctx, agentName)
	if err != nil {
		t.Fatalf("RematchAgent: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 finding (openssl only), got %d", n)
	}

	vulns, err := st.AgentVulnerabilities(ctx, agentName)
	if err != nil {
		t.Fatalf("AgentVulnerabilities: %v", err)
	}
	if len(vulns) != 1 || vulns[0].CVE != "CVE-2023-0286" || vulns[0].Package != "openssl" {
		t.Fatalf("wrong findings: %+v", vulns)
	}
	if vulns[0].FixedVersion != "3.0.2-0ubuntu1.16" || vulns[0].Severity != "high" {
		t.Fatalf("finding detail wrong: %+v", vulns[0])
	}

	// Summary reflects one high finding for the agent.
	sums, err := st.ListVulnSummaries(ctx)
	if err != nil {
		t.Fatalf("ListVulnSummaries: %v", err)
	}
	found := false
	for _, s := range sums {
		if s.AgentName == agentName {
			found = true
			if s.High != 1 || s.Critical != 0 || s.Total != 1 {
				t.Fatalf("summary wrong: %+v", s)
			}
		}
	}
	if !found {
		t.Fatal("agent missing from vuln summary")
	}

	// Patch openssl in the inventory and re-match: the finding must clear (proving remediation shows).
	inv.Packages[0].Version = "3.0.2-0ubuntu1.16"
	if err := st.ReplaceInventory(ctx, agentName, inv); err != nil {
		t.Fatalf("ReplaceInventory (patched): %v", err)
	}
	n, err = st.RematchAgent(ctx, agentName)
	if err != nil {
		t.Fatalf("RematchAgent (patched): %v", err)
	}
	if n != 0 {
		t.Fatalf("after patching openssl the finding must clear, got %d", n)
	}
}
