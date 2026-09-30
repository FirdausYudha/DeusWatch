package store

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"deuswatch/internal/agent"
)

// sortSCASummaries orders agents worst-first: by critical, then high, then total.
func sortSCASummaries(out []SCASummary) {
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Critical != b.Critical {
			return a.Critical > b.Critical
		}
		if a.High != b.High {
			return a.High > b.High
		}
		return a.Total > b.Total
	})
}

// Software inventory storage (Vulnerability Assessment, phase 1).

// InventorySummary is one agent's OS/package headline, for the fleet list.
type InventorySummary struct {
	AgentName  string    `json:"agent_name"`
	OSID       string    `json:"os_id"`
	OSVersion  string    `json:"os_version"`
	OSCodename string    `json:"os_codename"`
	Kernel     string    `json:"kernel"`
	Arch       string    `json:"arch"`
	PkgManager string    `json:"pkg_manager"`
	PkgCount   int       `json:"pkg_count"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// ReplaceInventory stores an agent's full inventory, replacing any previous one atomically. An
// inventory is a point-in-time SNAPSHOT (not an append log), so the package set is swapped wholesale
// inside a transaction, a package the agent no longer has simply disappears.
func (s *Store) ReplaceInventory(ctx context.Context, agentName string, inv agent.Inventory) error {
	if agentName == "" {
		return fmt.Errorf("store: inventory needs an agent name")
	}
	tx, err := s.q(ctx).Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: inventory begin: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_os_inventory
		  (agent_name, os_id, os_version, os_codename, kernel, arch, pkg_manager, pkg_count, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now())
		ON CONFLICT (agent_name) DO UPDATE SET
		  os_id=EXCLUDED.os_id, os_version=EXCLUDED.os_version, os_codename=EXCLUDED.os_codename,
		  kernel=EXCLUDED.kernel, arch=EXCLUDED.arch, pkg_manager=EXCLUDED.pkg_manager,
		  pkg_count=EXCLUDED.pkg_count, updated_at=now()`,
		agentName, inv.OSID, inv.OSVersion, inv.OSCodename, inv.Kernel, inv.Arch,
		inv.PkgManager, len(inv.Packages)); err != nil {
		return fmt.Errorf("store: inventory os upsert: %w", err)
	}

	if _, err := tx.Exec(ctx, `DELETE FROM agent_packages WHERE agent_name=$1`, agentName); err != nil {
		return fmt.Errorf("store: inventory clear packages: %w", err)
	}
	if len(inv.Packages) > 0 {
		rows := make([][]any, 0, len(inv.Packages))
		// De-duplicate on the primary key (agent, name, arch): dpkg can list the same name for
		// multiple arches, but an identical (name,arch) twice would break the COPY, so keep last.
		seen := make(map[string]int, len(inv.Packages))
		for _, p := range inv.Packages {
			if p.Name == "" || p.Version == "" {
				continue
			}
			key := p.Name + "\x00" + p.Arch
			row := []any{agentName, p.Name, p.Version, p.Arch, p.Source}
			if i, ok := seen[key]; ok {
				rows[i] = row
				continue
			}
			seen[key] = len(rows)
			rows = append(rows, row)
		}
		if _, err := tx.CopyFrom(ctx,
			pgx.Identifier{"agent_packages"},
			[]string{"agent_name", "name", "version", "arch", "source"},
			pgx.CopyFromRows(rows)); err != nil {
			return fmt.Errorf("store: inventory copy packages: %w", err)
		}
	}
	// SCA manifests (language dependency files) — snapshot, replaced wholesale like packages.
	if _, err := tx.Exec(ctx, `DELETE FROM agent_manifests WHERE agent_name=$1`, agentName); err != nil {
		return fmt.Errorf("store: inventory clear manifests: %w", err)
	}
	if len(inv.Manifests) > 0 {
		seen := make(map[string]int, len(inv.Manifests))
		rows := make([][]any, 0, len(inv.Manifests))
		for _, m := range inv.Manifests {
			if m.Path == "" || m.Content == "" {
				continue
			}
			row := []any{agentName, m.Path, m.Content}
			if i, ok := seen[m.Path]; ok {
				rows[i] = row
				continue
			}
			seen[m.Path] = len(rows)
			rows = append(rows, row)
		}
		if _, err := tx.CopyFrom(ctx,
			pgx.Identifier{"agent_manifests"},
			[]string{"agent_name", "path", "content"},
			pgx.CopyFromRows(rows)); err != nil {
			return fmt.Errorf("store: inventory copy manifests: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: inventory commit: %w", err)
	}
	return nil
}

// Manifest is one stored dependency file for SCA.
type Manifest struct {
	Path    string
	Content string
}

// AgentManifests returns an agent's stored dependency manifests, for the Trivy SCA scan.
func (s *Store) AgentManifests(ctx context.Context, agentName string) ([]Manifest, error) {
	rows, err := s.q(ctx).Query(ctx, `SELECT path, content FROM agent_manifests WHERE agent_name=$1`, agentName)
	if err != nil {
		return nil, fmt.Errorf("store: agent manifests: %w", err)
	}
	defer rows.Close()
	var out []Manifest
	for rows.Next() {
		var m Manifest
		if err := rows.Scan(&m.Path, &m.Content); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// SCAFinding is one vulnerable language package in a manifest.
type SCAFinding struct {
	Target           string  `json:"target"`
	PkgType          string  `json:"pkg_type"`
	Package          string  `json:"package"`
	InstalledVersion string  `json:"installed_version"`
	FixedVersion     string  `json:"fixed_version"`
	VulnID           string  `json:"vuln_id"`
	Severity         string  `json:"severity"`
	CVSS             float64 `json:"cvss"`
}

// ReplaceSCAFindings swaps an agent's SCA findings wholesale inside a transaction.
func (s *Store) ReplaceSCAFindings(ctx context.Context, agentName string, findings []SCAFinding) error {
	tx, err := s.q(ctx).Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM agent_sca_findings WHERE agent_name=$1`, agentName); err != nil {
		return fmt.Errorf("store: clear sca findings: %w", err)
	}
	if len(findings) > 0 {
		seen := make(map[string]bool, len(findings))
		rows := make([][]any, 0, len(findings))
		for _, f := range findings {
			if f.VulnID == "" || f.Package == "" {
				continue
			}
			key := f.VulnID + "\x00" + f.Package + "\x00" + f.InstalledVersion
			if seen[key] {
				continue
			}
			seen[key] = true
			rows = append(rows, []any{agentName, f.Target, f.PkgType, f.Package,
				f.InstalledVersion, nilStr(f.FixedVersion), f.VulnID, f.Severity, nilFloat(f.CVSS)})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"agent_sca_findings"},
			[]string{"agent_name", "target", "pkg_type", "pkg_name", "installed_version", "fixed_version", "vuln_id", "severity", "cvss"},
			pgx.CopyFromRows(rows)); err != nil {
			return fmt.Errorf("store: copy sca findings: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// SCASummary is one agent's SCA headline: dependency-vuln counts by severity.
type SCASummary struct {
	AgentName string    `json:"agent_name"`
	Critical  int       `json:"critical"`
	High      int       `json:"high"`
	Medium    int       `json:"medium"`
	Low       int       `json:"low"`
	Unknown   int       `json:"unknown"`
	Total     int       `json:"total"`
	Manifests int       `json:"manifests"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListSCASummaries returns per-agent SCA severity counts (agents with manifests but no findings show
// zeros), worst-affected first. Agents that reported at least one manifest are included.
func (s *Store) ListSCASummaries(ctx context.Context) ([]SCASummary, error) {
	rows, err := s.q(ctx).Query(ctx, `
		SELECT m.agent_name,
		  count(*) FILTER (WHERE f.severity='critical'),
		  count(*) FILTER (WHERE f.severity='high'),
		  count(*) FILTER (WHERE f.severity='medium'),
		  count(*) FILTER (WHERE f.severity='low'),
		  count(*) FILTER (WHERE f.vuln_id IS NOT NULL AND (f.severity IS NULL OR f.severity='' OR f.severity='unknown' OR f.severity='negligible')),
		  count(f.vuln_id),
		  count(DISTINCT m.path),
		  max(m.updated_at)
		FROM agent_manifests m
		LEFT JOIN agent_sca_findings f ON f.agent_name = m.agent_name
		GROUP BY m.agent_name`)
	if err != nil {
		return nil, fmt.Errorf("store: sca summaries: %w", err)
	}
	defer rows.Close()
	out := make([]SCASummary, 0, 16)
	for rows.Next() {
		var v SCASummary
		if err := rows.Scan(&v.AgentName, &v.Critical, &v.High, &v.Medium, &v.Low, &v.Unknown, &v.Total, &v.Manifests, &v.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortSCASummaries(out)
	return out, nil
}

// AgentSCAFindings returns an agent's SCA findings, worst severity first.
func (s *Store) AgentSCAFindings(ctx context.Context, agentName string) ([]SCAFinding, error) {
	rows, err := s.q(ctx).Query(ctx, `
		SELECT COALESCE(target,''), COALESCE(pkg_type,''), pkg_name, COALESCE(installed_version,''),
		       COALESCE(fixed_version,''), vuln_id, COALESCE(severity,''), COALESCE(cvss,0)
		FROM agent_sca_findings WHERE agent_name=$1
		ORDER BY CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
		                       WHEN 'low' THEN 2 WHEN 'negligible' THEN 1 ELSE 0 END DESC,
		         COALESCE(cvss,0) DESC, pkg_name, vuln_id`, agentName)
	if err != nil {
		return nil, fmt.Errorf("store: agent sca findings: %w", err)
	}
	defer rows.Close()
	out := make([]SCAFinding, 0, 64)
	for rows.Next() {
		var f SCAFinding
		if err := rows.Scan(&f.Target, &f.PkgType, &f.Package, &f.InstalledVersion, &f.FixedVersion, &f.VulnID, &f.Severity, &f.CVSS); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ListInventorySummaries returns every agent's OS/package headline, newest report first.
func (s *Store) ListInventorySummaries(ctx context.Context) ([]InventorySummary, error) {
	rows, err := s.q(ctx).Query(ctx, `
		SELECT agent_name, COALESCE(os_id,''), COALESCE(os_version,''), COALESCE(os_codename,''),
		       COALESCE(kernel,''), COALESCE(arch,''), COALESCE(pkg_manager,''), pkg_count, updated_at
		FROM agent_os_inventory ORDER BY updated_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list inventory: %w", err)
	}
	defer rows.Close()
	out := make([]InventorySummary, 0, 16)
	for rows.Next() {
		var s InventorySummary
		if err := rows.Scan(&s.AgentName, &s.OSID, &s.OSVersion, &s.OSCodename, &s.Kernel,
			&s.Arch, &s.PkgManager, &s.PkgCount, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetAgentPackages returns one agent's installed packages (alphabetical), optionally filtered by a
// case-insensitive substring of the package or source name.
func (s *Store) GetAgentPackages(ctx context.Context, agentName, filter string) ([]agent.Package, error) {
	rows, err := s.q(ctx).Query(ctx, `
		SELECT name, version, COALESCE(arch,''), COALESCE(source,'')
		FROM agent_packages
		WHERE agent_name=$1
		  AND ($2='' OR name ILIKE '%'||$2||'%' OR source ILIKE '%'||$2||'%')
		ORDER BY name`, agentName, filter)
	if err != nil {
		return nil, fmt.Errorf("store: get packages: %w", err)
	}
	defer rows.Close()
	out := make([]agent.Package, 0, 256)
	for rows.Next() {
		var p agent.Package
		if err := rows.Scan(&p.Name, &p.Version, &p.Arch, &p.Source); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
