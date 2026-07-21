package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"deuswatch/internal/agent"
)

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
// inside a transaction — a package the agent no longer has simply disappears.
func (s *Store) ReplaceInventory(ctx context.Context, agentName string, inv agent.Inventory) error {
	if agentName == "" {
		return fmt.Errorf("store: inventory needs an agent name")
	}
	tx, err := s.pool.Begin(ctx)
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
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: inventory commit: %w", err)
	}
	return nil
}

// ListInventorySummaries returns every agent's OS/package headline, newest report first.
func (s *Store) ListInventorySummaries(ctx context.Context) ([]InventorySummary, error) {
	rows, err := s.pool.Query(ctx, `
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
	rows, err := s.pool.Query(ctx, `
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
