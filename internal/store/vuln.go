package store

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"deuswatch/internal/vuln"
)

// Vulnerability Assessment phase 2 storage: cached advisories + matcher findings.

// ReplaceAdvisories swaps the cached advisories for one feed source (usn | debian) wholesale, so a
// feed refresh cleanly reflects retractions. Runs in a transaction.
func (s *Store) ReplaceAdvisories(ctx context.Context, source string, advs []vuln.Advisory) error {
	if source == "" {
		return fmt.Errorf("store: advisories need a source")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM advisories WHERE source=$1`, source); err != nil {
		return fmt.Errorf("store: clear advisories: %w", err)
	}
	if len(advs) > 0 {
		// De-dup on the primary key (source, cve, package, release) — a feed can list the same
		// tuple more than once; keep the last.
		seen := make(map[string]int, len(advs))
		rows := make([][]any, 0, len(advs))
		for _, a := range advs {
			if a.CVE == "" || a.Package == "" || a.Release == "" {
				continue
			}
			key := a.CVE + "\x00" + a.Package + "\x00" + a.Release
			row := []any{source, a.CVE, a.Package, a.Release, nilStr(a.FixedVersion), a.Severity, a.Title}
			if i, ok := seen[key]; ok {
				rows[i] = row
				continue
			}
			seen[key] = len(rows)
			rows = append(rows, row)
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"advisories"},
			[]string{"source", "cve", "package", "release", "fixed_version", "severity", "title"},
			pgx.CopyFromRows(rows)); err != nil {
			return fmt.Errorf("store: copy advisories: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// AdvisoryStats reports how many advisories are cached, per release — for the UI/health so an
// operator can see the feed is loaded and for which releases.
func (s *Store) AdvisoryStats(ctx context.Context) (total int, byRelease map[string]int, err error) {
	rows, err := s.pool.Query(ctx, `SELECT release, count(*) FROM advisories GROUP BY release`)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	byRelease = map[string]int{}
	for rows.Next() {
		var rel string
		var n int
		if err := rows.Scan(&rel, &n); err != nil {
			return 0, nil, err
		}
		byRelease[rel] = n
		total += n
	}
	return total, byRelease, rows.Err()
}

// RematchAgent recomputes an agent's vulnerability findings from its current inventory and the
// cached advisories, replacing the stored findings. Returns the number of findings. A missing
// inventory or codename yields 0 (nothing to match against) without error.
func (s *Store) RematchAgent(ctx context.Context, agentName string) (int, error) {
	var codename string
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(os_codename,'') FROM agent_os_inventory WHERE agent_name=$1`, agentName).Scan(&codename)
	if err == pgx.ErrNoRows || codename == "" {
		return 0, s.replaceFindings(ctx, agentName, nil) // clear stale findings, nothing to match
	}
	if err != nil {
		return 0, fmt.Errorf("store: rematch lookup: %w", err)
	}

	// Load the agent's packages.
	prows, err := s.pool.Query(ctx,
		`SELECT name, version, COALESCE(source,'') FROM agent_packages WHERE agent_name=$1`, agentName)
	if err != nil {
		return 0, fmt.Errorf("store: rematch packages: %w", err)
	}
	var pkgs []vuln.InstalledPackage
	names := map[string]bool{}
	for prows.Next() {
		var p vuln.InstalledPackage
		if err := prows.Scan(&p.Name, &p.Version, &p.Source); err != nil {
			prows.Close()
			return 0, err
		}
		pkgs = append(pkgs, p)
		src := p.Source
		if src == "" {
			src = p.Name
		}
		names[src] = true
	}
	prows.Close()
	if err := prows.Err(); err != nil {
		return 0, err
	}
	if len(pkgs) == 0 {
		return 0, s.replaceFindings(ctx, agentName, nil)
	}

	// Load only the advisories for this release AND the agent's source packages — far smaller than
	// the whole release feed.
	srcList := make([]string, 0, len(names))
	for n := range names {
		srcList = append(srcList, n)
	}
	arows, err := s.pool.Query(ctx, `
		SELECT source, cve, package, COALESCE(fixed_version,''), COALESCE(severity,'')
		FROM advisories WHERE release=$1 AND package = ANY($2)`, codename, srcList)
	if err != nil {
		return 0, fmt.Errorf("store: rematch advisories: %w", err)
	}
	advBySrc := map[string][]vuln.Advisory{}
	for arows.Next() {
		var a vuln.Advisory
		if err := arows.Scan(&a.Source, &a.CVE, &a.Package, &a.FixedVersion, &a.Severity); err != nil {
			arows.Close()
			return 0, err
		}
		a.Release = codename
		advBySrc[a.Package] = append(advBySrc[a.Package], a)
	}
	arows.Close()
	if err := arows.Err(); err != nil {
		return 0, err
	}

	findings := vuln.Match(pkgs, advBySrc)
	if err := s.replaceFindings(ctx, agentName, findings); err != nil {
		return 0, err
	}
	return len(findings), nil
}

// replaceFindings swaps an agent's findings wholesale inside a transaction.
func (s *Store) replaceFindings(ctx context.Context, agentName string, findings []vuln.Finding) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM agent_vulnerabilities WHERE agent_name=$1`, agentName); err != nil {
		return fmt.Errorf("store: clear findings: %w", err)
	}
	if len(findings) > 0 {
		seen := make(map[string]bool, len(findings))
		rows := make([][]any, 0, len(findings))
		for _, f := range findings {
			key := f.CVE + "\x00" + f.Package
			if seen[key] {
				continue
			}
			seen[key] = true
			rows = append(rows, []any{agentName, f.CVE, f.Package, nilStr(f.InstalledVersion),
				nilStr(f.FixedVersion), f.Severity, f.Source})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"agent_vulnerabilities"},
			[]string{"agent_name", "cve", "package", "installed_version", "fixed_version", "severity", "source"},
			pgx.CopyFromRows(rows)); err != nil {
			return fmt.Errorf("store: copy findings: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// RematchAll recomputes findings for every agent that has an inventory. Returns how many agents were
// matched. Used after a feed refresh.
func (s *Store) RematchAll(ctx context.Context) (int, error) {
	rows, err := s.pool.Query(ctx, `SELECT agent_name FROM agent_os_inventory`)
	if err != nil {
		return 0, err
	}
	var agents []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			rows.Close()
			return 0, err
		}
		agents = append(agents, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, a := range agents {
		if _, err := s.RematchAgent(ctx, a); err != nil {
			return 0, err
		}
	}
	return len(agents), nil
}

// VulnSummary is one agent's vulnerability headline: counts by severity.
type VulnSummary struct {
	AgentName string    `json:"agent_name"`
	Critical  int       `json:"critical"`
	High      int       `json:"high"`
	Medium    int       `json:"medium"`
	Low       int       `json:"low"`
	Total     int       `json:"total"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListVulnSummaries returns per-agent severity counts (agents with inventory but no findings appear
// with zeros), worst-affected first.
func (s *Store) ListVulnSummaries(ctx context.Context) ([]VulnSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT oi.agent_name,
		  count(*) FILTER (WHERE v.severity='critical'),
		  count(*) FILTER (WHERE v.severity='high'),
		  count(*) FILTER (WHERE v.severity='medium'),
		  count(*) FILTER (WHERE v.severity='low'),
		  count(v.cve),
		  max(oi.updated_at)
		FROM agent_os_inventory oi
		LEFT JOIN agent_vulnerabilities v ON v.agent_name = oi.agent_name
		GROUP BY oi.agent_name`)
	if err != nil {
		return nil, fmt.Errorf("store: vuln summaries: %w", err)
	}
	defer rows.Close()
	out := make([]VulnSummary, 0, 16)
	for rows.Next() {
		var v VulnSummary
		if err := rows.Scan(&v.AgentName, &v.Critical, &v.High, &v.Medium, &v.Low, &v.Total, &v.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Worst first: by critical, then high, then total.
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
	return out, nil
}

// AgentVulnerability is one finding row for the per-agent view.
type AgentVulnerability struct {
	CVE              string `json:"cve"`
	Package          string `json:"package"`
	InstalledVersion string `json:"installed_version"`
	FixedVersion     string `json:"fixed_version"`
	Severity         string `json:"severity"`
	Source           string `json:"source"`
}

// AgentVulnerabilities returns an agent's findings, worst severity first.
func (s *Store) AgentVulnerabilities(ctx context.Context, agentName string) ([]AgentVulnerability, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT cve, package, COALESCE(installed_version,''), COALESCE(fixed_version,''),
		       COALESCE(severity,''), COALESCE(source,'')
		FROM agent_vulnerabilities WHERE agent_name=$1
		ORDER BY CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
		                       WHEN 'low' THEN 2 WHEN 'negligible' THEN 1 ELSE 0 END DESC,
		         package, cve`, agentName)
	if err != nil {
		return nil, fmt.Errorf("store: agent vulns: %w", err)
	}
	defer rows.Close()
	out := make([]AgentVulnerability, 0, 64)
	for rows.Next() {
		var v AgentVulnerability
		if err := rows.Scan(&v.CVE, &v.Package, &v.InstalledVersion, &v.FixedVersion, &v.Severity, &v.Source); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// DistroReleasesInUse returns, per feed source ("usn"/"debian"), the distinct distro release
// codenames the fleet is actually running — so the feed ingester only pulls advisories for
// releases we have agents on. Distros with no supported feed (or no codename) are skipped.
func (s *Store) DistroReleasesInUse(ctx context.Context) (map[string][]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT COALESCE(os_id,''), COALESCE(os_codename,'')
		FROM agent_os_inventory WHERE COALESCE(os_codename,'') <> ''`)
	if err != nil {
		return nil, fmt.Errorf("store: distros in use: %w", err)
	}
	defer rows.Close()
	bySource := map[string]map[string]bool{}
	for rows.Next() {
		var osID, codename string
		if err := rows.Scan(&osID, &codename); err != nil {
			return nil, err
		}
		src := vuln.FeedForDistro(osID)
		if src == "" {
			continue
		}
		if bySource[src] == nil {
			bySource[src] = map[string]bool{}
		}
		bySource[src][codename] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for src, set := range bySource {
		for rel := range set {
			out[src] = append(out[src], rel)
		}
	}
	return out, nil
}

func nilStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
