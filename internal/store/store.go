// Package store is the repository layer over PostgreSQL + TimescaleDB.
// All log writes go through here; queries are always parameterized (design doc section 4).
package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"deuswatch/internal/ingest"
	"deuswatch/internal/tenancy"
)

// Store holds the Postgres connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// Queryer is the subset of database operations the store's methods use. Both *pgxpool.Pool and
// pgx.Tx satisfy it, so a method runs either unscoped (directly on the pool) or scoped (inside a
// tenant transaction opened by WithTenantScope). Methods use s.q(ctx) instead of s.pool directly.
type Queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Begin(context.Context) (pgx.Tx, error)
}

// q returns the scoped transaction carried in ctx (opened by WithTenantScope) if one is present,
// otherwise the raw pool. Every store data method routes through this so tenant scoping is applied
// transparently without changing method signatures or callers. The scope tx lives in the shared
// tenancy package key so sibling stores (enroll, tickets) run in the SAME scoped transaction.
func (s *Store) q(ctx context.Context) Queryer {
	if tx, ok := tenancy.TxFrom(ctx); ok {
		return tx
	}
	return s.pool
}

// WithTenantScope runs fn inside a transaction whose session GUCs carry the tenant scope, so
// Postgres RLS (enabled in migration 000050) filters every query to these tenants. `set_config(...,
// true)` makes the GUCs transaction-LOCAL, auto-reset on commit/rollback — no leakage across pooled
// connections. superadmin=true (worker / platform admin) sets the bypass GUC; its SQL must still be
// tenant-aware. fn receives a ctx carrying the transaction; store methods called with it run scoped.
// The handler signals its own errors (HTTP status), so a nil return commits — partial writes on a
// mid-handler failure are no worse than today's autocommit-per-call behaviour.
func (s *Store) WithTenantScope(ctx context.Context, tenantIDs []string, superadmin bool, fn func(context.Context) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin scope: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	super := "0"
	if superadmin {
		super = "1"
	}
	if _, err := tx.Exec(ctx,
		`SELECT set_config('deuswatch.tenant_ids', $1, true), set_config('deuswatch.superadmin', $2, true)`,
		strings.Join(tenantIDs, ","), super); err != nil {
		return fmt.Errorf("store: set scope: %w", err)
	}
	// For a non-super-admin scope, drop to the restricted deuswatch_app role for the rest of this
	// transaction (migration 000051). RLS is ignored for superusers/BYPASSRLS roles, and the app
	// connects as a superuser bootstrap role — so without assuming a constrained role, scoped reads
	// would silently bypass isolation. SET LOCAL reverts automatically on commit/rollback. Super-admin
	// scopes (worker, gateway, platform admin, system feeds) intentionally keep the privileged role.
	if !superadmin {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE deuswatch_app`); err != nil {
			return fmt.Errorf("store: assume app role: %w", err)
		}
	}
	if err := fn(tenancy.WithTx(ctx, tx)); err != nil {
		return err
	}
	committed = true
	return tx.Commit(ctx)
}

// Connect opens a pool to dsn and verifies connectivity.
func Connect(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// ConnectSuperadmin is Connect for trusted system processes (worker, gateway) that legitimately span
// every tenant. Each pooled connection is opened with the RLS super-admin bypass set at the session
// level, so all their queries see and write across tenants without wrapping every call in a scope.
// The super-admin GUC means "spans all tenants", NOT "may merge them" — tenant-partitioning SQL
// (e.g. worker scorers GROUP BY tenant_id) is still required to avoid cross-tenant blending.
// The API process must NOT use this: it connects with Connect and scopes each request transaction.
func ConnectSuperadmin(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET deuswatch.superadmin = '1'`)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// rlsForcedTables are the tenant-scoped data tables that migration 000050 puts under FORCE ROW LEVEL
// SECURITY. All are reached exclusively through this store's s.q(ctx) plumbing, so a scoped request
// transaction filters them and an unscoped path (empty GUC) sees zero rows — fail-closed. Tables
// owned by sibling packages that lack scope plumbing (respond → response_actions/containment_actions,
// tickets → tickets, enroll → agents) are intentionally excluded until those packages are scoped.
//
// `events` is excluded from this list because it cannot carry RLS: TimescaleDB 2.17 makes columnar
// compression and RLS mutually exclusive, and events depends on compression. It is isolated instead by
// a security-barrier VIEW over the events_data hypertable (migration 000052), verified separately in
// AssertRLSEnforced.
var rlsForcedTables = []string{
	"fim_snapshots", "agent_file_actions", "file_restores",
	"agent_os_inventory", "agent_packages", "agent_vulnerabilities",
	"ip_scores", "suspicious_ips", "slow_scanners", "ip_anomaly",
	// Phase 5 (migration 000054): sibling-store tables now scoped via the shared tenancy tx.
	"agents", "agent_enroll_tokens", "tickets",
}

// AssertRLSEnforced verifies that every tenant-scoped table actually has ROW LEVEL SECURITY both
// ENABLED and FORCED. The API connects as the table owner, for whom RLS is ignored unless FORCEd —
// so a half-applied or missing migration 000050 would mean the store's scoped reads silently return
// unfiltered, cross-tenant rows. This is the "silent total leak" footgun; the API calls this at boot
// and refuses to start if isolation is not actually in force.
func (s *Store) AssertRLSEnforced(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `
		SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relname = ANY($1)`, rlsForcedTables)
	if err != nil {
		return fmt.Errorf("store: check RLS: %w", err)
	}
	defer rows.Close()
	seen := make(map[string]bool, len(rlsForcedTables))
	for rows.Next() {
		var name string
		var enabled, forced bool
		if err := rows.Scan(&name, &enabled, &forced); err != nil {
			return err
		}
		if !enabled || !forced {
			return fmt.Errorf("store: table %q does not have RLS enabled+forced (enabled=%v forced=%v) — tenant isolation is NOT active; apply migration 000050", name, enabled, forced)
		}
		seen[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, t := range rlsForcedTables {
		if !seen[t] {
			return fmt.Errorf("store: tenant-scoped table %q not found — cannot verify RLS; is the schema migrated?", t)
		}
	}
	// The restricted role that scoped request transactions assume (migration 000051) must exist and
	// must NOT be able to bypass RLS — a SUPERUSER or BYPASSRLS role would render every policy above
	// inert (the "silent total leak" footgun). Refuse to run if it is missing or over-privileged.
	var rolsuper, rolbypass bool
	if err := s.pool.QueryRow(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'deuswatch_app'`).
		Scan(&rolsuper, &rolbypass); err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("store: role deuswatch_app is missing — apply migration 000051; scoped reads cannot be isolated without it")
		}
		return fmt.Errorf("store: check app role: %w", err)
	}
	if rolsuper || rolbypass {
		return fmt.Errorf("store: role deuswatch_app can bypass RLS (superuser=%v bypassrls=%v) — tenant isolation would be silently disabled", rolsuper, rolbypass)
	}
	// events cannot carry RLS (compression conflict); it is isolated by a security-barrier VIEW over
	// the events_data hypertable (migration 000052). Verify `events` is a view AND that the barrier is
	// on — a plain view would still let a leaky function read filtered-out rows, and a bare table
	// (pre-000052) would not be isolated at all.
	var relkind string
	var reloptions []string
	if err := s.pool.QueryRow(ctx, `
		SELECT c.relkind::text, coalesce(c.reloptions, '{}')
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relname = 'events'`).Scan(&relkind, &reloptions); err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("store: relation 'events' not found — cannot verify isolation; is the schema migrated?")
		}
		return fmt.Errorf("store: check events view: %w", err)
	}
	if relkind != "v" {
		return fmt.Errorf("store: 'events' is not a view (relkind=%q) — apply migration 000052; events is not tenant-isolated", relkind)
	}
	hasBarrier := false
	for _, o := range reloptions {
		if o == "security_barrier=true" {
			hasBarrier = true
		}
	}
	if !hasBarrier {
		return fmt.Errorf("store: 'events' view is missing security_barrier — its tenant filter could be bypassed by a leaky function")
	}
	return nil
}

// Close closes the pool.
func (s *Store) Close() { s.pool.Close() }

// Pool returns the connection pool (used by the auth package so it shares the same pool).
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

const insertEventSQL = `
INSERT INTO events (
	time, event_category, event_action, event_outcome, event_severity,
	event_dataset, event_original,
	source_ip, source_port, source_geo_country_iso,
	host_name, host_os_type, agent_id, agent_version,
	user_name, rule_id, rule_name,
	threat_technique_id, threat_technique_name, threat_tactic_name,
	threat_indicator_ip, threat_indicator_confidence, threat_feed_name, threat_indicator_last_seen,
	dw_label, dw_severity_original, dw_severity_escalated_by,
	dw_enrichment_status, dw_enrichment_abuse_confidence, dw_enrichment_otx_pulse_count,
	source_geo_city,
	file_path, file_hash_sha256, file_owner, file_mode,
	dw_filehash_verdict, dw_filehash_detail,
	destination_ip, destination_port, network_transport, network_protocol,
	dw_remediation_action, dw_remediation_source, dw_remediation_status,
	file_diff,
	process_name, process_pid,
	http_method, http_uri, http_status, http_host,
	tenant_id
) VALUES (
	$1, $2, $3, $4, $5,
	$6, $7,
	$8::inet, $9, $10,
	$11, $12, $13, $14,
	$15, $16, $17,
	$18, $19, $20,
	$21::inet, $22, $23, $24,
	$25, $26, $27,
	$28, $29, $30,
	$31,
	$32, $33, $34, $35,
	$36, $37,
	$38::inet, $39, $40, $41,
	$42, $43, $44,
	$45,
	$46, $47,
	$48, $49, $50, $51,
	-- Stamp the tenant from the producing agent (agent_id = $13 = the cert CN / agent name).
	-- An unknown/unmapped agent falls back to the Default tenant so an event is never dropped.
	-- Sentinel must match migration 000049 (tenancy.DefaultTenantID).
	COALESCE((SELECT a.tenant_id FROM agents a WHERE a.name = $13), '00000000-0000-0000-0000-000000000001'::uuid)
)`

// InsertEvent writes one DCS event into the events hypertable. Unset fields are
// left NULL/default.
func (s *Store) InsertEvent(ctx context.Context, e *ingest.Event) error {
	var (
		srcIP, srcPort, srcGeoCountry any = nil, nil, nil
		srcGeoCity                    any = nil
		hostName, hostOS              any = nil, nil
		agentID, agentVer             any = nil, nil
		userName                      any = nil
		ruleID, ruleName              any = nil, nil
		techID, techName, tacticName  any = nil, nil, nil
		tiIP, tiConf, tiLastSeen      any = nil, nil, nil
		threatFeed                    any = nil
		dwAbuse, dwOTX, dwEscalatedBy any = nil, nil, nil
		filePath, fileHash            any = nil, nil
		fileOwner, fileMode           any = nil, nil
		fhVerdict, fhDetail           any = nil, nil
		dstIP, dstPort                any = nil, nil
		netTransport, netProtocol     any = nil, nil
		fileDiff                      any = nil
		procName, procPID             any = nil, nil
		httpMethod, httpURI           any = nil, nil
		httpStatus, httpHost          any = nil, nil
	)
	if e.Process != nil {
		procName = strOrNil(e.Process.Name)
		if e.Process.PID > 0 {
			procPID = e.Process.PID
		}
	}
	if e.HTTP != nil {
		httpMethod = strOrNil(e.HTTP.Method)
		httpURI = strOrNil(e.HTTP.URI)
		httpHost = strOrNil(e.HTTP.Host)
		if e.HTTP.StatusCode > 0 {
			httpStatus = e.HTTP.StatusCode
		}
	}
	if e.Destination != nil {
		dstIP = strOrNil(e.Destination.IP)
		dstPort = portOrNil(e.Destination.Port)
	}
	if e.Network != nil {
		netTransport = strOrNil(e.Network.Transport)
		netProtocol = strOrNil(e.Network.Protocol)
	}
	if e.File != nil {
		filePath = strOrNil(e.File.Path)
		fileHash = strOrNil(e.File.HashSHA256)
		fileOwner = strOrNil(e.File.Owner)
		fileMode = strOrNil(e.File.Mode)
		fileDiff = strOrNil(e.File.Diff)
	}
	fhVerdict = strOrNil(e.DeusWatch.FileHash.Verdict)
	fhDetail = strOrNil(e.DeusWatch.FileHash.Detail)
	if e.Source != nil {
		srcIP = strOrNil(e.Source.IP)
		srcPort = portOrNil(e.Source.Port)
		if e.Source.Geo != nil {
			srcGeoCountry = strOrNil(e.Source.Geo.CountryISOCode)
			srcGeoCity = strOrNil(e.Source.Geo.CityName)
		}
	}
	if e.Host != nil {
		hostName = strOrNil(e.Host.Name)
		hostOS = strOrNil(e.Host.OSType)
	}
	if e.Agent != nil {
		agentID = strOrNil(e.Agent.ID)
		agentVer = strOrNil(e.Agent.Version)
	}
	if e.User != nil {
		userName = strOrNil(e.User.Name)
	}
	if e.Rule != nil {
		ruleID = strOrNil(e.Rule.ID)
		ruleName = strOrNil(e.Rule.Name)
	}
	if e.Threat != nil {
		techID = strOrNil(e.Threat.Technique.ID)
		techName = strOrNil(e.Threat.Technique.Name)
		tacticName = strOrNil(e.Threat.TacticName)
		threatFeed = strOrNil(e.Threat.FeedName)
		if e.Threat.Indicator != nil {
			tiIP = strOrNil(e.Threat.Indicator.IP)
			tiConf = int16(e.Threat.Indicator.Confidence)
			if e.Threat.Indicator.LastSeen != nil {
				tiLastSeen = *e.Threat.Indicator.LastSeen
			}
		}
	}
	if e.DeusWatch.Enrichment.AbuseConfidence != nil {
		dwAbuse = int16(*e.DeusWatch.Enrichment.AbuseConfidence)
	}
	if e.DeusWatch.Enrichment.OTXPulseCount != nil {
		dwOTX = int(*e.DeusWatch.Enrichment.OTXPulseCount)
	}
	dwEscalatedBy = strOrNil(e.DeusWatch.Severity.EscalatedBy)

	_, err := s.q(ctx).Exec(ctx, insertEventSQL,
		e.Timestamp, strOrNil(e.Event.Category), strOrNil(e.Event.Action),
		strOrNil(e.Event.Outcome), int16(e.Event.Severity),
		strOrNil(e.Event.Dataset), strOrNil(e.Event.Original),
		srcIP, srcPort, srcGeoCountry,
		hostName, hostOS, agentID, agentVer,
		userName, ruleID, ruleName,
		techID, techName, tacticName,
		tiIP, tiConf, threatFeed, tiLastSeen,
		strOrNil(e.DeusWatch.Label), int16(e.DeusWatch.Severity.Original), dwEscalatedBy,
		strOrNil(string(e.DeusWatch.Enrichment.Status)), dwAbuse, dwOTX,
		srcGeoCity,
		filePath, fileHash, fileOwner, fileMode,
		fhVerdict, fhDetail,
		dstIP, dstPort, netTransport, netProtocol,
		strOrNil(e.DeusWatch.Remediation.Action),
		strOrNil(string(e.DeusWatch.Remediation.Source)),
		strOrNil(string(e.DeusWatch.Remediation.Status)),
		fileDiff,
		procName, procPID,
		httpMethod, httpURI, httpStatus, httpHost,
	)
	if err != nil {
		return fmt.Errorf("store: insert event: %w", err)
	}
	return nil
}

// CountEvents returns the number of rows in the events table.
func (s *Store) CountEvents(ctx context.Context) (int64, error) {
	var n int64
	if err := s.q(ctx).QueryRow(ctx, `SELECT count(*) FROM events`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count events: %w", err)
	}
	return n, nil
}

// CountByLabel counts events with a given deuswatch.label (e.g. "bruteforce").
func (s *Store) CountByLabel(ctx context.Context, label string) (int64, error) {
	var n int64
	err := s.q(ctx).QueryRow(ctx, `SELECT count(*) FROM events WHERE dw_label = $1`, label).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count by label: %w", err)
	}
	return n, nil
}

// CountBySourceIP counts events from a given source IP.
func (s *Store) CountBySourceIP(ctx context.Context, ip string) (int64, error) {
	var n int64
	err := s.q(ctx).QueryRow(ctx, `SELECT count(*) FROM events WHERE source_ip = $1::inet`, ip).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count by source ip: %w", err)
	}
	return n, nil
}

// CountByLabelAndSourceIP counts events with a given label from a given source IP.
func (s *Store) CountByLabelAndSourceIP(ctx context.Context, label, ip string) (int64, error) {
	var n int64
	err := s.q(ctx).QueryRow(ctx,
		`SELECT count(*) FROM events WHERE dw_label = $1 AND source_ip = $2::inet`, label, ip).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count by label and source ip: %w", err)
	}
	return n, nil
}

func strOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func portOrNil(p uint16) any {
	if p == 0 {
		return nil
	}
	return int32(p)
}
