// Package tenancy holds shared multi-tenancy primitives. Today that is just the Default tenant
// sentinel; later phases add the request-scope context helpers and the RLS wiring here.
package tenancy

// DefaultTenantID is the fixed sentinel UUID of the "Default" tenant seeded by migration 000049.
// Existing single-tenant data, and any write path not yet made tenant-aware, resolve to it.
// MUST stay in sync with migrations/000049_multitenancy.up.sql.
const DefaultTenantID = "00000000-0000-0000-0000-000000000001"
