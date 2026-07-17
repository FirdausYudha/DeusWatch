// Small client for the DeusWatch API.
// The dev server (Vite) proxies /healthz, /readyz & /api to the API on :8080 — see vite.config.ts.

export type DepState = 'reachable' | 'unreachable' | 'unknown'

export type Health = {
  api: 'alive' | 'down'
  postgres: DepState
  nats: DepState
  ready: boolean
}

export async function fetchHealth(): Promise<Health> {
  const health: Health = { api: 'down', postgres: 'unknown', nats: 'unknown', ready: false }

  try {
    const live = await fetch('/healthz', { cache: 'no-store' })
    health.api = live.ok ? 'alive' : 'down'
  } catch {
    health.api = 'down'
  }

  try {
    // /readyz returns 200 when ready, 503 otherwise — both carry JSON.
    const res = await fetch('/readyz', { cache: 'no-store' })
    const data = (await res.json()) as {
      status?: string
      dependencies?: Record<string, string>
    }
    health.ready = data.status === 'ready'
    const deps = data.dependencies ?? {}
    health.postgres = depState(deps.postgres)
    health.nats = depState(deps.nats)
  } catch {
    // Network error (e.g. API down) — leave dependencies as 'unknown'.
  }

  return health
}

function depState(raw?: string): DepState {
  if (!raw) return 'unknown'
  return raw.startsWith('reachable') ? 'reachable' : 'unreachable'
}

// ── Events / Alerts / Stats ───────────────────────────────

export type EventRow = {
  time: string
  event_category: string
  event_action: string
  event_outcome: string
  event_severity: number
  event_dataset: string
  source_ip: string
  host_name: string
  user_name: string
  agent_id: string
  rule_id: string
  rule_name: string
  threat_technique_id: string
  threat_tactic_name: string
  dw_label: string
  event_original: string
  source_geo_country_iso: string
  source_geo_city: string
  threat_feed_name: string
  dw_enrichment_abuse_confidence: number | null
  dw_enrichment_otx_pulse_count: number | null
  dw_enrichment_status: string
  dw_severity_escalated_by: string
  dw_llm_verdict: string
  dw_llm_summary: string
  file_path: string
  file_hash_sha256: string
  dw_filehash_verdict: string
  dw_filehash_detail: string
  file_diff: string
  process_name: string
  process_pid: number
  http_method: string
  http_uri: string
  http_status: number
  http_host: string
  dw_remediation_action: string
  dw_remediation_source: string
  threat_score: number
  threat_band: string
}

export type IPCount = { ip: string; count: number }
export type SeverityCount = { severity: number; count: number }

export type Stats = {
  total_events: number
  total_alerts: number
  alerts_24h: number
  top_source_ips: IPCount[] | null
  by_severity: SeverityCount[] | null
}

// EventSearch are the optional filters for the dashboard's Events/Alerts table.
export type EventSearch = {
  q?: string
  ip?: string
  agent?: string
  rule?: string
  technique?: string
  category?: string
  severity?: number // min level 0..4 (-1/undefined = any)
  alerts?: boolean // labeled events only
  from?: string
  to?: string
  limit?: number
}

function eventSearchParams(f: EventSearch): URLSearchParams {
  const qs = new URLSearchParams()
  if (f.q) qs.set('q', f.q)
  if (f.ip) qs.set('ip', f.ip)
  if (f.agent) qs.set('agent', f.agent)
  if (f.rule) qs.set('rule', f.rule)
  if (f.technique) qs.set('technique', f.technique)
  if (f.category) qs.set('category', f.category)
  if (f.severity != null && f.severity >= 0) qs.set('severity', String(f.severity))
  if (f.alerts) qs.set('alerts', '1')
  if (f.from) qs.set('from', f.from)
  if (f.to) qs.set('to', f.to)
  qs.set('limit', String(f.limit ?? 50))
  return qs
}

export async function searchEvents(f: EventSearch): Promise<EventRow[]> {
  const res = await authFetch(`/api/events/search?${eventSearchParams(f).toString()}`)
  if (!res.ok) throw new Error(`events: HTTP ${res.status}`)
  return res.json()
}

// Send the filtered events to the configured export webhook as JSON. Returns the count sent.
export async function exportEventsToWebhook(f: EventSearch): Promise<number> {
  const res = await authFetch(`/api/export/events?${eventSearchParams(f).toString()}`, { method: 'POST' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  const b = await res.json()
  return b.sent ?? 0
}

// Send the report to the configured export webhook as JSON.
export async function exportReportToWebhook(hours = 24): Promise<void> {
  const res = await authFetch(`/api/export/report?hours=${hours}`, { method: 'POST' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

export async function requestFimRestore(agent: string, path: string): Promise<void> {
  const res = await authFetch('/api/fim/restore', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agent, path }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

export async function fetchAlerts(limit = 20): Promise<EventRow[]> {
  const res = await authFetch(`/api/alerts?limit=${limit}`)
  if (!res.ok) throw new Error(`alerts: HTTP ${res.status}`)
  return res.json()
}

export async function fetchStats(): Promise<Stats> {
  const res = await authFetch('/api/stats')
  if (!res.ok) throw new Error(`stats: HTTP ${res.status}`)
  return res.json()
}

export const SEVERITY: Record<number, { label: string; cls: string }> = {
  0: { label: 'info', cls: 'text-slate-400 bg-slate-700/40' },
  1: { label: 'low', cls: 'text-sky-300 bg-sky-500/15' },
  2: { label: 'medium', cls: 'text-amber-300 bg-amber-500/15' },
  3: { label: 'high', cls: 'text-orange-300 bg-orange-500/15' },
  4: { label: 'critical', cls: 'text-rose-300 bg-rose-500/15' },
}

// ── Auth (session token) ──────────────────────────────────

const TOKEN_KEY = 'deuswatch_token'

export type Me = { username: string; role: string; twofa_enabled?: boolean; permissions: string[] }

// can reports whether the signed-in user holds a given permission (drives menu gating).
export function can(me: Me | null, perm: string): boolean {
  return !!me && Array.isArray(me.permissions) && me.permissions.includes(perm)
}

// Thrown when the password is correct but 2FA is enabled and the code is missing/invalid.
export class TwoFactorRequired extends Error {}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

function setToken(t: string) {
  localStorage.setItem(TOKEN_KEY, t)
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
}

// authFetch adds the Bearer header and clears the token on 401.
async function authFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const token = getToken()
  const headers: Record<string, string> = { ...(init.headers as Record<string, string>) }
  if (token) headers.Authorization = `Bearer ${token}`
  const res = await fetch(url, { ...init, headers, cache: 'no-store' })
  if (res.status === 401) clearToken()
  return res
}

export async function login(username: string, password: string, totp?: string): Promise<Me> {
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, totp }),
  })
  if (res.status === 401) {
    const text = await res.text()
    if (text.includes('2fa_required')) throw new TwoFactorRequired()
    throw new Error('Incorrect username or password')
  }
  if (res.status === 429) {
    throw new Error('Too many failed attempts - please wait a few minutes and try again')
  }
  if (!res.ok) throw new Error(`login: HTTP ${res.status}`)
  const data = await res.json()
  setToken(data.token)
  return { username: data.username, role: data.role, permissions: data.permissions ?? [] }
}

export async function register(username: string, password: string): Promise<Me> {
  const res = await fetch('/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  const data = await res.json()
  if (!data.token) throw new Error('Account created — please sign in')
  setToken(data.token)
  return { username: data.username, role: data.role, permissions: data.permissions ?? [] }
}

export async function fetchAuthConfig(): Promise<{ registration_enabled: boolean }> {
  try {
    const res = await fetch('/api/auth/config', { cache: 'no-store' })
    if (!res.ok) return { registration_enabled: false }
    return res.json()
  } catch {
    return { registration_enabled: false }
  }
}

// ── 2FA (self-service) ────────────────────────────────────

export async function setup2FA(): Promise<{ secret: string; otpauth_url: string }> {
  const res = await authFetch('/api/2fa/setup', { method: 'POST' })
  if (!res.ok) throw new Error(`2fa setup: HTTP ${res.status}`)
  return res.json()
}

export async function enable2FA(secret: string, code: string): Promise<void> {
  const res = await authFetch('/api/2fa/enable', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ secret, code }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

export async function disable2FA(code: string): Promise<void> {
  const res = await authFetch('/api/2fa/disable', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  const res = await authFetch('/api/me/password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

export async function fetchMe(): Promise<Me> {
  const res = await authFetch('/api/me')
  if (!res.ok) throw new Error(`me: HTTP ${res.status}`)
  return res.json()
}

export async function logout(): Promise<void> {
  try {
    await authFetch('/api/logout', { method: 'POST' })
  } catch {
    // ignore
  }
  clearToken()
}

// ── User management (admin) ───────────────────────────────

// permissions: null = inherit the role's defaults; an array = an explicit custom set.
export type UserInfo = {
  id: string
  username: string
  role: string
  disabled: boolean
  created_at: string
  permissions: string[] | null
}

export type PermissionInfo = { key: string; label: string; group: string }
export type PermissionCatalog = { catalog: PermissionInfo[]; role_defaults: Record<string, string[]> }

export async function fetchUsers(): Promise<UserInfo[]> {
  const res = await authFetch('/api/users')
  if (!res.ok) throw new Error(`users: HTTP ${res.status}`)
  return res.json()
}

// The permission catalog + per-role defaults used to render & prefill the RBAC checklist.
export async function fetchPermissions(): Promise<PermissionCatalog> {
  const res = await authFetch('/api/permissions')
  if (!res.ok) throw new Error(`permissions: HTTP ${res.status}`)
  return res.json()
}

// permissions: pass null to inherit the role's defaults, or an array for a custom set.
export async function createUser(
  username: string,
  password: string,
  role: string,
  permissions: string[] | null = null,
): Promise<void> {
  const res = await authFetch('/api/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, role, permissions }),
  })
  if (!res.ok) {
    throw new Error((await res.text()) || `HTTP ${res.status}`)
  }
}

// Update an existing user's role and permission override (null = inherit role).
export async function updateUser(id: string, role: string, permissions: string[] | null): Promise<void> {
  const res = await authFetch(`/api/users/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role, permissions }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

// Delete a user (you cannot delete your own account — the API rejects it).
export async function deleteUser(id: string): Promise<void> {
  const res = await authFetch(`/api/users/${id}`, { method: 'DELETE' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

// ── Agents (enrollment, config push, revoke) ──────────────

export type AgentSource = { dataset: string; type: string; path: string; interval?: number }

export type AgentStatus = 'unknown' | 'online' | 'degraded' | 'disconnected' | 'stale'

export type AgentInfo = {
  id: string
  name: string
  os: string
  enrolled_at: string
  last_seen_at: string | null
  revoked: boolean
  status: AgentStatus
  health_detail?: string
  config_version: number
  sources?: AgentSource[]
}

// An agent is considered online if its last heartbeat was < 90s ago (30s interval + tolerance).
export function agentOnline(a: AgentInfo): boolean {
  if (a.revoked || !a.last_seen_at) return false
  return Date.now() - new Date(a.last_seen_at).getTime() < 90_000
}

export async function fetchAgents(): Promise<AgentInfo[]> {
  const res = await authFetch('/api/agents')
  if (!res.ok) throw new Error(`agents: HTTP ${res.status}`)
  return res.json()
}

// Log-storage health for the dashboard (PostgreSQL + TimescaleDB).
export type StorageStatus = {
  reachable: boolean
  host: string
  db_size_bytes: number
  db_size_pretty: string
  events_count: number
  budget_bytes: number
  used_percent: number
  retention_days: number | null
  compression_days: number | null
  replication: { enabled: boolean; standbys: string[] }
}
export async function fetchStorageStatus(): Promise<StorageStatus> {
  const res = await authFetch('/api/storage/status')
  if (!res.ok) throw new Error(`storage status: HTTP ${res.status}`)
  return res.json()
}

// Change the log-storage lifecycle (TimescaleDB retention + compression). Admin only.
export async function saveRetention(retention_days: number, compression_days: number): Promise<StorageStatus> {
  const res = await authFetch('/api/storage/retention', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ retention_days, compression_days }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}

// Host-published ports agents must reach (the container listens on 8080/8443 internally).
// Used by the Add-agent wizard so the generated one-liner points at the right ports.
export type AgentInstallInfo = { api_port: string; gateway_port: string }
export async function fetchInstallInfo(): Promise<AgentInstallInfo> {
  const res = await authFetch('/api/agent/install-info')
  if (!res.ok) throw new Error(`install info: HTTP ${res.status}`)
  return res.json()
}

export async function createEnrollToken(): Promise<{ token: string; expires_at: string }> {
  const res = await authFetch('/api/agents/tokens', { method: 'POST' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}

export async function revokeAgent(id: string): Promise<void> {
  const res = await authFetch(`/api/agents/${id}/revoke`, { method: 'POST' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

export async function setAgentConfig(id: string, sources: AgentSource[]): Promise<{ version: number }> {
  const res = await authFetch(`/api/agents/${id}/config`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sources }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}

// ── Integrations (firewalls, bouncers, CTI providers) ─────

export type IntegrationField = { key: string; label: string; secret?: boolean; optional?: boolean; help?: string; options?: string[] }
export type IntegrationType = { type: string; label: string; category: string; desc: string; fields: IntegrationField[]; doc?: string }

export type Integration = {
  id: string
  type: string
  name: string
  enabled: boolean
  config: Record<string, string>
  secrets_set: Record<string, boolean>
  created_at: string
  updated_at: string
}

export async function fetchIntegrationTypes(): Promise<IntegrationType[]> {
  const res = await authFetch('/api/integrations/types')
  if (!res.ok) throw new Error(`integration types: HTTP ${res.status}`)
  return res.json()
}

export async function fetchIntegrations(): Promise<Integration[]> {
  const res = await authFetch('/api/integrations')
  if (!res.ok) throw new Error(`integrations: HTTP ${res.status}`)
  return (await res.json()) ?? []
}

export async function createIntegration(
  type: string,
  name: string,
  config: Record<string, string>,
): Promise<Integration> {
  const res = await authFetch('/api/integrations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type, name, config }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}

export async function updateIntegration(
  id: string,
  name: string,
  enabled: boolean,
  config: Record<string, string>,
): Promise<Integration> {
  const res = await authFetch(`/api/integrations/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, enabled, config }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}

export async function deleteIntegration(id: string): Promise<void> {
  const res = await authFetch(`/api/integrations/${id}`, { method: 'DELETE' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

// ── Response engine (block actions, approval workflow) ────

export type ResponseStatus = 'recommended' | 'approved' | 'executed' | 'dismissed' | 'failed' | 'unbanned'

export type ResponseAction = {
  id: string
  created_at: string
  source_ip: string
  agent_id: string
  action: string
  reason: string
  rule_id: string
  ban_seconds: number
  offense_count: number
  source: string
  status: ResponseStatus
  responder: string
  decided_by: string
  decided_at: string | null
  executed_at: string | null
  error: string
}

export async function fetchResponses(status = '', search = ''): Promise<ResponseAction[]> {
  const p = new URLSearchParams()
  if (status) p.set('status', status)
  if (search) p.set('q', search)
  const qs = p.toString()
  const res = await authFetch(`/api/responses${qs ? `?${qs}` : ''}`)
  if (!res.ok) throw new Error(`responses: HTTP ${res.status}`)
  return (await res.json()) ?? []
}

// Enforcement status: whether a ban actually reaches a firewall (a live push responder, or the
// pull blocklist feed). When false, the UI must not claim an IP is "blocked" — it is only flagged.
export type Enforcement = {
  enforcing: boolean
  push_live: boolean
  response_live: boolean
  backends: string[]
  blocklist_feed: boolean
}
export async function fetchEnforcement(): Promise<Enforcement> {
  const res = await authFetch('/api/response/enforcement')
  if (!res.ok) throw new Error(`enforcement: HTTP ${res.status}`)
  return res.json()
}

// Blocklist feed: the UI-managed token for GET /api/blocklist (external-firewall feed).
export type BlocklistConfig = { token: string; enabled: boolean }
export async function fetchBlocklistConfig(): Promise<BlocklistConfig> {
  const res = await authFetch('/api/blocklist-config')
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}
export async function regenerateBlocklistToken(): Promise<BlocklistConfig> {
  const res = await authFetch('/api/blocklist-config/regenerate', { method: 'POST' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}

// Inbound ingest webhook: the UI-managed token for POST /api/ingest/webhook (a Wazuh manager
// or any external system pushing raw logs / alerts into the DeusWatch pipeline).
export type IngestConfig = { token: string; enabled: boolean }
export async function fetchIngestConfig(): Promise<IngestConfig> {
  const res = await authFetch('/api/ingest-config')
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}
export async function regenerateIngestToken(): Promise<IngestConfig> {
  const res = await authFetch('/api/ingest-config/regenerate', { method: 'POST' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}
export async function disableIngestWebhook(): Promise<IngestConfig> {
  const res = await authFetch('/api/ingest-config/disable', { method: 'POST' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}

// Progressive-ban policy: the escalation ladder (durations in seconds for the 1st, 2nd,
// … offense), whether offenses beyond the ladder are permanent, and the observation
// window in seconds (0 = count all history).
export type BanPolicy = { durations: number[]; permanent: boolean; window_secs: number; auto_approve: boolean }

// Offender is a per-IP rollup of response actions (the IP-centric Response view).
export type Offender = {
  source_ip: string
  offenses: number
  total: number
  pending: number
  last_seen: string
  last_status: ResponseStatus
  last_reason: string
  last_agent: string
  last_ban_secs: number
  pending_id: string
  blocked_until: string | null
  blocked: boolean
}

export async function fetchOffenders(): Promise<Offender[]> {
  const res = await authFetch('/api/responses/offenders')
  if (!res.ok) throw new Error(`offenders: HTTP ${res.status}`)
  return res.json()
}

export async function fetchBanPolicy(): Promise<BanPolicy> {
  const res = await authFetch('/api/ban-policy')
  if (!res.ok) throw new Error(`ban policy: HTTP ${res.status}`)
  return res.json()
}

export async function saveBanPolicy(p: BanPolicy): Promise<BanPolicy> {
  const res = await authFetch('/api/ban-policy', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(p),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}

// IP whitelist: trusted IPs/CIDRs the response engine never bans.
export type WhitelistEntry = { id: string; cidr: string; note: string; created_at: string }

export async function fetchWhitelist(): Promise<WhitelistEntry[]> {
  const res = await authFetch('/api/whitelist')
  if (!res.ok) throw new Error(`whitelist: HTTP ${res.status}`)
  return res.json()
}

export async function addWhitelist(cidr: string, note: string): Promise<WhitelistEntry> {
  const res = await authFetch('/api/whitelist', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cidr, note }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}

export async function deleteWhitelist(id: string): Promise<void> {
  const res = await authFetch(`/api/whitelist/${id}`, { method: 'DELETE' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

export async function approveResponse(id: string): Promise<void> {
  const res = await authFetch(`/api/responses/${id}/approve`, { method: 'POST' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

export async function dismissResponse(id: string): Promise<void> {
  const res = await authFetch(`/api/responses/${id}/dismiss`, { method: 'POST' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

// unbanResponse lifts an executed/approved block (calls the responder's Unblock).
export async function unbanResponse(id: string): Promise<void> {
  const res = await authFetch(`/api/responses/${id}/unban`, { method: 'POST' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

// dismissPendingForIP bulk-dismisses every pending recommendation for one IP.
// Returns how many were dismissed.
export async function dismissPendingForIP(ip: string): Promise<number> {
  const res = await authFetch('/api/responses/dismiss-ip', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  const body = await res.json()
  return body.dismissed ?? 0
}

// ── Network containment (host isolation) ──────────────────

export type ContainmentStatus = 'recommended' | 'contained' | 'released' | 'dismissed' | 'failed'

export type Containment = {
  id: string
  created_at: string
  agent_id: string
  host_name: string
  ip_address: string
  reason: string
  rule_id: string
  timeout_seconds: number
  status: ContainmentStatus
  auto: boolean
  decided_by: string
  contained_at: string | null
  expires_at: string | null
  released_at: string | null
  error: string
}

export async function fetchContainments(status = ''): Promise<Containment[]> {
  const qs = status ? `?status=${encodeURIComponent(status)}` : ''
  const res = await authFetch(`/api/containments${qs}`)
  if (!res.ok) throw new Error(`containments: HTTP ${res.status}`)
  return (await res.json()) ?? []
}

// approveContainment isolates a recommended host; releaseContainment lifts an active one.
export async function approveContainment(id: string): Promise<void> {
  const res = await authFetch(`/api/containments/${id}/approve`, { method: 'POST' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

export async function dismissContainment(id: string): Promise<void> {
  const res = await authFetch(`/api/containments/${id}/dismiss`, { method: 'POST' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

export async function releaseContainment(id: string): Promise<void> {
  const res = await authFetch(`/api/containments/${id}/release`, { method: 'POST' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

// ── Customizable dashboard (data + per-user widget layout) ─

export type SeriesPoint = { label: string; count: number }
export type TimelinePoint = { time: string; count: number }

export type DashboardData = {
  total_events: number
  total_alerts: number
  alerts_24h: number
  series: Record<string, SeriesPoint[]>
  timeline: TimelinePoint[]
}

// DashRange selects the dashboard window: either a relative number of hours, or an
// explicit from/to (Date) range for precise calendar+time selection.
export type DashRange = { hours?: number; from?: Date; to?: Date }

export async function fetchDashboardData(range: number | DashRange = 24): Promise<DashboardData> {
  const r: DashRange = typeof range === 'number' ? { hours: range } : range
  const qs = new URLSearchParams()
  if (r.from && r.to) {
    qs.set('from', r.from.toISOString())
    qs.set('to', r.to.toISOString())
  } else {
    qs.set('hours', String(r.hours ?? 24))
  }
  const res = await authFetch(`/api/dashboard?${qs.toString()}`)
  if (!res.ok) throw new Error(`dashboard: HTTP ${res.status}`)
  return res.json()
}

export type WidgetKind = 'stat' | 'bar' | 'donut' | 'line' | 'table' | 'map'
export type DashWidget = { id: string; kind: WidgetKind; source: string; title: string; color: string; wide: boolean }
export type DashLayout = { widgets: DashWidget[] }

export async function fetchLayout(): Promise<DashLayout | null> {
  const res = await authFetch('/api/dashboard/layout')
  if (!res.ok) throw new Error(`layout: HTTP ${res.status}`)
  return res.json()
}

export async function saveLayout(layout: DashLayout): Promise<void> {
  const res = await authFetch('/api/dashboard/layout', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(layout),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

// ── Detection rules (Wazuh-style management) ──────────────

export type Rule = {
  id: string
  name: string
  kind: 'single' | 'aggregation'
  category: string
  yaml: string
  enabled: boolean
  builtin: boolean
  created_at: string
  updated_at: string
}

export async function fetchRules(): Promise<Rule[]> {
  const res = await authFetch('/api/rules')
  if (!res.ok) throw new Error(`rules: HTTP ${res.status}`)
  return (await res.json()) ?? []
}

export async function createRule(name: string, yaml: string): Promise<Rule> {
  const res = await authFetch('/api/rules', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, yaml }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}

export async function updateRule(id: string, name: string, yaml: string, enabled: boolean): Promise<Rule> {
  const res = await authFetch(`/api/rules/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, yaml, enabled }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}

export async function deleteRule(id: string): Promise<void> {
  const res = await authFetch(`/api/rules/${id}`, { method: 'DELETE' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

// Rule packs (marketplace): installed packs map to rule categories (toggle enables/disables the
// real bundled rules); external packs are real-world third-party rulesets you bring in (link-out).
export type RulePack = {
  id: string
  name: string
  description: string
  source: string
  rule_count: number
  enabled: number
  installed: boolean
  installable?: boolean // curated pack: one-click Install / Uninstall
  remote?: boolean // came from the online feed — re-installing pulls newly-added rules (Update)
  url?: string
}
export async function fetchRulePacks(): Promise<RulePack[]> {
  const res = await authFetch('/api/rules/packs')
  if (!res.ok) throw new Error(`rule packs: HTTP ${res.status}`)
  return (await res.json()) ?? []
}
export async function toggleRulePack(id: string, enabled: boolean): Promise<{ updated: number }> {
  const res = await authFetch(`/api/rules/packs/${id}/toggle`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}
export async function installRulePack(id: string): Promise<{ installed: number }> {
  const res = await authFetch(`/api/rules/packs/${id}/install`, { method: 'POST' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}
export async function uninstallRulePack(id: string): Promise<{ removed: number }> {
  const res = await authFetch(`/api/rules/packs/${id}/uninstall`, { method: 'POST' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}

// ── Custom decoders (data-driven log-source support) ──────
export type DecoderSpec = {
  name: string
  dataset: string
  category: string
  action: string
  outcome: string
  level: string
  regex: string
}
export type Decoder = DecoderSpec & {
  id: string
  enabled: boolean
  builtin: boolean
  created_at: string
  updated_at: string
}

export type PlaybookSpec = { label: string; name: string; steps: string[] }
export type PlaybookInfo = PlaybookSpec & {
  id: string
  enabled: boolean
  builtin: boolean
  created_at: string
  updated_at: string
}
export async function fetchPlaybooks(): Promise<PlaybookInfo[]> {
  const res = await authFetch('/api/playbooks')
  if (!res.ok) throw new Error(`playbooks: HTTP ${res.status}`)
  return (await res.json()) ?? []
}
export async function createPlaybook(spec: PlaybookSpec): Promise<PlaybookInfo> {
  const res = await authFetch('/api/playbooks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(spec),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}
export async function updatePlaybook(id: string, spec: PlaybookSpec, enabled: boolean): Promise<PlaybookInfo> {
  const res = await authFetch(`/api/playbooks/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...spec, enabled }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}
export async function deletePlaybook(id: string): Promise<void> {
  const res = await authFetch(`/api/playbooks/${id}`, { method: 'DELETE' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}

export async function fetchDecoders(): Promise<Decoder[]> {
  const res = await authFetch('/api/decoders')
  if (!res.ok) throw new Error(`decoders: HTTP ${res.status}`)
  return (await res.json()) ?? []
}
export async function createDecoder(spec: DecoderSpec): Promise<Decoder> {
  const res = await authFetch('/api/decoders', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(spec),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}
export async function updateDecoder(id: string, spec: DecoderSpec, enabled: boolean): Promise<Decoder> {
  const res = await authFetch(`/api/decoders/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...spec, enabled }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}
export async function deleteDecoder(id: string): Promise<void> {
  const res = await authFetch(`/api/decoders/${id}`, { method: 'DELETE' })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
}
export async function fetchDecoderSamples(dataset: string): Promise<string[]> {
  const res = await authFetch(`/api/decoders/samples?dataset=${encodeURIComponent(dataset)}`)
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return (await res.json()).lines ?? []
}
export async function testDecoder(spec: DecoderSpec, line: string): Promise<{ matched: boolean; fields: Record<string, string> }> {
  const res = await authFetch('/api/decoders/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...spec, line }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}

// ── Ticketing (Tier-2 DFIR case management) ───────────────

export type TicketStatus = 'open' | 'in_progress' | 'resolved' | 'closed'

export type Ticket = {
  id: string
  title: string
  description: string
  severity: number
  status: TicketStatus
  assignee: string | null
  created_by: string
  source_ip: string | null
  rule_id: string | null
  created_at: string
  updated_at: string
  resolved_at: string | null
  closed_at: string | null
}

export type TicketComment = { id: number; author: string; body: string; created_at: string }

export type NewTicketInput = {
  title: string
  description?: string
  severity?: number
  assignee?: string
  source_ip?: string
  rule_id?: string
}

export async function fetchTickets(status = ''): Promise<Ticket[]> {
  const q = status ? `?status=${encodeURIComponent(status)}` : ''
  const res = await authFetch(`/api/tickets${q}`)
  if (!res.ok) throw new Error(`tickets: HTTP ${res.status}`)
  return (await res.json()) ?? []
}

export async function fetchTicket(id: string): Promise<{ ticket: Ticket; comments: TicketComment[] }> {
  const res = await authFetch(`/api/tickets/${id}`)
  if (!res.ok) throw new Error(`ticket: HTTP ${res.status}`)
  return res.json()
}

export async function createTicket(input: NewTicketInput): Promise<Ticket> {
  const res = await authFetch('/api/tickets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}

export async function updateTicket(
  id: string,
  patch: Partial<{ title: string; description: string; severity: number; status: TicketStatus; assignee: string }>,
): Promise<Ticket> {
  const res = await authFetch(`/api/tickets/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(patch),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}

export async function addTicketComment(id: string, body: string): Promise<TicketComment> {
  const res = await authFetch(`/api/tickets/${id}/comments`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ body }),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}

// ── Report ────────────────────────────────────────────────

export type ReportCount = { label: string; count: number }

export type SecurityReport = {
  generated: string
  since: string
  until?: string // set only when an explicit from–to range was requested
  window_hours: number
  total_events: number
  total_alerts: number
  by_severity: ReportCount[] | null
  top_source_ips: ReportCount[] | null
  top_agents: ReportCount[] | null
  top_rules: ReportCount[] | null
  top_techniques: ReportCount[] | null
  by_verdict: ReportCount[] | null
}

// A report window: either the rolling last-N-hours, or an explicit from–to date range
// (YYYY-MM-DD). A bare `to` date includes that whole day.
export type ReportRange = { from?: string; to?: string }

function reportQuery(hours: number, range?: ReportRange): string {
  if (range?.from) {
    const p = new URLSearchParams({ from: range.from })
    if (range.to) p.set('to', range.to)
    return p.toString()
  }
  return `hours=${hours}`
}

export async function fetchReport(hours = 24, range?: ReportRange): Promise<SecurityReport> {
  const res = await authFetch(`/api/report?${reportQuery(hours, range)}`)
  if (!res.ok) throw new Error(`report: HTTP ${res.status}`)
  return res.json()
}

export async function fetchReportMarkdown(hours = 24, range?: ReportRange): Promise<string> {
  const res = await authFetch(`/api/report?${reportQuery(hours, range)}&format=md`)
  if (!res.ok) throw new Error(`report: HTTP ${res.status}`)
  return res.text()
}

// AI report summary (generated on demand or on a schedule).
export type ReportSummary = { summary: string; model?: string; period_hours?: number; generated_at: string | null }

export async function fetchReportSummary(): Promise<ReportSummary> {
  const res = await authFetch('/api/report/summary')
  if (!res.ok) throw new Error(`report summary: HTTP ${res.status}`)
  return res.json()
}

export async function generateReportSummary(hours = 24): Promise<ReportSummary> {
  const res = await authFetch(`/api/report/summary?hours=${hours}`, { method: 'POST' })
  if (!res.ok) {
    const body = (await res.text()).trim()
    // A reverse-proxy timeout (e.g. 504) returns an HTML page, not our JSON/plain error —
    // don't dump raw HTML into the UI as if it were a summary.
    const msg = /^<(!doctype|html)/i.test(body) || body.includes('<html')
      ? `Report generation failed (HTTP ${res.status}). The LLM likely took too long — try a shorter window (24h) or a faster model.`
      : body || `HTTP ${res.status}`
    throw new Error(msg)
  }
  return res.json()
}

// ── Software update check (read-only; update runs on the host) ─
export type UpdateInfo = {
  current: string
  latest: string
  latest_date: string
  update_available: boolean
  repo_url: string
  update_command: string
}
export async function fetchUpdateCheck(): Promise<UpdateInfo> {
  const res = await authFetch('/api/update-check')
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}

// ── Notifications (alert threshold + scheduled report delivery) ─
export type NotifyConfig = {
  min_severity: number
  report_interval_hours: number
  report_period_hours: number
  report_last_sent_at?: string | null
}

export async function fetchNotifyConfig(): Promise<NotifyConfig> {
  const res = await authFetch('/api/notify-config')
  if (!res.ok) throw new Error(`notify config: HTTP ${res.status}`)
  return res.json()
}

export async function saveNotifyConfig(c: NotifyConfig): Promise<NotifyConfig> {
  const res = await authFetch('/api/notify-config', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(c),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}

// ── Config profile (export/import to clone a server's settings) ─
export async function exportConfig(): Promise<Blob> {
  const res = await authFetch('/api/config/export')
  if (!res.ok) throw new Error(`export: HTTP ${res.status}`)
  return res.blob()
}

export async function importConfig(json: string): Promise<Record<string, number>> {
  const res = await authFetch('/api/config/import', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: json,
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  const b = await res.json()
  return b.applied ?? {}
}

// Schedule for auto-generating the AI summary (interval_hours: 0 = disabled).
export type ReportAIConfig = {
  interval_hours: number
  period_hours: number
  at_hour?: number // 0..23 = run at that hour (server time); -1 = drifting interval
  server_time?: string // read-only: the server's current HH:MM, so at_hour is unambiguous
  server_tz?: string
  summary_prompt?: string // custom system prompt ("" = use the built-in default)
  default_prompt?: string // the built-in default (returned by GET, for display/reset)
}

export async function fetchReportAIConfig(): Promise<ReportAIConfig> {
  const res = await authFetch('/api/report/ai-config')
  if (!res.ok) throw new Error(`report ai config: HTTP ${res.status}`)
  return res.json()
}

export async function saveReportAIConfig(c: ReportAIConfig): Promise<ReportAIConfig> {
  const res = await authFetch('/api/report/ai-config', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(c),
  })
  if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`)
  return res.json()
}
