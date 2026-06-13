// Klien kecil untuk endpoint kesehatan API DeusWatch.
// Dev server (Vite) mem-proxy /healthz & /readyz ke API :8080 — lihat vite.config.ts.

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
    // /readyz mengembalikan 200 saat ready, 503 saat belum — keduanya berisi JSON.
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
    // Error jaringan (mis. API mati) — biarkan dependensi 'unknown'.
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
  rule_id: string
  rule_name: string
  threat_technique_id: string
  threat_tactic_name: string
  dw_label: string
  event_original: string
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

// ── Auth (token sesi) ─────────────────────────────────────

const TOKEN_KEY = 'deuswatch_token'

export type Me = { username: string; role: string }

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

function setToken(t: string) {
  localStorage.setItem(TOKEN_KEY, t)
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
}

// authFetch menambah header Bearer dan membersihkan token pada 401.
async function authFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const token = getToken()
  const headers: Record<string, string> = { ...(init.headers as Record<string, string>) }
  if (token) headers.Authorization = `Bearer ${token}`
  const res = await fetch(url, { ...init, headers, cache: 'no-store' })
  if (res.status === 401) clearToken()
  return res
}

export async function login(username: string, password: string): Promise<Me> {
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  if (!res.ok) throw new Error('Username atau password salah')
  const data = await res.json()
  setToken(data.token)
  return { username: data.username, role: data.role }
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
    // abaikan
  }
  clearToken()
}
