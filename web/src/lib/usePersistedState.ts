import { useEffect, useState } from 'react'

// usePersistedState is useState that REMEMBERS the value across navigation and reloads.
//
// Pages are unmounted when you switch views, so plain useState resets every filter to its
// default the moment you come back (pick 1h on the dashboard, visit Integrations, return —
// it was 24h again). Persisting the choice under a stable key fixes that for good.
//
// Use it for preference-like controls (time range, severity, "alerts only", page size, a
// collapsed section). Keep free-text search on plain useState — a search you can't see is
// more confusing than one that resets.
export function usePersistedState<T>(key: string, initial: T): [T, (v: T) => void] {
  const storageKey = `deuswatch.ui.${key}`
  const [value, setValue] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(storageKey)
      return raw === null ? initial : (JSON.parse(raw) as T)
    } catch {
      return initial // private mode / corrupt entry: fall back to the default
    }
  })
  useEffect(() => {
    try {
      localStorage.setItem(storageKey, JSON.stringify(value))
    } catch {
      /* storage unavailable — the value still works for this session */
    }
  }, [storageKey, value])
  return [value, setValue]
}
