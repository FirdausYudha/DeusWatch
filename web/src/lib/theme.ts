import { useEffect, useState } from 'react'

export type Theme = 'dark' | 'light'
const KEY = 'deuswatch.theme'

/** The stored preference, else the OS preference, else dark (the operator default). */
export function initialTheme(): Theme {
  const saved = localStorage.getItem(KEY)
  if (saved === 'dark' || saved === 'light') return saved
  if (window.matchMedia?.('(prefers-color-scheme: light)').matches) return 'light'
  return 'dark'
}

function apply(theme: Theme) {
  document.documentElement.classList.toggle('dark', theme === 'dark')
  document.documentElement.style.colorScheme = theme
}

// Apply before React mounts so there is no flash of the wrong theme.
apply(initialTheme())

/** useTheme returns the current theme and a toggle that persists the choice. */
export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(initialTheme)
  useEffect(() => {
    apply(theme)
    localStorage.setItem(KEY, theme)
  }, [theme])
  return [theme, () => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))]
}
