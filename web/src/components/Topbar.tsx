import type { View } from './Sidebar'
import { useTheme } from '../lib/theme'

// Topbar is the prototype's global 60px header: it names the page on the left and carries the
// app-level controls on the right.
//
// It exists so every page announces itself the same way. Previously each page rendered its own
// title block, which meant the heading sat at a different height on every screen and the theme
// toggle lived in the sidebar, far from the content it affects.
//
// It deliberately owns ONLY chrome (title, subtitle, theme). Page-specific controls - filters,
// view switches, search - stay inside their page, because they belong to that page's state.

// PAGE_META is the single source of truth for what each screen calls itself. Keeping it here
// rather than in each page means the sidebar label and the header can never drift apart.
export const PAGE_META: Record<View, { title: string; subtitle: string }> = {
  dashboard: { title: 'Dashboard', subtitle: 'Live security posture' },
  agents: { title: 'Agents', subtitle: 'Endpoints reporting in' },
  snapshots: { title: 'Snapshots', subtitle: 'Versioned file timeline & recovery' },
  response: { title: 'Response', subtitle: 'Recommendations awaiting your call' },
  tickets: { title: 'Tickets', subtitle: 'Investigations and their status' },
  report: { title: 'Report', subtitle: 'Scheduled and on-demand exports' },
  rules: { title: 'Rules', subtitle: 'Detection logic and coverage' },
  decoders: { title: 'Decoders', subtitle: 'Custom log parsing' },
  playbooks: { title: 'Playbooks', subtitle: 'Automated response actions' },
  integrations: { title: 'Integrations', subtitle: 'Connected sources and enrichment' },
  users: { title: 'Users', subtitle: 'Accounts, roles and access' },
  settings: { title: 'Settings', subtitle: 'Platform configuration' },
}

export default function Topbar({ view, onMenu }: { view: View; onMenu?: () => void }) {
  const [theme, toggle] = useTheme()
  const meta = PAGE_META[view] ?? PAGE_META.dashboard

  return (
    <header className="sticky top-0 z-10 flex h-[60px] flex-none items-center gap-4 border-b border-border bg-surface px-4 sm:px-6">
      {/* Only reachable below `lg`, where the nav rail collapses into a slide-over. */}
      <button
        onClick={onMenu}
        aria-label="Open navigation"
        className="-ml-1 flex h-8 w-8 items-center justify-center rounded-[8px] border border-border text-muted transition-colors hover:bg-surface-2 hover:text-fg lg:hidden"
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M4 6h16M4 12h16M4 18h16" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
        </svg>
      </button>
      <h1 className="text-[16px] font-bold tracking-tight text-fg">{meta.title}</h1>
      {/* The subtitle is supporting context, so it is hidden on narrow screens rather than
          allowed to wrap and push the 60px bar out of shape. */}
      <p className="hidden truncate text-[12.5px] text-dim sm:block">{meta.subtitle}</p>

      <div className="ml-auto flex items-center gap-2.5">
        <button
          onClick={toggle}
          title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
          aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
          className="flex h-8 w-8 items-center justify-center rounded-[8px] border border-border text-muted transition-colors hover:bg-surface-2 hover:text-fg"
        >
          {theme === 'dark' ? (
            /* Currently dark → offer the sun (switch to light). */
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <circle cx="12" cy="12" r="4" stroke="currentColor" strokeWidth="1.8" />
              <path
                d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4"
                stroke="currentColor"
                strokeWidth="1.8"
                strokeLinecap="round"
              />
            </svg>
          ) : (
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path
                d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8"
                stroke="currentColor"
                strokeWidth="1.8"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          )}
        </button>
      </div>
    </header>
  )
}
