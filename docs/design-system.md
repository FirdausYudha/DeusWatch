# DeusWatch design standard

The rules every screen follows so the app reads as one product. Grounded in Don Norman's basics:
**visibility** (state is shown, not guessed), **feedback** (every action confirms), **consistency**
(one thing looks/works one way everywhere), **affordance/signifiers** (controls look operable),
**error prevention** over error messages.

Primitives live in [`web/src/components/ui.tsx`](../web/src/components/ui.tsx); tokens in
[`web/src/index.css`](../web/src/index.css). Compose these - do not re-invent chrome.

## Tokens (never hardcode a hex)

Colors are CSS vars mapped to Tailwind: `bg`, `surface`, `surface-2`, `border`, `border-strong`,
`fg`, `muted`, `dim`, `accent`, `accent-soft`, and severity `critical/high/medium/low/info` +
`success`, `manager`. Use `text-fg`, `bg-surface`, `border-border`, etc. Radii: `--radius-card`
(12px), `--radius-control` (8px). A color always means the same thing (severity palette is fixed).

## Layout & spacing

- Every page wraps content in `<Page>` - one max width (1400px) + gutter (`px-6 py-6`). This is the
  fix for uneven left/right spacing: no page sets its own `mx-auto/max-w/px`.
- Page name is in the Topbar; a page adds only subtitle + actions via `PageHeader`.
- Cards via `<Card>`; vertical rhythm in multiples of 4 (`gap-2/3/4`, `mb-4/5`).

## Controls

- **Filters with >3 options → `<Select>` dropdown**, not a row of buttons (e.g. Ticket status).
  Segmented buttons only for 2-3 mutually exclusive views (e.g. By IP / Events).
- Inputs/buttons/selects come from `ui.tsx` so focus, radius and colors match.
- Every button gives feedback: disabled while busy, `Copied ✓` / `Saving…` states.

## Tables

- **Always paginate.** Use `usePaged(rows)` + `<Pagination>` (default 25/page). No unbounded
  scroll. Client-side slicing for already-fetched lists; server-side `limit`/`offset` only where
  the dataset is truly unbounded (raw events).
- Header row: `bg-surface text-[12.5px] uppercase tracking-wider text-dim`. Row hover
  `hover:bg-surface-2`. Empty state via `<EmptyState>` naming the one action that fixes it.
- **Wrap a table in `overflow-x-auto`, never `overflow-hidden`**, and give the table a `min-w-*`.
  Hidden overflow does not shrink a wide table, it silently CLIPS the right-hand columns: the
  Dashboard events table lost its Severity column this way, and Severity is the first thing an
  operator looks at. The min-width stops columns being squeezed into each other instead. Keep
  short status cells (`Severity`, badges) `whitespace-nowrap` so they never wrap mid-table.

## Icons

- **SVG only, never glyph characters.** Reuse the in-repo inline-SVG pattern (see the `ICONS`
  map + `NavIcon` in `components/Sidebar.tsx`): stroke paths on `viewBox 0 0 24 24`,
  `stroke="currentColor"`, ~1.7 width, so an icon inherits its parent's color. No icon package,
  by design the app must run fully offline. Size 16-18px inline, 20px in the sidebar. One icon =
  one meaning.

## Charts

- Use `recharts`. Every chart has **labelled X and Y axes with real values** (e.g. X = time,
  Y = attack count) and a **hover tooltip** showing the exact number (see `dashboard/widgets.tsx`).
  No axis-less sparkline as a primary chart. Axis/tooltip colors come from the tokens (`TIP`,
  `AXIS_TICK`); series colors from the palette; severity keeps its fixed colors.
- **A "top N" ranking is a list, not a plotted chart.** Use `BarList` (`dashboard/widgets.tsx`):
  label, proportional bar, exact count, one row each. A category axis thins its own ticks once the
  rows outnumber the vertical space, which silently drops labels: "Top source IPs" was rendering ten
  bars of which only five were identifiable, and an attack volume you cannot attribute to an IP
  answers nothing. Reach for an axis when the X value is continuous (time, score); reach for a list
  when the categories are arbitrary strings (IPs, ports, rule names, agents).

## Feedback & errors

- Loading → `<Skeleton>`; failure → `<ErrorText>` / `<NoticeBanner>` with the fix, never a silent
  blank. Destructive actions confirm first. Prefer disabling an impossible action over letting it
  fail.

## Rollout checklist

- [x] `<Page>`, `usePaged`/`<Pagination>` primitives
- [x] Tickets: status dropdown + pagination + `<Page>` (reference implementation)
- [x] Dashboard charts on `recharts` (axes + hover tooltip)
- [x] Sidebar icons are inline SVG (offline, no package)
- [x] `<Page>` applied to every page (Dashboard, Agents, Response, Rules, Decoders, Inventory, Users,
  Tenants, Workspaces, Playbooks, Integrations, Snapshots, Settings, FileIntegrity; Report keeps its
  own wrapper for the print `#report-print` id but matches Page's gutter)
- [x] `<Pagination>` on the growable tables (Agents, Rules, Response offenders+events, Decoders,
  Inventory vulns+packages, Users, Tenants, Playbooks, Integrations, FIM findings). Bounded
  operational/picker lists (Response whitelist/kills/contained, Workspaces + Snapshots pickers) stay
  unpaginated by design; Dashboard events use a server-side `limit`.
- [x] Glyph icons replaced with the shared inline-SVG `Icon` (close, chevrons, up/down, download,
  upload, external, filter, map, list, webhook, crosshair, plus, minus, drag)
- [x] All dashboard charts on recharts with non-clipping X/Y axes (incl. Event Trend By Tenant)
