import type { PanelInfo } from './types'

export const RANGES = ['15m', '1h', '24h', '7d', '30d', 'custom'] as const
export type Range = (typeof RANGES)[number]
export const REFRESH = ['off', '1m', '5m'] as const
export type Refresh = (typeof REFRESH)[number]
export const TIMEZONES = ['local', 'UTC', 'Europe/Moscow', 'Asia/Yekaterinburg'] as const

export interface Filters {
  panels: string[] // empty = all available
  nodes: string[] // empty = all nodes of the selected panels
  range: Range
  from?: string // RFC3339, only for custom
  to?: string
  tz: string
  refresh: Refresh
}

export const DEFAULT_FILTERS: Filters = { panels: [], nodes: [], range: '24h', tz: 'local', refresh: 'off' }

const csv = (s: string | null) => (s ? s.split(',').filter(Boolean) : [])

export function parseFilters(sp: URLSearchParams): Filters {
  const range = RANGES.includes(sp.get('range') as Range) ? (sp.get('range') as Range) : DEFAULT_FILTERS.range
  const refresh = REFRESH.includes(sp.get('refresh') as Refresh) ? (sp.get('refresh') as Refresh) : 'off'
  const tz = sp.get('tz')
  const f: Filters = {
    panels: csv(sp.get('panels')),
    nodes: csv(sp.get('nodes')),
    range,
    tz: tz && (TIMEZONES as readonly string[]).includes(tz) ? tz : DEFAULT_FILTERS.tz,
    refresh,
  }
  if (range === 'custom') {
    f.from = sp.get('from') ?? undefined
    f.to = sp.get('to') ?? undefined
  }
  return f
}

// Only non-default values go to the URL, so shared links stay short and carry no secrets.
export function serializeFilters(f: Filters): URLSearchParams {
  const sp = new URLSearchParams()
  if (f.panels.length) sp.set('panels', f.panels.join(','))
  if (f.nodes.length) sp.set('nodes', f.nodes.join(','))
  if (f.range !== DEFAULT_FILTERS.range) sp.set('range', f.range)
  if (f.range === 'custom') {
    if (f.from) sp.set('from', f.from)
    if (f.to) sp.set('to', f.to)
  }
  if (f.tz !== DEFAULT_FILTERS.tz) sp.set('tz', f.tz)
  if (f.refresh !== 'off') sp.set('refresh', f.refresh)
  return sp
}

export function rangeToParams(f: Filters): Record<string, string> {
  if (f.range === 'custom') return { from: f.from ?? '', to: f.to ?? '' }
  return { range: f.range }
}

/** Drops panel/node ids that no longer exist or no longer match the panel scope. */
export function sanitizeFilters(f: Filters, panels: PanelInfo[]): Filters {
  const known = new Set(panels.map((p) => p.id))
  const keptPanels = f.panels.filter((id) => known.has(id))
  const scope = keptPanels.length ? panels.filter((p) => keptPanels.includes(p.id)) : panels
  const allowed = new Set(scope.flatMap((p) => p.nodes.map((n) => n.id)))
  const keptNodes = f.nodes.filter((id) => allowed.has(id))
  if (keptPanels.length === f.panels.length && keptNodes.length === f.nodes.length) return f
  return { ...f, panels: keptPanels, nodes: keptNodes }
}

/** Switching panel scope clears node picks that fall outside it. */
export function setPanelScope(f: Filters, panelIds: string[], panels: PanelInfo[]): Filters {
  return sanitizeFilters({ ...f, panels: panelIds }, panels)
}
