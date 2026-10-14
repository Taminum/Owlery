import { api } from '../lib/api'
import { rangeToParams, type Filters } from '../lib/filters'
import { useLoad } from './useLoad'

const POLL = { off: 0, '1m': 60_000, '5m': 300_000 } as const

/** Builds the analyzer query from the shared filters (panel, nodes, range), plus page-specific params. */
export function analyticsURL(path: string, f: Filters, extra: Record<string, string> = {}): string {
  const p = new URLSearchParams(rangeToParams(f))
  if (f.panels.length) p.set('panel_ids', f.panels.join(','))
  if (f.nodes.length) p.set('node_ids', f.nodes.join(','))
  for (const [k, v] of Object.entries(extra)) if (v !== '') p.set(k, v)
  return `/api/v1/analytics/${path}?${p}`
}

export function useAnalytics<T>(path: string, f: Filters, extra: Record<string, string> = {}, enabled = true) {
  const url = analyticsURL(path, f, extra)
  const poll = enabled ? POLL[f.refresh] : 0
  const state = useLoad<T | null>((signal) => (enabled ? api.get<T>(url, signal) : Promise.resolve(null)), [url, enabled], poll)
  return { ...state, url }
}
