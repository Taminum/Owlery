import { t } from '../i18n'
import type { AlertsResponse } from './types'

export type AlertItem = AlertsResponse['alerts'][number]

export type AlertGroup = {
  /** One kind of alert about one thing: "memory is low on home-pc" however many times it came. */
  key: string
  kind: string
  label: string
  panel_name: string
  /** Newest first. */
  items: AlertItem[]
  first: string
  last: string
  /** The middle length of the closed ones, in minutes; null when none has closed. */
  typicalMin: number | null
}

const minutesOf = (a: AlertItem): number | null => (a.resolved_at ? (new Date(a.resolved_at).getTime() - new Date(a.opened_at).getTime()) / 60000 : null)

function median(xs: number[]): number | null {
  if (xs.length === 0) return null
  const s = [...xs].sort((a, b) => a - b)
  return s[Math.floor(s.length / 2)]
}

/** Folds the repeats of the same alert into one group each. Order of the groups: the ones that came most often first. */
export function groupAlerts(list: AlertItem[]): AlertGroup[] {
  const by = new Map<string, AlertItem[]>()
  for (const a of list) {
    const key = `${a.kind}|${a.subject ?? a.label}`
    by.set(key, [...(by.get(key) ?? []), a])
  }
  const out: AlertGroup[] = []
  for (const [key, raw] of by) {
    const items = [...raw].sort((a, b) => b.opened_at.localeCompare(a.opened_at))
    out.push({
      key, kind: items[0].kind, label: items[0].label, panel_name: items[0].panel_name, items,
      first: items[items.length - 1].opened_at, last: items[0].opened_at,
      typicalMin: median(items.map(minutesOf).filter((m): m is number => m !== null)),
    })
  }
  return out.sort((a, b) => b.items.length - a.items.length || b.last.localeCompare(a.last))
}

export type KindClass = 'machines' | 'channels' | 'agents' | 'dns' | 'other'

/** What a kind of alert is about, for the filter above the history. */
export function kindClass(kind: string): KindClass {
  if (kind.startsWith('host_') || kind === 'sec_tls' || kind === 'sec_port') return 'machines'
  if (kind === 'probe_down' || kind === 'panel_sync') return 'channels'
  if (kind === 'agent_silent' || kind === 'sec_agent_silent' || kind.startsWith('awg_')) return 'agents'
  if (kind.startsWith('dns_')) return 'dns'
  return 'other'
}

/** A length of time in minutes, in words ("5 min", "1 h 20 min", "2 d 3 h"). */
export function minutesText(min: number): string {
  const m = Math.max(1, Math.round(min))
  if (m < 60) return t('srv.min', { n: m })
  const h = Math.floor(m / 60)
  if (h < 24) return t('srv.hours', { h, m: m % 60 })
  return t('srv.days', { d: Math.floor(h / 24), h: h % 24 })
}

export type HistoryStats = {
  /** Alerts opened in the last 30 days, and in how many different kinds-on-things they came. */
  count30: number
  kinds30: number
  mostRepeated: AlertGroup | null
  longest: { label: string; minutes: number } | null
}

export function historyStats(closedAndOpen: AlertItem[], now: number): HistoryStats {
  const since = now - 30 * 86_400_000
  const recent = closedAndOpen.filter((a) => new Date(a.opened_at).getTime() >= since)
  const groups = groupAlerts(closedAndOpen)
  let longest: HistoryStats['longest'] = null
  for (const a of closedAndOpen) {
    const m = minutesOf(a)
    if (m !== null && (!longest || m > longest.minutes)) longest = { label: a.label, minutes: m }
  }
  return { count30: recent.length, kinds30: groupAlerts(recent).length, mostRepeated: groups[0] && groups[0].items.length > 1 ? groups[0] : null, longest }
}
