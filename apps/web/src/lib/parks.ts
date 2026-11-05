import type { Server } from '../components/ServerParts'

/** A machine's group may name a park inside it: "Офис / Вентрейд" is the park "Вентрейд" of the group "Офис". */
export function splitGroup(group: string | undefined): { top: string; park: string } {
  const g = (group ?? '').trim()
  const i = g.indexOf('/')
  if (i < 0) return { top: g, park: '' }
  return { top: g.slice(0, i).trim(), park: g.slice(i + 1).trim() }
}

export interface Park { name: string; servers: Server[] } // name '' holds the machines of the group that have no park
export interface Block { name: string; count: number; parks: Park[]; hasParks: boolean }

const byName = (a: string, b: string) => (a === '' ? 1 : b === '' ? -1 : a.localeCompare(b, 'ru'))

/** Machines of one group stand together, and inside a group those of one park; both go by name, loose machines last. */
export function buildBlocks(list: Server[]): Block[] {
  const tops = new Map<string, Map<string, Server[]>>()
  for (const s of list) {
    const { top, park } = splitGroup(s.group)
    const inner = tops.get(top) ?? new Map<string, Server[]>()
    inner.set(park, [...(inner.get(park) ?? []), s])
    tops.set(top, inner)
  }
  return [...tops.keys()].sort(byName).map((name) => {
    const inner = tops.get(name)!
    const parks = [...inner.keys()].sort(byName).map((p) => ({ name: p, servers: inner.get(p)! }))
    return { name, count: parks.reduce((n, p) => n + p.servers.length, 0), parks, hasParks: parks.some((p) => p.name !== '') }
  })
}

/** What a collapsed park still has to say: how many of its machines need a look. */
export function parkSummary(servers: Server[]): { attention: number; worst: Server['status'] } {
  let attention = 0
  let worst: Server['status'] = 'ok'
  const rank = { ok: 0, unknown: 1, warn: 2, bad: 3 } as const
  for (const s of servers) {
    if (s.status === 'warn' || s.status === 'bad') attention++
    if (rank[s.status] > rank[worst]) worst = s.status
  }
  return { attention, worst }
}

/** The address to show for a machine: where its agent connects from, else the first one somebody wrote down. */
export function shownAddress(s: Server): string {
  if (s.external_ip) return s.external_ip
  return s.addresses?.find((a) => a.kind !== 'domain')?.address ?? ''
}

const KEY_VIEW = 'owl.servers.view'
const KEY_FOLDED = 'owl.servers.folded'

export type View = 'cards' | 'list'

export function loadView(): View | null {
  try {
    const v = localStorage.getItem(KEY_VIEW)
    return v === 'cards' || v === 'list' ? v : null
  } catch { return null }
}
export function saveView(v: View): void {
  try { localStorage.setItem(KEY_VIEW, v) } catch { /* a convenience only */ }
}
export function loadFolded(): Set<string> {
  try { return new Set<string>(JSON.parse(localStorage.getItem(KEY_FOLDED) ?? '[]')) } catch { return new Set() }
}
export function saveFolded(s: Set<string>): void {
  try { localStorage.setItem(KEY_FOLDED, JSON.stringify([...s])) } catch { /* a convenience only */ }
}
