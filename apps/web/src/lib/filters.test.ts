import { DEFAULT_FILTERS, parseFilters, sanitizeFilters, serializeFilters, setPanelScope } from './filters'
import type { PanelInfo } from './types'

const node = (id: string, panel_id: string) => ({ id, panel_id, name: id, agent_status: 'ok' as const, lag_seconds: 1 })
const panels: PanelInfo[] = [
  { id: 'home', name: 'Домашняя', nodes: [node('h1', 'home'), node('h2', 'home')] },
  { id: 'work', name: 'Рабочая', nodes: [node('w1', 'work')] },
]

describe('filters in the URL', () => {
  it('omits defaults so shared links stay short', () => {
    expect(serializeFilters(DEFAULT_FILTERS).toString()).toBe('')
  })

  it('round-trips panels, nodes, range, tz and refresh', () => {
    const f = { ...DEFAULT_FILTERS, panels: ['home'], nodes: ['h1', 'h2'], range: '7d' as const, tz: 'UTC', refresh: '5m' as const }
    expect(parseFilters(serializeFilters(f))).toEqual(f)
  })

  it('round-trips a custom range', () => {
    const f = { ...DEFAULT_FILTERS, range: 'custom' as const, from: '2026-10-01T00:00:00Z', to: '2026-10-02T00:00:00Z' }
    expect(parseFilters(serializeFilters(f))).toMatchObject({ range: 'custom', from: f.from, to: f.to })
  })

  it('falls back to defaults for junk values', () => {
    const f = parseFilters(new URLSearchParams('range=2y&tz=Mars/Base&refresh=1s'))
    expect(f).toMatchObject({ range: '24h', tz: 'local', refresh: 'off' })
  })

  it('never puts secrets or demo flags into shareable filters', () => {
    expect(serializeFilters({ ...DEFAULT_FILTERS, panels: ['home'] }).toString()).not.toMatch(/token|secret|demo/i)
  })
})

describe('panel scope and node selection', () => {
  it('clears node picks that fall outside a newly selected panel', () => {
    const f = { ...DEFAULT_FILTERS, nodes: ['h1', 'w1'] }
    expect(setPanelScope(f, ['work'], panels).nodes).toEqual(['w1'])
    expect(setPanelScope(f, ['home'], panels).nodes).toEqual(['h1'])
  })

  it('keeps node picks when scope is all panels', () => {
    const f = { ...DEFAULT_FILTERS, nodes: ['h1', 'w1'] }
    expect(setPanelScope(f, [], panels).nodes).toEqual(['h1', 'w1'])
  })

  it('drops unknown panels and nodes coming from a stale URL', () => {
    const f = sanitizeFilters({ ...DEFAULT_FILTERS, panels: ['ghost', 'home'], nodes: ['nope', 'h2'] }, panels)
    expect(f.panels).toEqual(['home'])
    expect(f.nodes).toEqual(['h2'])
  })

  it('returns the same object when nothing needs cleaning', () => {
    const f = { ...DEFAULT_FILTERS, panels: ['home'], nodes: ['h1'] }
    expect(sanitizeFilters(f, panels)).toBe(f)
  })
})
