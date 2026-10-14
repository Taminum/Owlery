import { formatBytes, formatClock, formatInt, formatPct, plural } from './format'
import { overviewURL } from './api'
import { DEFAULT_FILTERS } from './filters'

describe('formatting', () => {
  it('formats counts with Russian grouping', () => {
    expect(formatInt(22621).replace(/\s/g, ' ')).toBe('22 621')
  })

  it('uses a decimal comma for percentages', () => {
    expect(formatPct(98.7)).toBe('98,7%')
  })

  it('scales bytes into binary-based Russian units', () => {
    expect(formatBytes(0)).toBe('0 Б')
    expect(formatBytes(1536)).toBe('1,50 КБ')
    expect(formatBytes(8.5 * 1024 ** 3)).toBe('8,50 ГБ')
  })

  it('renders clock time in the chosen zone, not the machine zone', () => {
    const iso = '2026-10-09T12:00:00Z'
    expect(formatClock(iso, 'UTC')).toBe('12:00')
    expect(formatClock(iso, 'Asia/Yekaterinburg')).toBe('17:00')
  })
})

describe('overview request', () => {
  it('sends scope and range as query params only', () => {
    const url = overviewURL({ ...DEFAULT_FILTERS, panels: ['p1'], nodes: ['n1', 'n2'], range: '1h' })
    expect(url).toBe('/api/v1/overview?range=1h&panel_ids=p1&node_ids=n1%2Cn2')
  })

  it('uses from/to for a custom range', () => {
    const url = overviewURL({ ...DEFAULT_FILTERS, range: 'custom', from: '2026-10-01T00:00:00Z', to: '2026-10-02T00:00:00Z' })
    expect(url).toContain('from=2026-10-01T00%3A00%3A00Z')
    expect(url).not.toContain('range=')
  })
})

describe('russian plurals', () => {
  const nodes = (n: number) => plural(n, 'нода', 'ноды', 'нод')
  it('follows the one / few / many rules, including the teens', () => {
    expect([0, 1, 2, 4, 5, 11, 12, 14, 21, 22, 25, 101, 111].map(nodes)).toEqual(
      ['нод', 'нода', 'ноды', 'ноды', 'нод', 'нод', 'нод', 'нод', 'нода', 'ноды', 'нод', 'нода', 'нод'])
  })
})
