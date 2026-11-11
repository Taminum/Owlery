import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Alerts from '../pages/Alerts'
import { groupAlerts, historyStats, kindClass, minutesText, type AlertItem } from '../lib/alertGroups'
import { mockApi, owner } from './helpers'

afterEach(() => vi.unstubAllGlobals())

const at = (day: number, h: number, m = 0) => new Date(Date.UTC(2026, 10, day, h, m)).toISOString()
let n = 0
const alert = (kind: string, subject: string, label: string, opened: string, mins: number | null, over: Partial<AlertItem> = {}): AlertItem => ({
  id: `a${++n}`, panel_id: 'p', panel_name: 'Main', kind, subject, label, detail: 'подробности', opened_at: opened,
  last_seen_at: opened, resolved_at: mins === null ? null : new Date(new Date(opened).getTime() + mins * 60000).toISOString(), ...over,
})

const history: AlertItem[] = [
  alert('host_mem', 'bb', 'Память почти кончилась: home-pc', at(9, 10), 5),
  alert('host_mem', 'bb', 'Память почти кончилась: home-pc', at(9, 14), 3),
  alert('host_mem', 'bb', 'Память почти кончилась: home-pc', at(10, 9), 7),
  alert('host_disk', 'bb:C:', 'Диск почти полон: home-pc C:', at(5, 8), 60 * 30),
  alert('host_disk', 'bb:D:', 'Диск почти полон: home-pc D:', at(6, 8), 60),
  alert('probe_down', 'pr1', 'Канал Helsinki CDN', at(2, 3), 8),
  alert('dns_change', 'dm1', 'DNS: изменения у example.org', at(1, 12), 1440),
]

describe('folding the repeats of an alert', () => {
  it('makes one group of the same kind about the same thing, the most frequent first, and keeps what is different apart', () => {
    const g = groupAlerts(history)
    expect(g.map((x) => [x.label, x.items.length])).toEqual([
      ['Память почти кончилась: home-pc', 3], ['Диск почти полон: home-pc D:', 1], ['Диск почти полон: home-pc C:', 1], ['Канал Helsinki CDN', 1], ['DNS: изменения у example.org', 1],
    ]) // the same size: the one that came last comes first
    expect(g[0].typicalMin).toBe(5) // the middle of 3, 5 and 7
    expect(g[0].items.map((a) => a.opened_at)).toEqual([at(10, 9), at(9, 14), at(9, 10)]) // newest first
    expect(g[0].first).toBe(at(9, 10))
    expect(g[0].last).toBe(at(10, 9))
  })

  it('has no typical length for one that never closed', () => {
    expect(groupAlerts([alert('host_mem', 'x', 'Память: x', at(9, 1), null)])[0].typicalMin).toBeNull()
  })

  it('sorts alerts into the kinds the filter offers', () => {
    expect(['host_mem', 'host_flood', 'sec_tls', 'sec_port'].map(kindClass)).toEqual(['machines', 'machines', 'machines', 'machines'])
    expect(['probe_down', 'panel_sync'].map(kindClass)).toEqual(['channels', 'channels'])
    expect(['agent_silent', 'sec_agent_silent', 'awg_down'].map(kindClass)).toEqual(['agents', 'agents', 'agents'])
    expect(['dns_change', 'dns_check_failed'].map(kindClass)).toEqual(['dns', 'dns'])
    expect(['bill_due', 'user_expiry'].map(kindClass)).toEqual(['other', 'other'])
  })

  it('counts the last thirty days, names the one that repeats most and the one that lasted longest', () => {
    const now = new Date(Date.UTC(2026, 10, 11, 12)).getTime()
    const s = historyStats([...history, alert('host_disk', 'old', 'Диск: давний', new Date(now - 40 * 86_400_000).toISOString(), 10)], now)
    expect(s.count30).toBe(history.length) // the old one is out
    expect(s.kinds30).toBe(5)
    expect(s.mostRepeated?.label).toBe('Память почти кончилась: home-pc')
    expect(s.longest).toEqual({ label: 'Диск почти полон: home-pc C:', minutes: 1800 }) // longer than the DNS change (1440)
  })

  it('writes a length in words', () => {
    expect(minutesText(5)).toBe('5 мин')
    expect(minutesText(80)).toMatch(/1 ч/)
    expect(minutesText(60 * 51)).toMatch(/2 д/)
  })
})

function open() {
  setCsrf('')
  mockApi({ me: owner, handler: (r) => {
    if (r.path === '/api/v1/alerts') return { status: 200, body: { alerts: history, open: 0 } }
    if (r.path === '/api/v1/modules') return { status: 200, body: { modules: [] } }
    return undefined
  } })
  return render(
    <MemoryRouter initialEntries={['/alerts']}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="alerts" element={<Alerts />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const rows = () => screen.getAllByRole('row').slice(1)

describe('the alerts page: history in groups', () => {
  it('shows one row for the repeats, with how many and a link to the machine tab for those with a threshold', async () => {
    open()
    await screen.findByRole('button', { name: 'Память почти кончилась: home-pc' })
    expect(rows()).toHaveLength(5) // seven alerts, five groups
    const first = rows()[0]
    expect(within(first).getByText('3')).toBeInTheDocument()
    expect(within(first).getByRole('link', { name: 'Настроить порог…' })).toHaveAttribute('href', '/servers/bb?view=alerts')
    expect(within(rows()[3]).queryByRole('link')).toBeNull() // a channel has no threshold to set
  })

  it('opens every case of a group, switches to one row per alert, and filters by kind', async () => {
    open()
    await userEvent.click(await screen.findByRole('button', { name: 'Память почти кончилась: home-pc' }))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getAllByRole('row').slice(1)).toHaveLength(3)
    await userEvent.keyboard('{Escape}')
    await userEvent.click(screen.getByRole('button', { name: 'По одной' }))
    expect(rows()).toHaveLength(7)
    await userEvent.click(screen.getByRole('button', { name: 'Каналы' }))
    expect(rows()).toHaveLength(1)
    await userEvent.click(screen.getByRole('button', { name: 'Группами' }))
    expect(rows()).toHaveLength(1)
  })

  it('tells the numbers above the history', async () => {
    open()
    await screen.findByText('Чаще всех повторяется')
    expect(screen.getByText('3 раз, обычно по 5 мин')).toBeInTheDocument()
  })
})
