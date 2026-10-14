import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Alerts from '../pages/Alerts'
import Channels from '../pages/Channels'
import Live from '../pages/Live'
import Settings from '../pages/Settings'
import Sites from '../pages/Sites'
import { member, mockApi, owner, type Req } from './helpers'
import type { AMeta, AlertsResponse, LiveResponse, Me, ProbesResponse, SitesResponse } from '../lib/types'

afterEach(() => vi.unstubAllGlobals())

const meta = (over: Partial<AMeta> = {}): AMeta => ({
  demo: false, state: 'ok', from: '2026-10-09T00:00:00Z', to: '2026-10-10T00:00:00Z', granularity_seconds: 3600, panel_ids: ['p-home'],
  metric_kind: 'connection_count', source: 'agent_access_log', coverage: { nodes_total: 2, nodes_with_agent: 2 }, ...over,
})
const q = (r: Req) => new URL(r.url, 'http://x').searchParams

function renderAt(path: string) {
  setCsrf('')
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="alerts" element={<Alerts />} />
            <Route path="live" element={<Live />} />
            <Route path="channels" element={<Channels />} />
            <Route path="sites" element={<Sites />} />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const alerts = (over: Partial<AlertsResponse> = {}): AlertsResponse => ({
  open: 1,
  alerts: [
    { id: 'a1', panel_id: 'p-home', panel_name: 'Home', kind: 'agent_silent', label: 'Агент ноды Helsinki', detail: 'не выходит на связь 12 мин; события за это время не собираются', opened_at: '2026-10-13T12:00:00Z', last_seen_at: '2026-10-13T12:10:00Z', resolved_at: null },
    { id: 'a2', panel_id: 'p-home', panel_name: 'Home', kind: 'panel_sync', label: 'Панель Main', detail: 'синхронизация не удаётся: 3 неудач подряд', opened_at: '2026-10-12T08:00:00Z', last_seen_at: '2026-10-12T09:00:00Z', resolved_at: '2026-10-12T09:05:00Z' },
  ],
  ...over,
})

describe('alerts', () => {
  it('shows what is wrong now, the history, and a badge in the menu', async () => {
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/alerts' ? { status: 200, body: alerts() } : undefined) })
    renderAt('/alerts')
    const open = await screen.findByLabelText('Открытые')
    expect(within(open).getByText('Агент ноды Helsinki')).toBeInTheDocument()
    expect(within(open).getByText(/не выходит на связь 12 мин/)).toBeInTheDocument()
    const history = screen.getByRole('table', { name: 'История' })
    expect(within(history).getByText('Панель Main')).toBeInTheDocument()
    expect(await screen.findByLabelText('Открытых оповещений: 1')).toBeInTheDocument()
  })

  it('says everything is fine when nothing is open, and shows no badge', async () => {
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/alerts' ? { status: 200, body: { alerts: [], open: 0 } } : undefined) })
    renderAt('/alerts')
    expect(await screen.findByText(/Всё в порядке/)).toBeInTheDocument()
    expect(screen.queryByLabelText(/Открытых оповещений/)).not.toBeInTheDocument()
  })
})

const sitesBody = (): SitesResponse => ({
  meta: meta(),
  rows: [
    { site: 'known.example', service: 'Known', category: 'Игры', classified: true, connections: 5, visits: 2, share: 50, users: 1, devices: 0, hosts: 1, bytes: null, router_connections: 0, ru_zone: false, blocked: 0, warp: 0, first_seen: '2026-10-09T08:00:00Z', last_seen: '2026-10-09T10:00:00Z' },
    { site: 'mystery.example', category: 'Не определена', classified: false, connections: 5, visits: 5, share: 50, users: 1, devices: 0, hosts: 1, bytes: null, router_connections: 0, ru_zone: false, blocked: 0, warp: 0, first_seen: '2026-10-09T08:00:00Z', last_seen: '2026-10-09T09:00:00Z' },
  ],
  categories: [], groups: 2, total_connections: 10, limit: 50, offset: 0,
})

describe('sites: new only, hand-made categories, activity', () => {
  it('asks only for new sites when the switch is on', async () => {
    const calls: Req[] = []
    mockApi({ me: owner, handler: (r) => { calls.push(r); if (r.path === '/api/v1/analytics/sites') return { status: 200, body: sitesBody() }; if (r.path === '/api/v1/analytics/subjects') return { status: 200, body: { subjects: [] } }; return undefined } })
    renderAt('/sites')
    await screen.findByRole('button', { name: 'mystery.example' })
    expect(q(calls.filter((c) => c.path === '/api/v1/analytics/sites').at(-1)!).has('new')).toBe(false)
    await userEvent.click(screen.getByRole('button', { name: 'Только новые' }))
    await waitFor(() => expect(q(calls.filter((c) => c.path === '/api/v1/analytics/sites').at(-1)!).get('new')).toBe('1'))
  })

  it('lets the owner set a category for a site, and offers the categories already in use', async () => {
    const calls: Req[] = []
    mockApi({
      me: owner,
      handler: (r) => {
        calls.push(r)
        if (r.path === '/api/v1/analytics/sites') return { status: 200, body: sitesBody() }
        if (r.path === '/api/v1/analytics/subjects') return { status: 200, body: { subjects: [] } }
        if (r.path === '/api/v1/rules' && r.method === 'GET') return { status: 200, body: { rules: [], categories: ['Игры', 'Музыка'], can_edit: true } }
        if (r.path === '/api/v1/rules' && r.method === 'POST') return { status: 201, body: { id: 'r1', pattern: 'mystery.example', service: 'Моё', category: 'Музыка', source: 'custom', created_at: null } }
        return undefined
      },
    })
    renderAt('/sites')
    await userEvent.click(await screen.findByRole('button', { name: 'Категория: mystery.example' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByRole('button', { name: 'Сохранить правило' })).toBeDisabled()
    await userEvent.type(within(dialog).getByLabelText('Категория'), 'Музыка')
    await userEvent.type(within(dialog).getByLabelText('Название сервиса'), 'Моё')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Сохранить правило' }))
    await waitFor(() => expect(calls.some((c) => c.method === 'POST' && c.path === '/api/v1/rules')).toBe(true))
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ pattern: 'mystery.example', category: 'Музыка', service: 'Моё' })
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument()) // closed, and the table reloads
  })

  it('does not offer to edit categories to anyone but the owner', async () => {
    const op: Me = member('operator', 'p-home')
    mockApi({ me: op, handler: (r) => { if (r.path === '/api/v1/analytics/sites') return { status: 200, body: sitesBody() }; if (r.path === '/api/v1/analytics/subjects') return { status: 200, body: { subjects: [] } }; return undefined } })
    renderAt('/sites')
    await screen.findByRole('button', { name: 'mystery.example' })
    expect(screen.queryByRole('button', { name: /Категория: mystery.example/ })).not.toBeInTheDocument()
  })

  it('draws the weekday-by-hour grid with the time zone offset in the request', async () => {
    const calls: Req[] = []
    const grid = Array.from({ length: 7 }, (_, d) => Array.from({ length: 24 }, (_, h) => (d === 4 && h === 17 ? 9 : 0)))
    mockApi({
      me: owner,
      handler: (r) => {
        calls.push(r)
        if (r.path === '/api/v1/analytics/sites') return { status: 200, body: sitesBody() }
        if (r.path === '/api/v1/analytics/subjects') return { status: 200, body: { subjects: [] } }
        if (r.path === '/api/v1/analytics/activity') return { status: 200, body: { meta: meta(), grid, max: 9, total: 9 } }
        return undefined
      },
    })
    renderAt('/sites')
    await userEvent.click(await screen.findByRole('button', { name: 'Когда' }))
    expect(await screen.findByLabelText('пт 17:00 9')).toBeInTheDocument()
    expect(screen.getByLabelText('пн 00:00 0')).toBeInTheDocument()
    expect(Number.isInteger(Number(q(calls.find((c) => c.path === '/api/v1/analytics/activity')!).get('tz_offset')))).toBe(true)
  })
})

describe('live', () => {
  const agent = (over = {}) => ({
    agent_id: 'ag1', name: 'OpenWrt', panel_id: 'p-home', panel_name: 'Home', live: true, age_ms: 800, connections: 42, up_bps: 125_000, down_bps: 2_500_000,
    devices: [
      { ip: '192.168.1.9', name: 'beelink', up_bps: 5_000, down_bps: 2_000_000, connections: 30 },
      { ip: '192.168.1.5', up_bps: 120_000, down_bps: 500_000, connections: 12 },
    ],
    series: [{ ts: 1791500000000, up_bps: 100, down_bps: 200, connections: 3 }, { ts: 1791500002000, up_bps: 125_000, down_bps: 2_500_000, connections: 42 }], ...over,
  })

  it('shows speeds in bits per second, the busiest device first, and keeps polling', async () => {
    const body: LiveResponse = { agents: [agent()], has_router: true }
    const calls: Req[] = []
    mockApi({ me: owner, handler: (r) => { calls.push(r); return r.path === '/api/v1/live' ? { status: 200, body } : undefined } })
    renderAt('/live')
    expect(await screen.findByText('в эфире')).toBeInTheDocument()
    expect(screen.getByText('20,0 Мбит/с')).toBeInTheDocument() // 2 500 000 B/s
    expect(screen.getByText('1,00 Мбит/с')).toBeInTheDocument() // 125 000 B/s
    expect(screen.getByText('42')).toBeInTheDocument()
    const rows = within(screen.getByRole('table', { name: 'Устройства' })).getAllByRole('row').slice(1)
    expect(rows[0]).toHaveTextContent('beelink')
    expect(rows[1]).toHaveTextContent('192.168.1.5')
    expect(calls.filter((c) => c.path === '/api/v1/live').length).toBeGreaterThan(0)
  })

  it('labels the share column honestly and makes the shares add up to the whole', async () => {
    const body: LiveResponse = { agents: [agent()], has_router: true }
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/live' ? { status: 200, body } : undefined) })
    renderAt('/live')
    const head = await screen.findByRole('columnheader', { name: 'Доля скорости' })
    expect(head).toHaveAttribute('title', expect.stringContaining('Это не загрузка канала'))
    expect(screen.queryByRole('columnheader', { name: 'Загрузка' })).not.toBeInTheDocument()
    // 2 005 000 and 620 000 bytes per second: 76,4% and 23,6% of the total.
    expect(screen.getByText('76,4%')).toBeInTheDocument()
    expect(screen.getByText('23,6%')).toBeInTheDocument()
  })

  it('draws straight segments by default and smooths only when asked, remembering the choice', async () => {
    const body: LiveResponse = { agents: [agent()], has_router: true }
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/live' ? { status: 200, body } : undefined) })
    localStorage.removeItem('remnascope.smooth')
    renderAt('/live')
    const toggle = await screen.findByRole('button', { name: 'Сглаживание графиков' })
    expect(toggle).toHaveAttribute('aria-pressed', 'false')
    await userEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-pressed', 'true')
    expect(localStorage.getItem('remnascope.smooth')).toBe('1')
    await userEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-pressed', 'false')
    expect(localStorage.getItem('remnascope.smooth')).toBe('0')
  })

  it('does not present a quiet agent as current', async () => {
    const body: LiveResponse = { agents: [agent({ live: false, age_ms: 45_000, devices: [], up_bps: 0, down_bps: 0, connections: 0 })], has_router: true }
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/live' ? { status: 200, body } : undefined) })
    renderAt('/live')
    expect(await screen.findByText('молчит 45 с')).toBeInTheDocument()
    expect(screen.getByText('Агент молчит: список устройств сейчас показать нечем.')).toBeInTheDocument()
    expect(screen.queryByText('20,0 Мбит/с')).not.toBeInTheDocument()
  })

  it('explains the two empty states differently', async () => {
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/live' ? { status: 200, body: { agents: [], has_router: false } } : undefined) })
    const { unmount } = renderAt('/live')
    expect(await screen.findByText('Роутер не подключён')).toBeInTheDocument()
    unmount()
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/live' ? { status: 200, body: { agents: [], has_router: true } } : undefined) })
    renderAt('/live')
    expect(await screen.findByText('Ждём первые данные от роутера')).toBeInTheDocument()
  })
})

describe('channels', () => {
  const target = (over = {}) => ({
    id: 't1', panel_id: 'p-home', panel_name: 'Home', name: 'Мобильный CDN', host: 'fi.example.com', port: 7443, mode: 'tls' as const, enabled: true,
    state: 'up' as const, last_at: '2026-10-13T12:00:00Z', connect_ms: 52, tls_ms: 120, samples_1h: 60, loss_pct: 1.7, p50_connect_ms: 48, p50_tls_ms: 115,
    series: [{ ts: 1791500000, ms: 100, samples: 10, failed: 0 }, { ts: 1791500600, ms: 130, samples: 10, failed: 1 }], ...over,
  })

  it('shows state, medians, loss and the way a failure ended', async () => {
    const body: ProbesResponse = { targets: [target(), target({ id: 't2', name: 'Прямой', state: 'down', last_error: 'timeout', loss_pct: 100, p50_connect_ms: null, p50_tls_ms: null }), target({ id: 't3', name: 'Старый', state: 'unknown' })], can_edit: true, max_per_panel: 20 }
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/probes' ? { status: 200, body } : undefined) })
    renderAt('/channels')
    expect(await screen.findByText('Мобильный CDN')).toBeInTheDocument()
    expect(screen.getByText('отвечает')).toBeInTheDocument()
    expect(screen.getByText('не отвечает')).toBeInTheDocument()
    expect(screen.getByText('таймаут')).toBeInTheDocument()
    expect(screen.getByText('нет свежих замеров')).toBeInTheDocument()
    expect(screen.getAllByText('115 мс').length).toBe(2) // two of the three channels have that median
    expect(screen.getAllByText('1,7%').length).toBe(2)
  })

  it('adds a channel and sends exactly what was typed', async () => {
    const calls: Req[] = []
    mockApi({
      me: owner,
      handler: (r) => {
        calls.push(r)
        if (r.path === '/api/v1/probes' && r.method === 'GET') return { status: 200, body: { targets: [], can_edit: true, max_per_panel: 20 } }
        if (r.path === '/api/v1/probes' && r.method === 'POST') return { status: 201, body: { id: 'x' } }
        return undefined
      },
    })
    renderAt('/channels')
    expect(await screen.findByText('Каналов для замера пока нет')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Добавить канал' }))
    const dlg = await screen.findByRole('dialog')
    const add = within(dlg).getByRole('button', { name: 'Добавить' })
    expect(add).toBeDisabled()
    await userEvent.type(within(dlg).getByLabelText('Название'), 'Helsinki прямой')
    await userEvent.type(within(dlg).getByLabelText('Домен или IP'), 'fi.example.com')
    await userEvent.click(add)
    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true))
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ panel_id: 'p-home', name: 'Helsinki прямой', host: 'fi.example.com', port: 443, mode: 'tls', sni: '' })
  })

  it('offers neither adding nor deleting to a viewer', async () => {
    const viewer: Me = member('viewer', 'p-home')
    mockApi({ me: viewer, handler: (r) => (r.path === '/api/v1/probes' ? { status: 200, body: { targets: [target()], can_edit: false, max_per_panel: 20 } } : undefined) })
    renderAt('/channels')
    await screen.findByText('Мобильный CDN')
    expect(screen.queryByRole('button', { name: 'Добавить канал' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Удалить канал/ })).not.toBeInTheDocument()
  })
})

describe('countries', () => {
  it('lists countries by share, says how many connections could be placed, and credits the data', async () => {
    const calls: Req[] = []
    mockApi({
      me: owner,
      handler: (r) => {
        calls.push(r)
        if (r.path === '/api/v1/analytics/sites') return { status: 200, body: sitesBody() }
        if (r.path === '/api/v1/analytics/subjects') return { status: 200, body: { subjects: [] } }
        if (r.path === '/api/v1/analytics/countries') return { status: 200, body: { meta: meta(), located: 90, no_ip: 30, unknown: 5, total_connections: 125,
          rows: [{ code: 'US', name: 'Соединенные Штаты', connections: 60, share: 66.7, users: 2, sites: 4, bytes: null }, { code: 'RU', name: 'Россия', connections: 30, share: 33.3, users: 1, sites: 2, bytes: 2048 }] } }
        return undefined
      },
    })
    renderAt('/sites')
    await userEvent.click(await screen.findByRole('button', { name: 'Страны' }))
    const list = await screen.findByRole('list', { name: 'Страны назначения' })
    expect(within(list).getByText('Россия')).toBeInTheDocument()
    expect(within(list).getByText('US')).toBeInTheDocument()
    expect(screen.getByText(/Страна известна у 90 из 125 соединений/)).toBeInTheDocument()
    expect(screen.getByText(/IP geolocation by DB-IP/)).toBeInTheDocument()
    expect(q(calls.filter((c) => c.path === '/api/v1/analytics/countries').at(-1)!).get('limit')).toBe('40')
  })
})

describe('settings: own category rules', () => {
  it('lists the owner rules and deletes one', async () => {
    const calls: Req[] = []
    mockApi({
      me: owner,
      handler: (r) => {
        calls.push(r)
        if (r.path === '/api/v1/rules' && r.method === 'GET') return { status: 200, body: { rules: [{ id: 'r1', pattern: 'mystery.example', service: 'Моё', category: 'Музыка', source: 'custom', created_at: null }], categories: ['Музыка'], can_edit: true } }
        if (r.path === '/api/v1/rules/r1' && r.method === 'DELETE') return { status: 204 }
        return undefined
      },
    })
    renderAt('/settings')
    await userEvent.click(await screen.findByRole('tab', { name: 'Правила' }).catch(() => screen.findByRole('button', { name: 'Правила' })))
    expect(await screen.findByText('mystery.example')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Удалить: mystery.example' }))
    await waitFor(() => expect(calls.some((c) => c.method === 'DELETE' && c.path === '/api/v1/rules/r1')).toBe(true))
  })
})
