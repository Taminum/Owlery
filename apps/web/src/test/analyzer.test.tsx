import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Sites from '../pages/Sites'
import { mockApi, owner, type Req } from './helpers'
import type { AMeta, DestResponse, SiteDetailResponse, SitesResponse, SubjectsResponse } from '../lib/types'

afterEach(() => vi.unstubAllGlobals())

const meta = (over: Partial<AMeta> = {}): AMeta => ({
  demo: false, state: 'ok', from: '2026-10-09T00:00:00Z', to: '2026-10-10T00:00:00Z', granularity_seconds: 3600, panel_ids: ['p-home'],
  metric_kind: 'connection_count', source: 'agent_access_log+router_clash_api', coverage: { nodes_total: 2, nodes_with_agent: 2 }, ...over,
})

const row = (key: string, kind: 'site' | 'domain', over = {}) => ({
  key, kind, connections: 10, share: 50, users: 1, nodes: 1, last_seen: '2026-10-09T10:00:00Z', ports: [443], bytes: null, router_connections: 0, ...over,
})

const subjects: SubjectsResponse = {
  subjects: [
    { subject: 'user:p-home|u1', kind: 'user', label: 'alexandra', panel_name: 'Home', connections: 5 },
    { subject: 'device:p-home|192.168.1.5', kind: 'device', label: 'Home PC (192.168.1.5)', panel_name: 'Home', connections: 9 },
  ],
}

function renderPage(path: string) {
  setCsrf('')
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="sites" element={<Sites />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const q = (r: Req) => new URL(r.url, 'http://x').searchParams

describe('services: a service opens into its sites and their hosts', () => {
  it('opens a service to show its sites and the hosts below them, scoped to the chosen subject', async () => {
    const calls: Req[] = []
    mockApi({
      me: owner,
      handler: (r) => {
        calls.push(r)
        if (r.path === '/api/v1/analytics/subjects') return { status: 200, body: subjects }
        if (r.path === '/api/v1/analytics/destinations') {
          const p = q(r)
          const g = p.get('group_by')
          const rows = g === 'host'
            ? [row('www.pixiv.net', 'domain', { connections: 6, service: 'pixiv', category: 'Аниме и арт' }), row('i.pximg.net', 'domain', { connections: 4 })]
            : g === 'site'
              ? [row('pixiv.net', 'site', { connections: 10, service: 'pixiv', category: 'Аниме и арт', bytes: 2048, router_connections: 10 })]
              : [{ ...row('pixiv', 'domain', { connections: 10 }), kind: 'service', service: 'pixiv' }]
          const body: DestResponse = { meta: meta(), group_by: g as 'host', rows, groups: rows.length, total_connections: 10, limit: 50, offset: 0 } as DestResponse
          return { status: 200, body }
        }
        return undefined
      },
    })
    renderPage('/sites?view=services')
    expect(await screen.findByRole('tab', { name: 'Службы', selected: true })).toBeInTheDocument()
    await userEvent.click(await screen.findByRole('button', { name: /Показать поддомены: pixiv$/ }))
    expect(await screen.findByText('pixiv.net')).toBeInTheDocument()
    expect(screen.getByText('2,00 КБ')).toBeInTheDocument() // bytes exist only for router rows
    expect(screen.queryByText('www.pixiv.net')).not.toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /Показать поддомены: pixiv.net/ }))
    expect(await screen.findByText('www.pixiv.net')).toBeInTheDocument()
    expect(screen.getByText('i.pximg.net')).toBeInTheDocument()
    const hostCall = calls.filter((c) => c.path === '/api/v1/analytics/destinations' && q(c).get('group_by') === 'host').at(-1)!
    expect(q(hostCall).get('site')).toBe('pixiv.net')
    expect(q(hostCall).get('service')).toBe('pixiv') // the service filter travels down with the site

    // Choosing a device narrows the request; clearing it removes the parameter.
    await userEvent.selectOptions(screen.getByLabelText('Чей трафик'), 'device:p-home|192.168.1.5')
    await waitFor(() => {
      const last = calls.filter((c) => c.path === '/api/v1/analytics/destinations' && q(c).get('group_by') === 'service').at(-1)!
      expect(q(last).get('subject')).toBe('device:p-home|192.168.1.5')
    })
    await userEvent.selectOptions(screen.getByLabelText('Чей трафик'), '')
    await waitFor(() => {
      const last = calls.filter((c) => c.path === '/api/v1/analytics/destinations' && q(c).get('group_by') === 'service').at(-1)!
      expect(q(last).has('subject')).toBe(false)
    })
  })

  it('shows rows without router data as "no bytes", not zero', async () => {
    mockApi({
      me: owner,
      handler: (r) => {
        if (r.path === '/api/v1/analytics/subjects') return { status: 200, body: { subjects: [] } }
        if (r.path === '/api/v1/analytics/destinations') return { status: 200, body: { meta: meta(), group_by: 'host', rows: [row('example.org', 'domain')], groups: 1, total_connections: 10, limit: 50, offset: 0 } }
        return undefined
      },
    })
    renderPage('/sites?view=addresses')
    const cell = (await screen.findByText('example.org')).closest('tr')!
    expect(within(cell).getByTitle(/Нет данных о байтах/)).toHaveTextContent('—')
    expect(within(cell).queryByText(/0 Б/)).not.toBeInTheDocument()
  })
})

describe('addresses: who owns a bare IP', () => {
  it('names the owner next to an address, and groups bare IPs by owner on the Networks view', async () => {
    const calls: Req[] = []
    mockApi({
      me: owner,
      handler: (r) => {
        calls.push(r)
        if (r.path === '/api/v1/analytics/subjects') return { status: 200, body: { subjects: [] } }
        if (r.path === '/api/v1/analytics/destinations') return { status: 200, body: { meta: meta(), group_by: 'ip', rows: [{ ...row('1.1.1.1', 'domain'), kind: 'ip', owner: 'Cloudflare, Inc.', asn: 13335 }, { ...row('192.0.2.7', 'domain'), kind: 'ip' }], groups: 2, total_connections: 20, limit: 50, offset: 0 } }
        if (r.path === '/api/v1/analytics/networks') return { status: 200, body: { meta: meta(), ip_only: 120, matched: 100, unknown: 20,
          rows: [{ asn: 13335, org: 'Cloudflare, Inc.', connections: 70, share: 70, ips: 12, bytes: null, examples: ['1.1.1.1', '1.0.0.1'] }, { asn: 15169, org: 'Google LLC', connections: 30, share: 30, ips: 4, bytes: null, examples: ['8.8.8.8'] }] } }
        return undefined
      },
    })
    renderPage('/sites?view=addresses')
    await userEvent.click(await screen.findByRole('button', { name: 'Только IP' }))
    const cf = (await screen.findByText('1.1.1.1')).closest('tr')!
    expect(within(cf).getByText('Cloudflare, Inc.')).toBeInTheDocument()
    expect(within((await screen.findByText('192.0.2.7')).closest('tr')!).queryByText(/Cloudflare|Google/)).not.toBeInTheDocument() // no owner known: nothing invented

    await userEvent.click(screen.getByRole('button', { name: 'Сети' }))
    const table = await screen.findByRole('table', { name: 'Кому принадлежат голые IP' })
    expect(within(table).getByText('Google LLC')).toBeInTheDocument()
    expect(within(table).getByText('AS15169')).toBeInTheDocument()
    expect(screen.getByText(/Владелец известен у 100 из 120 соединений без домена/)).toBeInTheDocument()
    expect(screen.getByText(/а не сайт и не то, что делал человек/)).toBeInTheDocument()
    expect(calls.some((c) => c.path === '/api/v1/analytics/networks')).toBe(true)
  })
})

describe('sites page', () => {
  const sitesBody = (): SitesResponse => ({
    meta: meta(),
    rows: [
      { site: 'pixiv.net', service: 'pixiv', category: 'Аниме и арт', classified: true, connections: 20, visits: 7, share: 60, users: 2, devices: 1, hosts: 3, bytes: 4096, router_connections: 20, ru_zone: false, blocked: 0, warp: 0, first_seen: '2026-10-09T08:00:00Z', last_seen: '2026-10-09T10:00:00Z' },
      { site: 'mystery.example', category: 'Не определена', classified: false, connections: 5, visits: 5, share: 15, users: 1, devices: 0, hosts: 1, bytes: null, router_connections: 0, ru_zone: true, blocked: 3, warp: 0, first_seen: '2026-10-09T08:00:00Z', last_seen: '2026-10-09T09:00:00Z' },
    ],
    categories: [
      { category: 'Аниме и арт', classified: true, sites: 1, connections: 20, visits: 7, share: 80, users: 2, bytes: 4096, router_connections: 20 },
      { category: 'Не определена', classified: false, sites: 1, connections: 5, visits: 5, share: 20, users: 1, bytes: null, router_connections: 0 },
    ],
    groups: 2, total_connections: 25, limit: 50, offset: 0,
  })
  const detailBody = (): SiteDetailResponse => ({
    meta: meta(), site: 'pixiv.net', service: 'pixiv', category: 'Аниме и арт', classified: true, connections: 20, visits: 7, users: 2, bytes: 4096,
    who: [
      { kind: 'device', label: 'Home PC (192.168.1.5)', panel_name: 'Home', subject: 'device:p-home|192.168.1.5', connections: 14, visits: 5, bytes: 3000, first_seen: '2026-10-09T08:00:00Z', last_seen: '2026-10-09T10:00:00Z' },
      { kind: 'user', label: 'alexandra', panel_name: 'Home', subject: 'user:p-home|u1', connections: 6, visits: 2, bytes: null, first_seen: '2026-10-09T08:00:00Z', last_seen: '2026-10-09T09:00:00Z' },
    ],
    hosts: [
      { host: 'www.pixiv.net', connections: 12, share: 60, users: 2, bytes: 3000, router_connections: 12, last_seen: '2026-10-09T10:00:00Z' },
      { host: 'app-api.pixiv.net', connections: 8, share: 40, users: 1, bytes: null, router_connections: 0, last_seen: '2026-10-09T09:00:00Z' },
    ],
    timeline: [{ ts: 1791500000, connections: 3 }, { ts: 1791503600, connections: 9 }],
  })

  it('lists sites with categories, says when a site is not classified, and opens who went there', async () => {
    const calls: Req[] = []
    mockApi({
      me: owner,
      handler: (r) => {
        calls.push(r)
        if (r.path === '/api/v1/analytics/subjects') return { status: 200, body: subjects }
        if (r.path === '/api/v1/analytics/sites') return { status: 200, body: sitesBody() }
        if (r.path === '/api/v1/analytics/sites/detail') return { status: 200, body: detailBody() }
        return undefined
      },
    })
    renderPage('/sites')
    expect(await screen.findByRole('button', { name: 'pixiv.net' })).toBeInTheDocument()
    const mystery = screen.getByRole('button', { name: 'mystery.example' }).closest('tr')!
    expect(within(mystery).getByText('Не определена')).toBeInTheDocument()
    expect(within(mystery).getAllByText('—').length).toBeGreaterThan(0) // no router bytes for it
    expect(within(mystery).getByText('3')).toBeInTheDocument() // what the node blocked

    await userEvent.click(screen.getByRole('button', { name: 'pixiv.net' }))
    expect(await screen.findByRole('heading', { name: 'Кто заходил' })).toBeInTheDocument()
    const who = within(screen.getByRole('table', { name: 'Кто заходил' }))
    expect(who.getByText('Home PC (192.168.1.5)')).toBeInTheDocument()
    expect(who.getByText('alexandra')).toBeInTheDocument()
    expect(within(screen.getByRole('table', { name: 'Поддомены' })).getByText('app-api.pixiv.net')).toBeInTheDocument()
    const d = calls.filter((c) => c.path === '/api/v1/analytics/sites/detail').at(-1)!
    expect(q(d).get('site')).toBe('pixiv.net')
  })

  it('opens the categories view and filters sites by the category clicked', async () => {
    const calls: Req[] = []
    mockApi({
      me: owner,
      handler: (r) => {
        calls.push(r)
        if (r.path === '/api/v1/analytics/subjects') return { status: 200, body: subjects }
        if (r.path === '/api/v1/analytics/sites') return { status: 200, body: sitesBody() }
        return undefined
      },
    })
    renderPage('/sites')
    await screen.findByRole('button', { name: 'pixiv.net' })
    await userEvent.click(screen.getByRole('tab', { name: 'Категории' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Аниме и арт' }))
    await waitFor(() => {
      const last = calls.filter((c) => c.path === '/api/v1/analytics/sites').at(-1)!
      expect(q(last).get('category')).toBe('Аниме и арт')
    })
    expect(screen.getByRole('button', { name: 'Сбросить категорию' })).toBeInTheDocument()
  })
})

describe('sites and domains: one page', () => {
  it('has six tabs, and shows the filters only where they apply', async () => {
    mockApi({
      me: owner,
      handler: (r) => {
        if (r.path === '/api/v1/analytics/subjects') return { status: 200, body: { subjects: [] } }
        if (r.path === '/api/v1/analytics/destinations') return { status: 200, body: { meta: meta(), group_by: 'service', rows: [], groups: 0, total_connections: 0, limit: 50, offset: 0 } }
        if (r.path === '/api/v1/analytics/sites') return { status: 200, body: { meta: meta(), rows: [], categories: [], groups: 0, total_connections: 0, limit: 50, offset: 0 } }
        return undefined
      },
    })
    renderPage('/sites')
    await screen.findByRole('tab', { name: 'Сайты', selected: true })
    expect(screen.getAllByRole('tab').map((x) => x.textContent)).toEqual(['Сайты', 'Категории', 'Службы', 'Адреса', 'Когда', 'Страны'])
    expect(screen.getByRole('group', { name: 'Зона сайта' })).toBeInTheDocument() // the zone belongs to the list of sites
    expect(screen.getByRole('button', { name: /Только новые/ })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'Службы' }))
    expect(screen.queryByRole('group', { name: 'Зона сайта' })).toBeNull()
    expect(screen.queryByRole('button', { name: /Только новые/ })).toBeNull()
    expect(screen.getByLabelText('Чей трафик')).toBeInTheDocument() // whose traffic and the search stay
    expect(screen.getByRole('searchbox')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'Адреса' }))
    expect(screen.getByRole('button', { name: 'Домены и IP', pressed: true })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'Страны' }))
    expect(screen.queryByRole('searchbox')).toBeNull() // a view of countries has nothing to search
  })
})
