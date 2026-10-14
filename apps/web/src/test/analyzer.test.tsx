import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Destinations from '../pages/Destinations'
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
            <Route path="domains" element={<Destinations />} />
            <Route path="sites" element={<Sites />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const q = (r: Req) => new URL(r.url, 'http://x').searchParams

describe('domains: sites with their subdomains', () => {
  it('opens a site to show the hosts below it, scoped to the chosen subject', async () => {
    const calls: Req[] = []
    mockApi({
      me: owner,
      handler: (r) => {
        calls.push(r)
        if (r.path === '/api/v1/analytics/subjects') return { status: 200, body: subjects }
        if (r.path === '/api/v1/analytics/destinations') {
          const p = q(r)
          const rows = p.get('group_by') === 'host'
            ? [row('www.pixiv.net', 'domain', { connections: 6, service: 'pixiv', category: 'Аниме и арт' }), row('i.pximg.net', 'domain', { connections: 4 })]
            : [row('pixiv.net', 'site', { connections: 10, service: 'pixiv', category: 'Аниме и арт', bytes: 2048, router_connections: 10 })]
          const body: DestResponse = { meta: meta(), group_by: p.get('group_by') as 'host', rows, groups: rows.length, total_connections: 10, limit: 50, offset: 0 } as DestResponse
          return { status: 200, body }
        }
        return undefined
      },
    })
    renderPage('/domains')
    const site = await screen.findByText('pixiv.net')
    expect(site).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Сайты и поддомены' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByText('2,00 КБ')).toBeInTheDocument() // bytes exist only for router rows
    expect(screen.queryByText('www.pixiv.net')).not.toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /Показать поддомены: pixiv.net/ }))
    expect(await screen.findByText('www.pixiv.net')).toBeInTheDocument()
    expect(screen.getByText('i.pximg.net')).toBeInTheDocument()
    const hostCall = calls.filter((c) => c.path === '/api/v1/analytics/destinations' && q(c).get('group_by') === 'host').at(-1)!
    expect(q(hostCall).get('site')).toBe('pixiv.net')

    // Choosing a device narrows the request; clearing it removes the parameter.
    await userEvent.selectOptions(screen.getByLabelText('Чей трафик'), 'device:p-home|192.168.1.5')
    await waitFor(() => {
      const last = calls.filter((c) => c.path === '/api/v1/analytics/destinations' && q(c).get('group_by') === 'site').at(-1)!
      expect(q(last).get('subject')).toBe('device:p-home|192.168.1.5')
    })
    await userEvent.selectOptions(screen.getByLabelText('Чей трафик'), '')
    await waitFor(() => {
      const last = calls.filter((c) => c.path === '/api/v1/analytics/destinations' && q(c).get('group_by') === 'site').at(-1)!
      expect(q(last).has('subject')).toBe(false)
    })
  })

  it('shows rows without router data as "no bytes", not zero', async () => {
    mockApi({
      me: owner,
      handler: (r) => {
        if (r.path === '/api/v1/analytics/subjects') return { status: 200, body: { subjects: [] } }
        if (r.path === '/api/v1/analytics/destinations') return { status: 200, body: { meta: meta(), group_by: 'site', rows: [row('example.org', 'site')], groups: 1, total_connections: 10, limit: 50, offset: 0 } }
        return undefined
      },
    })
    renderPage('/domains')
    const cell = (await screen.findByText('example.org')).closest('tr')!
    expect(within(cell).getByTitle(/Нет данных о байтах/)).toHaveTextContent('—')
    expect(within(cell).queryByText(/0 Б/)).not.toBeInTheDocument()
  })
})

describe('domains: who owns a bare IP', () => {
  it('names the owner next to an address, and groups bare IPs by owner on the Networks tab', async () => {
    const calls: Req[] = []
    mockApi({
      me: owner,
      handler: (r) => {
        calls.push(r)
        if (r.path === '/api/v1/analytics/subjects') return { status: 200, body: { subjects: [] } }
        if (r.path === '/api/v1/analytics/destinations') return { status: 200, body: { meta: meta(), group_by: 'ip', rows: [{ ...row('1.1.1.1', 'domain'), kind: 'ip', owner: 'Cloudflare, Inc.', asn: 13335 }, { ...row('192.0.2.7', 'domain'), kind: 'ip' }], groups: 2, total_connections: 20, limit: 50, offset: 0 } }
        if (r.path === '/api/v1/analytics/networks') return { status: 200, body: { meta: meta(), ip_only: 120, matched: 100, unknown: 20,
          rows: [{ asn: 13335, org: 'Cloudflare, Inc.', connections: 70, share: 70, ips: 12, bytes: null, examples: ['1.1.1.1', '1.0.0.1'] }, { asn: 15169, org: 'Google LLC', connections: 30, share: 30, ips: 4, bytes: 2048, examples: ['8.8.8.8'] }] } }
        return undefined
      },
    })
    renderPage('/domains')
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

describe('domains: category, service, site, host tree', () => {
  it('opens a category into its services, a service into its sites, passing the filters down', async () => {
    const calls: Req[] = []
    const body = (group: string, rows: unknown[]) => ({ meta: meta(), group_by: group, rows, groups: rows.length, total_connections: 10, limit: 50, offset: 0 })
    mockApi({
      me: owner,
      handler: (r) => {
        calls.push(r)
        if (r.path === '/api/v1/analytics/subjects') return { status: 200, body: { subjects: [] } }
        if (r.path !== '/api/v1/analytics/destinations') return undefined
        const g = q(r).get('group_by')
        if (g === 'category') return { status: 200, body: body(g, [{ ...row('Аниме и арт', 'domain'), kind: 'category' }]) }
        if (g === 'service') return { status: 200, body: body(g, [{ ...row('pixiv', 'domain'), kind: 'service', service: 'pixiv' }]) }
        if (g === 'site') return { status: 200, body: body(g, [{ ...row('pixiv.net', 'site'), category: 'Аниме и арт' }]) }
        return { status: 200, body: body('site', []) }
      },
    })
    renderPage('/domains')
    await userEvent.click(await screen.findByRole('button', { name: 'Категории' }))
    await userEvent.click(await screen.findByRole('button', { name: /Показать поддомены: Аниме и арт/ }))
    await userEvent.click(await screen.findByRole('button', { name: /Показать поддомены: pixiv$/ }))
    expect(await screen.findByRole('button', { name: /Показать поддомены: pixiv.net/ })).toBeInTheDocument()
    const siteCall = calls.filter((c) => q(c).get('group_by') === 'site' && q(c).get('service') === 'pixiv').at(-1)!
    expect(q(siteCall).get('category')).toBe('Аниме и арт') // the category filter travels down with the service
    // The category is visible on a narrow screen too.
    expect(screen.getAllByText('Аниме и арт').length).toBeGreaterThan(1)
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
    await userEvent.click(screen.getByRole('button', { name: 'Категории' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Аниме и арт' }))
    await waitFor(() => {
      const last = calls.filter((c) => c.path === '/api/v1/analytics/sites').at(-1)!
      expect(q(last).get('category')).toBe('Аниме и арт')
    })
    expect(screen.getByRole('button', { name: 'Сбросить категорию' })).toBeInTheDocument()
  })
})
