import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import { AwgClients } from '../components/AwgClients'
import { mockApi, owner, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString()
const peer = (over: object) => ({ id: 'p1', label: 'Телефон Анны', tunnel_ip: '10.8.1.4/32', key_short: 'AAAA11…111=', state: 'active', handshake_at: ago(60), first_seen: ago(9999), gone: false, download_total: 5e9, upload_total: 1e9, download_range: 3e9, upload_range: 2e8, total_download: 0, total_upload: 0, total_since: null, last_seen_at: ago(60), last_seen_source: 'live', expires_at: null, traffic_limit_bytes: null, used_bytes: 0, ...over })
const inst = { id: 'i1', panel_id: 'p-home', host: 'exit-nl', container: 'amnezia-awg2', interface: 'awg0', mode: 'read_only', report_fresh: true,
  peers: [peer({}), peer({ id: 'p2', label: 'Планшет', tunnel_ip: '10.8.2.3/32', state: 'stale', last_seen_at: ago(9 * 86400), last_seen_source: 'recorded', download_range: 0, upload_range: 0 }), peer({ id: 'p3', label: 'Удалённый', gone: true })] }

function renderCard(handler: (r: Req) => { status: number; body: unknown } | undefined) {
  setCsrf('')
  mockApi({ me: owner, handler })
  return render(
    <MemoryRouter initialEntries={['/x']}>
      <AuthProvider>
        <Routes><Route element={<Layout />}><Route path="x" element={<AwgClients range="24h" tz="UTC" />} /></Route></Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('Клиенты AmneziaWG в «Пользователях»', () => {
  it('lists the clients that are not gone, with state and traffic, and opens one with its chart and sites', async () => {
    const asked: string[] = []
    renderCard((r) => {
      asked.push(r.url)
      if (r.path === '/api/v1/awg') return { status: 200, body: { instances: [inst], period: '24h0m0s' } }
      if (r.path === '/api/v1/awg/peers/p1/series') return { status: 200, body: { bucket_seconds: 3600, from: '', to: '', points: [] } }
      if (r.path === '/api/v1/analytics/sites') return { status: 200, body: { meta: { state: 'ok' }, rows: [{ site: 'video.example', service: 'YouTube', connections: 120 }], categories: [], groups: 1, total_connections: 120, limit: 10, offset: 0 } }
      return undefined
    })
    expect((await screen.findAllByText('Клиенты AmneziaWG')).length).toBeGreaterThan(0)
    const table = screen.getByRole('table', { name: 'Клиенты AmneziaWG' })
    expect(within(table).getByText('Телефон Анны')).toBeInTheDocument()
    expect(within(table).getByText('Планшет')).toBeInTheDocument()
    expect(within(table).queryByText('Удалённый')).toBeNull()
    expect(within(table).getAllByText('exit-nl').length).toBe(2)
    await userEvent.click(within(table).getByRole('button', { name: 'Телефон Анны' }))
    expect(await screen.findByText('video.example')).toBeInTheDocument()
    expect(asked.some((a) => a.includes('/api/v1/analytics/sites') && decodeURIComponent(a).includes('subject=awg:p-home|10.8.1.4/32'))).toBe(true)
  })

  it('shows nothing when there are no clients', async () => {
    renderCard((r) => (r.path === '/api/v1/awg' ? { status: 200, body: { instances: [], period: '24h0m0s' } } : undefined))
    await new Promise((r) => setTimeout(r, 200))
    expect(screen.queryAllByText('Клиенты AmneziaWG')).toHaveLength(0)
  })
})
