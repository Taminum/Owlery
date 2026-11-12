import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Settings from '../pages/Settings'
import { mockApi, owner } from './helpers'

afterEach(() => vi.unstubAllGlobals())

function renderPage(path: string) {
  setCsrf('')
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const health = (over: object = {}) => ({
  requests: { since: '2026-11-12T05:00:00Z', total: 1200, failed: 2, slow: 5, worst: [{ at: '2026-11-12T06:00:00Z', method: 'GET', path: '/api/v1/analytics/overview', status: 200, ms: 3400 }], hourly: [] },
  db_bytes: 5_000_000_000,
  db_samples: [{ day: '2026-11-01', bytes: 4_800_000_000 }, { day: '2026-11-12', bytes: 5_000_000_000 }],
  backups: [{ taken_at: new Date(Date.now() - 5 * 3_600_000).toISOString(), bytes: 1_000_000_000, ok: true }],
  backup_stale_hours: 30,
  ...over,
})

describe('panel health', () => {
  it('shows the counts, the size with its growth, the last good copy and the slowest request', async () => {
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/panel-health' ? { status: 200, body: health() } : undefined) })
    renderPage('/settings?tab=health')
    expect(await screen.findByText('Запросов за сутки')).toBeInTheDocument()
    expect(screen.getByText('1 200')).toBeInTheDocument()
    expect(screen.getByText(/Последняя удачная копия/)).toBeInTheDocument()
    expect(screen.getByText(/GET \/api\/v1\/analytics\/overview/)).toBeInTheDocument()
    expect(screen.getByText(/за 1 дн\./)).toBeInTheDocument()
  })

  it('says so when the copy is old or no report has come yet', async () => {
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/panel-health' ? { status: 200, body: health({ backups: [{ taken_at: new Date(Date.now() - 50 * 3_600_000).toISOString(), bytes: 10, ok: false }] }) } : undefined) })
    renderPage('/settings?tab=health')
    expect(await screen.findByText('Давно нет удачной копии')).toBeInTheDocument()
  })

  it('is not offered to anyone but the owner', async () => {
    mockApi({ me: { ...owner, account: { ...owner.account, is_owner: false } }, handler: () => undefined })
    renderPage('/settings')
    expect(await screen.findByRole('tab', { name: 'Мой профиль' })).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Здоровье панели' })).not.toBeInTheDocument()
  })
})
