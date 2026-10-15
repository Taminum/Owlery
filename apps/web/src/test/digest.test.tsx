import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Digest from '../pages/Digest'
import { mockApi, owner, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

function renderDigest() {
  setCsrf('')
  return render(
    <MemoryRouter initialEntries={['/digest']}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="digest" element={<Digest />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const base = {
  from: '2026-10-14T12:00:00Z', to: '2026-10-15T12:00:00Z', new_sites: [], top_devices: [], new_devices: [], security_events: [],
  dns: null, open_alerts: 0, has_traffic: true, has_security: true,
}

describe('Digest page', () => {
  it('says plainly that nothing happened', async () => {
    mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/analytics/digest') return { status: 200, body: base }
    } })
    renderDigest()
    expect(await screen.findByText('Открытых оповещений нет.')).toBeInTheDocument()
    expect(screen.getByText('Новых сайтов за период нет.')).toBeInTheDocument()
    expect(screen.getByText('Журнал серверов за период пуст.')).toBeInTheDocument()
  })

  it('lists new sites, new devices, event counts and open alerts', async () => {
    mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/analytics/digest') {
        return { status: 200, body: {
          ...base, open_alerts: 1,
          new_sites: [{ site: 'example.org', category: 'Новости', connections: 12, users: 1, first_seen: '2026-10-15T10:00:00Z' }],
          new_devices: [{ panel_id: 'p1', panel_name: 'Main', ip: '192.168.1.50', name: 'Phone', up_bytes: 0, down_bytes: 1000, first_seen: '2026-10-15T09:00:00Z' }],
          security_events: [{ type: 'fail2ban.ban', category: 'fail2ban', severity: 'info', count: 42 }, { type: 'something.new', category: 'x', severity: 'warning', count: 1 }],
          dns: { total: 2, volatile: 1, failed_checks: 0 },
        } }
      }
    } })
    renderDigest()
    expect(await screen.findByText('example.org')).toBeInTheDocument()
    expect(screen.getByText('Phone')).toBeInTheDocument()
    expect(screen.getByText('Блокировок Fail2ban')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
    // A type the page has no wording for is shown as it is, not dropped.
    expect(screen.getByText('something.new')).toBeInTheDocument()
    expect(screen.getByText('Открытых оповещений: 1')).toBeInTheDocument()
    expect(screen.getByText('Подтверждённых изменений: 2')).toBeInTheDocument()
  })
})
