import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Security, { SecurityDetail } from '../pages/Security'
import { mockApi, member, owner, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

function renderSec(path: string) {
  setCsrf('')
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="security" element={<Security />} />
            <Route path="security/:id" element={<SecurityDetail />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const vps = (over: object = {}) => ({
  id: 'v1', name: 'Helsinki', origin: 'manual', enabled: true, note: '', created_at: '2026-10-15T10:00:00Z', updated_at: '2026-10-15T10:00:00Z',
  addresses: [{ address: '203.0.113.7', kind: 'ipv4' }], links: [], can_edit: true, ...over,
})

describe('Security page', () => {
  it('lists servers and lets the owner add one', async () => {
    const api = mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/security/vps' && r.method === 'GET') return { status: 200, body: { items: [vps()], can_create: true } }
      if (r.path === '/api/v1/security/vps' && r.method === 'POST') return { status: 201, body: vps({ id: 'v2', name: 'Oslo' }) }
      if (r.path === '/api/v1/security/vps/v2') return { status: 200, body: vps({ id: 'v2', name: 'Oslo' }) }
    } })
    renderSec('/security')
    expect(await screen.findByText('Helsinki')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.7')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /Добавить сервер/ }))
    await userEvent.type(screen.getByLabelText('Название'), 'Oslo')
    await userEvent.type(screen.getByLabelText('Адреса'), '198.51.100.9')
    await userEvent.click(screen.getByRole('button', { name: 'Добавить' }))
    expect(await screen.findByRole('heading', { name: 'Oslo' })).toBeInTheDocument()
    const post = api.find('POST', '/api/v1/security/vps')[0]
    expect(post.body).toMatchObject({ name: 'Oslo', addresses: ['198.51.100.9'] })
  })

  it('shows no create button and an honest empty state to a viewer', async () => {
    mockApi({ me: member('viewer'), handler: (r: Req) => (r.path === '/api/v1/security/vps' ? { status: 200, body: { items: [], can_create: false } } : undefined) })
    renderSec('/security')
    expect(await screen.findByText('Серверов пока нет')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Добавить сервер/ })).toBeNull()
  })

  it('never shows a healthy state for collectors that are not connected', async () => {
    mockApi({ me: owner, handler: (r: Req) => (r.path === '/api/v1/security/vps/v1' ? { status: 200, body: vps() } : undefined) })
    renderSec('/security/v1')
    expect(await screen.findByText('Fail2ban')).toBeInTheDocument()
    expect(screen.getAllByText('нужен агент')).toHaveLength(4)
    expect(screen.getByText(/не значит, что всё в порядке/)).toBeInTheDocument()
  })
})
