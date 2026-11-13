import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import { SubLeaks } from '../components/SubLeaks'
import { mockApi, owner, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

function renderIt(handler: (r: Req) => { status: number; body: unknown } | undefined) {
  setCsrf('')
  mockApi({ me: owner, handler })
  return render(
    <MemoryRouter initialEntries={['/x']}>
      <AuthProvider>
        <Routes><Route element={<Layout />}><Route path="x" element={<SubLeaks tz="UTC" />} /></Route></Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const row = (over: object) => ({ panel_id: 'p1', panel_name: 'home', user: '21', label: 'Друг Серёги', ips: 14, requests: 212, last: '2026-11-13T10:00:00Z', clients: ['Hiddify', 'v2rayN'], level: 'leak', ...over })

describe('Откуда берут подписки', () => {
  it('lists the subscriptions with many addresses, marks them, and shows where one was taken from', async () => {
    const asked: string[] = []
    renderIt((r) => {
      asked.push(r.url)
      if (r.path === '/api/v1/subscriptions/leaks/ips') {
        return { status: 200, body: { ips: [{ ip: '46.0.0.18', country: 'Россия', org: 'MTS', hosting: false, requests: 88, last: '2026-11-13T10:00:00Z', client: 'Hiddify' },
          { ip: '178.0.0.7', country: 'Германия', org: 'Hetzner Online', hosting: true, requests: 9, last: '2026-11-12T10:00:00Z', client: 'Streisand' }] } }
      }
      if (r.path !== '/api/v1/subscriptions/leaks') return undefined
      return { status: 200, body: { asked: 38, leaks: 1, new: 1, rows: [row({}), row({ user: '22', label: 'Тест-2', ips: 6, level: 'check', clients: ['Hiddify'] })] } }
    })
    expect(await screen.findByText('Друг Серёги')).toBeInTheDocument()
    expect(screen.getByText('утечка?')).toBeInTheDocument()
    expect(screen.getByText('проверить')).toBeInTheDocument()
    expect(screen.getByText('38')).toBeInTheDocument()
    expect(screen.getByText('14 IP')).toBeInTheDocument()
    expect(asked.some((u) => u.includes('days=7') && u.includes('min=5'))).toBe(true)

    await userEvent.click(screen.getByRole('button', { name: 'Друг Серёги' }))
    expect(await screen.findByText('46.0.0.18')).toBeInTheDocument()
    expect(screen.getByText('похоже на хостинг')).toBeInTheDocument()
    expect(asked.some((u) => u.includes('leaks/ips') && u.includes('panel_id=p1') && u.includes('user=21'))).toBe(true)

    await userEvent.click(screen.getByRole('button', { name: '30 дн.' }))
    await new Promise((r) => setTimeout(r, 50))
    expect(asked.some((u) => u.includes('leaks?days=30'))).toBe(true)
  })

  it('shows nothing until a panel has reported any subscription requests', async () => {
    renderIt((r) => (r.path === '/api/v1/subscriptions/leaks' ? { status: 200, body: { asked: 0, leaks: 0, new: 0, rows: [] } } : undefined))
    await new Promise((r) => setTimeout(r, 50))
    expect(screen.queryByText('Откуда берут подписки')).toBeNull()
  })
})
