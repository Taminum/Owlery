import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import { Timeline } from '../components/Timeline'
import { mockApi, owner, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

const row = (over: object) => ({ site: 'youtube.com', service: 'YouTube', host: 'www.youtube.com', hosts: 2, start: '2026-11-12T17:15:00Z', end: '2026-11-12T17:20:00Z', connections: 9, bytes: null,
  src: 'router', kind: 'device', label: 'Ноутбук (192.168.1.5)', panel_name: 'home', ...over })

function renderTl(q: string, handler: (r: Req) => { status: number; body: unknown } | undefined) {
  setCsrf('')
  mockApi({ me: owner, handler })
  return render(
    <MemoryRouter initialEntries={['/x']}>
      <AuthProvider>
        <Routes><Route element={<Layout />}><Route path="x" element={<Timeline q={q} subject="" />} /></Route></Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const cov = { nodes_total: 1, nodes_with_agent: 1 }
const base = { from: '2026-11-06T00:00:00Z', to: '2026-11-13T00:00:00Z', source: 'agent_access_log', coverage: cov }
const meta = { ...base, state: 'ok' }

describe('Лента по домену', () => {
  it('asks for nothing until something is typed', async () => {
    const asked: string[] = []
    renderTl('', (r) => { asked.push(r.path); return undefined })
    expect(await screen.findByText(/Введите часть домена/)).toBeInTheDocument()
    expect(asked.includes('/api/v1/analytics/timeline')).toBe(false)
  })

  it('lists visits by day with who and where from, and pages back from the last one shown', async () => {
    const asked: string[] = []
    renderTl('youtube', (r) => {
      if (r.path !== '/api/v1/analytics/timeline') return undefined
      asked.push(decodeURIComponent(r.url))
      if (r.url.includes('before=')) return { status: 200, body: { meta, rows: [row({ site: 'ytimg.com', service: 'YouTube', start: '2026-11-10T19:30:00Z', end: '2026-11-10T19:40:00Z', label: 'Телевизор' })], more: false, totals: { visits: 3, connections: 40, sites: 3, last: '2026-11-12T17:20:00Z' } } }
      return { status: 200, body: { meta, rows: [
        row({}),
        row({ site: 'googlevideo.com', src: 'node', node: 'exit-nl', label: 'Телефон Миша', kind: 'user', start: '2026-11-12T10:00:00Z', end: '2026-11-12T11:00:00Z', connections: 214 }),
      ], more: true, totals: { visits: 3, connections: 40, sites: 3, last: '2026-11-12T17:20:00Z' } } }
    })
    expect(await screen.findByText('youtube.com')).toBeInTheDocument()
    expect(screen.getByText('googlevideo.com')).toBeInTheDocument()
    expect(screen.getByText('Ноутбук (192.168.1.5)')).toBeInTheDocument()
    expect(screen.getAllByText('роутер').length).toBe(2) // the chip and the source filter
    expect(screen.getByText('VPN, exit-nl')).toBeInTheDocument()
    expect(screen.getByText(/Видно только домены/)).toBeInTheDocument()
    expect(asked[0]).toContain('q=youtube')
    await userEvent.click(screen.getByRole('button', { name: 'Показать ещё' }))
    expect(await screen.findByText('ytimg.com')).toBeInTheDocument()
    expect(asked.some((a) => a.includes('before=2026-11-12T10:00:00Z'))).toBe(true)
    expect(screen.queryByRole('button', { name: 'Показать ещё' })).toBeNull()
  })

  it('switches to every connection and says when nothing was found', async () => {
    const asked: string[] = []
    renderTl('zzz', (r) => {
      if (r.path !== '/api/v1/analytics/timeline') return undefined
      asked.push(r.url)
      return { status: 200, body: { meta, rows: [], more: false, totals: { visits: 0, connections: 0, sites: 0, last: null } } }
    })
    expect(await screen.findByText(/Ничего не нашлось/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Каждое соединение' }))
    await new Promise((r) => setTimeout(r, 50))
    expect(asked.some((a) => a.includes('raw=1'))).toBe(true)
  })
})
