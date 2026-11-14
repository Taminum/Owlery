import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import { SubDevices, SubTorrents } from '../components/SubProtection'
import { mockApi, owner, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

function renderIt(handler: (r: Req) => { status: number; body: unknown } | undefined) {
  setCsrf('')
  mockApi({ me: owner, handler })
  return render(
    <MemoryRouter initialEntries={['/x']}>
      <AuthProvider>
        <Routes><Route element={<Layout />}><Route path="x" element={<><SubTorrents tz="UTC" /><SubDevices /></>} /></Route></Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('Торренты и устройства подписок', () => {
  it('says plainly that nothing has come while the plugin and the HWID limit are off', async () => {
    renderIt((r) => {
      if (r.path === '/api/v1/subscriptions/torrents') return { status: 200, body: { days: 7, seen: false, reports: 0, subs: 0, nodes: 0, rows: [] } }
      if (r.path === '/api/v1/subscriptions/devices') return { status: 200, body: { days: 7, min: 5, seen: false, subs: 0, leaks: 0, rows: [] } }
      return undefined
    })
    expect(await screen.findByText(/Торрент-блокер выключен на панели/)).toBeInTheDocument()
    expect(await screen.findByText(/HWID-лимит выключен на панели/)).toBeInTheDocument()
  })

  it('lists who was caught and who has many devices', async () => {
    renderIt((r) => {
      if (r.path === '/api/v1/subscriptions/torrents') {
        return { status: 200, body: { days: 7, seen: true, reports: 14, subs: 2, nodes: 2, rows: [
          { panel_id: 'p1', panel_name: 'home', user: '21', label: 'Друг Серёги', reports: 9, recent: 6, nodes: ['Steal'], last: '2026-11-13T10:00:00Z', repeat: true },
          { panel_id: 'p1', panel_name: 'home', user: '22', label: 'Тест-2', reports: 5, recent: 1, nodes: ['Helsinki'], last: '2026-11-12T10:00:00Z', repeat: false }] } }
      }
      if (r.path === '/api/v1/subscriptions/devices') {
        return { status: 200, body: { days: 7, min: 5, seen: true, subs: 1, leaks: 1, rows: [{ panel_id: 'p1', panel_name: 'home', user: '21', label: 'Друг Серёги', devices: 11, ips: 9, level: 'leak' }] } }
      }
      return undefined
    })
    expect(await screen.findByText('Тест-2')).toBeInTheDocument()
    expect(screen.getByText('повторно')).toBeInTheDocument()
    expect(screen.getByText('9 раз')).toBeInTheDocument()
    expect(screen.getByText('11 устр.')).toBeInTheDocument()
    expect(screen.getByText('утечка?')).toBeInTheDocument()
    expect(screen.queryByText(/выключен на панели/)).toBeNull()
  })
})
