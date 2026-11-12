import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import NetworkMap from '../pages/NetworkMap'
import { mockApi, owner } from './helpers'

afterEach(() => vi.unstubAllGlobals())

function renderPage() {
  setCsrf('')
  return render(
    <MemoryRouter initialEntries={['/map']}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="map" element={<NetworkMap />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const view = (clients: object[], ifaces: object[] = []) => ({ board: 'hAP', conn: 800, ifaces, clients })
const devices = [
  { id: 'a', name: 'Дом', kind: 'mikrotik', online: true, last_seen: '2026-11-12T10:00:00Z', parent_id: null, view: view([{ ip: '192.168.88.20', mac: 'AA:01', host: 'home-pc' }], [{ name: 'bridge', up: true, rx_bps: 9e6, tx_bps: 9e6 }, { name: 'pppoe-out1', up: true, rx_bps: 5e5, tx_bps: 7e6 }]) },
  { id: 'b', name: 'RouteRich', kind: 'openwrt', online: true, last_seen: '2026-11-12T10:00:00Z', parent_id: 'a', view: view([{ ip: '192.168.1.5', mac: 'BB:01', host: 'tv' }]) },
  { id: 'c', name: 'Работа', kind: 'mikrotik', online: false, last_seen: '2026-11-12T01:00:00Z', parent_id: null, view: view([]) },
]

describe('Карта сети', () => {
  it('draws each edge router as a network of its own, with the router behind it nested', async () => {
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/net-devices' ? { status: 200, body: { devices } } : undefined) })
    renderPage()
    expect(await screen.findByText('Сеть «Дом»')).toBeInTheDocument()
    expect(screen.getByText('Сеть «Работа»')).toBeInTheDocument()
    expect(screen.queryByText('Сеть «RouteRich»')).toBeNull()
    expect(screen.getByText('RouteRich')).toBeInTheDocument()
    expect(screen.getByText('home-pc')).toBeInTheDocument()
    expect(screen.getByText('tv')).toBeInTheDocument()
    expect(screen.getByText(/порт pppoe-out1/)).toBeInTheDocument()
    expect(screen.getByText('не отвечает')).toBeInTheDocument()
  })

  it('hides the devices when only routers are wanted', async () => {
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/net-devices' ? { status: 200, body: { devices } } : undefined) })
    renderPage()
    expect(await screen.findByText('home-pc')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Только роутеры' }))
    expect(screen.queryByText('home-pc')).toBeNull()
    expect(screen.getByText('RouteRich')).toBeInTheDocument()
  })
})
