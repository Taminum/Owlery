import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Routers from '../pages/Routers'
import { mockApi, owner } from './helpers'

afterEach(() => vi.unstubAllGlobals())

function renderPage() {
  setCsrf('')
  return render(
    <MemoryRouter initialEntries={['/routers']}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="routers" element={<Routers />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const device = (over: object = {}) => ({
  id: 'd1', name: 'Дом', kind: 'mikrotik', created_at: '2026-11-12T00:00:00Z', online: true, last_seen: new Date().toISOString(),
  view: {
    board: 'hAP ax3', version: '7.16', uptime: 86400, cpu: 7, mem_free: 600, mem_total: 1000, temp: 47, stats_at: new Date().toISOString(),
    ifaces: [{ name: 'ether1', rx: 2e9, tx: 1e9, up: true, rx_bps: 1.5e6, tx_bps: 3e5 }],
    clients: [{ ip: '192.168.88.20', mac: 'AA:BB:CC:DD:EE:01', host: 'home-pc' }],
  },
  ...over,
})

describe('Роутеры', () => {
  it('shows the state, the ports and the clients of a router', async () => {
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/net-devices' ? { status: 200, body: { devices: [device()] } } : undefined) })
    renderPage()
    expect(await screen.findByText('Дом')).toBeInTheDocument()
    expect(screen.getByText('на связи')).toBeInTheDocument()
    expect(screen.getByText('7%')).toBeInTheDocument()
    expect(screen.getByText('40%')).toBeInTheDocument()
    expect(screen.getByText('47 °C')).toBeInTheDocument()
    expect(screen.getByText('ether1')).toBeInTheDocument()
    expect(screen.getByText('home-pc')).toBeInTheDocument()
    expect(screen.getByText('192.168.88.20')).toBeInTheDocument()
  })

  it('says so when a router has gone quiet or has never reported', async () => {
    mockApi({
      me: owner,
      handler: (r) =>
        r.path === '/api/v1/net-devices'
          ? { status: 200, body: { devices: [device({ online: false, last_seen: '2026-11-12T01:00:00Z' }), device({ id: 'd2', name: 'Дача', online: false, last_seen: null, view: { board: '', version: '', uptime: 0, cpu: 0, mem_free: 0, mem_total: 0, ifaces: [], clients: [] } })] } }
          : undefined,
    })
    renderPage()
    expect(await screen.findByText('не отвечает')).toBeInTheDocument()
    expect(screen.getByText('ещё не присылал данные')).toBeInTheDocument()
    expect(screen.getByText(/Клиентов нет/)).toBeInTheDocument()
  })

  it('shows connections and NAT rules', async () => {
    const base = device()
    const view = { ...base.view, conn: 812, conn_max: 16384, top: [{ ip: '192.168.88.20', n: 300 }], nat: [{ chain: 'dstnat', action: 'dst-nat', packets: 5, bytes: 300, dst_port: '8080', to_addr: '192.168.88.20', to_ports: '80', comment: 'web' }] }
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/net-devices' ? { status: 200, body: { devices: [device({ view })] } } : undefined) })
    renderPage()
    expect(await screen.findByText('812')).toBeInTheDocument()
    expect(screen.getByText('из 16384 возможных')).toBeInTheDocument()
    expect(screen.getByText('300')).toBeInTheDocument()
    expect(screen.getByText('dstnat · dst-nat')).toBeInTheDocument()
    expect(screen.getByText(':8080 → 192.168.88.20:80')).toBeInTheDocument()
  })

  it('folds ports without a cable away until asked', async () => {
    const base = device()
    const ifaces = [...base.view.ifaces, { name: 'ether5', rx: 0, tx: 0, up: false, rx_bps: 0, tx_bps: 0 }]
    mockApi({ me: owner, handler: (r) => (r.path === '/api/v1/net-devices' ? { status: 200, body: { devices: [device({ view: { ...base.view, ifaces } })] } } : undefined) })
    renderPage()
    expect(await screen.findByText('ether1')).toBeInTheDocument()
    expect(screen.queryByText('ether5')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /Ещё 1 без кабеля/ }))
    expect(screen.getByText('ether5')).toBeInTheDocument()
  })

  it('renames a router', async () => {
    let sent = ''
    mockApi({
      me: owner,
      handler: (r) => {
        if (r.path === '/api/v1/net-devices/d1' && r.method === 'PATCH') { sent = JSON.stringify(r.body); return { status: 204, body: null } }
        if (r.path === '/api/v1/net-devices') return { status: 200, body: { devices: [device({ name: 'Дои' })] } }
        return undefined
      },
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Переименовать' }))
    fireEvent.change(screen.getByLabelText('Название'), { target: { value: 'Дом' } })
    fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
    await vi.waitFor(() => expect(sent).toBe('{"name":"Дом"}'))
  })

  it('creates a router and shows the script with its token once', async () => {
    const made = { token: 'd9.secretsecretsecretsecret', script: ':local hdr "Authorization: Bearer d9.secretsecretsecretsecret"', device: { name: 'Новый' } }
    mockApi({
      me: owner,
      handler: (r) => {
        if (r.path === '/api/v1/net-devices' && r.method === 'POST') return { status: 201, body: made }
        if (r.path === '/api/v1/net-devices') return { status: 200, body: { devices: [] } }
        return undefined
      },
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /Добавить роутер/ }))
    fireEvent.change(screen.getByLabelText('Название'), { target: { value: 'Новый' } })
    fireEvent.click(screen.getByRole('button', { name: 'Создать' }))
    expect(await screen.findByText(/Bearer d9\.secretsecretsecretsecret/)).toBeInTheDocument()
    expect(screen.getByText(/System → Scripts → Add/)).toBeInTheDocument()
  })
})

describe('Роутеры: OpenWrt', () => {
  it('asks for the kind and shows the ssh steps without a MikroTik scheduler command', async () => {
    const made = { token: 'd9.secretsecretsecretsecret', script: 'cat > /usr/bin/owlery-report.sh', device: { name: 'RouteRich', kind: 'openwrt' } }
    let sent = ''
    mockApi({
      me: owner,
      handler: (r) => {
        if (r.path === '/api/v1/net-devices' && r.method === 'POST') { sent = JSON.stringify(r.body); return { status: 201, body: made } }
        if (r.path === '/api/v1/net-devices') return { status: 200, body: { devices: [] } }
        return undefined
      },
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /Добавить роутер/ }))
    fireEvent.change(screen.getByLabelText('Тип роутера'), { target: { value: 'openwrt' } })
    fireEvent.change(screen.getByLabelText('Название'), { target: { value: 'RouteRich' } })
    fireEvent.click(screen.getByRole('button', { name: 'Создать' }))
    expect(await screen.findByText(/по SSH/)).toBeInTheDocument()
    expect(sent).toBe('{"name":"RouteRich","kind":"openwrt"}')
    expect(screen.queryByText(/System → Scripts/)).toBeNull()
    expect(screen.queryByText(/system scheduler add/)).toBeNull()
  })
})
