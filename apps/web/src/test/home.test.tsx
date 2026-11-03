import { render, screen, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Home from '../pages/Home'
import { mockApi, owner, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

function renderHome() {
  setCsrf('')
  return render(
    <MemoryRouter initialEntries={['/']}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Home />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const GB = 1024 ** 3
const host = (cpu: number) => ({
  id: 'h', name: 'x', online: true, has_data: true, updated_at: new Date().toISOString(), os: 'Ubuntu', kernel: '', arch: 'amd64', cpu_model: '', cpus: 2,
  mem_total: 4 * GB, swap_total: 0, cpu, load1: 0.1, load5: 0, load15: 0, mem_used: 2 * GB, swap_used: 0, uptime: 1000, estab: 1, syn_recv: 0, rx_bps: 0, tx_bps: 0, rx_pps: 0,
  disks: [{ m: '/', fs: 'ext4', t: 100 * GB, u: 40 * GB }], procs: [], units: [], cpu_spark: [], mem_spark: [],
})
const server = (over: object) => ({
  id: 's1', name: 'exit-nl', roles: ['exit'], status: 'ok', reason: '', host: host(10), nodes: [], alerts_open: 0, alerts_critical: 0, ...over,
})

function backend(servers: object[], alerts: object[] = []) {
  mockApi({
    me: owner,
    handler: (r: Req) => {
      if (r.path === '/api/v1/servers') return { status: 200, body: { servers } }
      if (r.path === '/api/v1/alerts') return { status: 200, body: { alerts, open: alerts.length } }
    },
  })
}

describe('Home', () => {
  it('counts the machines and puts the troubled ones, worst first, in "needs attention"', async () => {
    backend([
      server({ id: 'a', name: 'calm-box' }),
      server({ id: 'b', name: 'warn-box', status: 'warn', reason: 'alerts', alerts_open: 2 }),
      server({ id: 'c', name: 'dead-box', status: 'bad', reason: 'offline', host: null }),
      server({ id: 'd', name: 'bare-box', status: 'unknown', reason: 'no_agent', host: null }),
    ])
    renderHome()
    const card = (await screen.findByText('Требует внимания')).closest('section') as HTMLElement
    const names = within(card).getAllByRole('link').map((l) => l.textContent ?? '')
    expect(names[0]).toMatch(/dead-box/)
    expect(names[1]).toMatch(/warn-box/)
    expect(within(card).queryByText(/calm-box|bare-box/)).toBeNull()
    expect(screen.getByText('Машин всего').nextElementSibling).toHaveTextContent('4')
    expect(screen.getByText('без связи: 1')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Нужно внимание' })).toBeInTheDocument() // one dead machine makes the whole banner red
  })

  it('says all is calm when nothing is wrong, and lists the open alerts', async () => {
    backend([server({})], [{ id: 'x', panel_id: 'p', panel_name: 'P', kind: 'k', label: 'Диск почти полон', detail: 'C: 95%', opened_at: new Date().toISOString(), last_seen_at: new Date().toISOString(), resolved_at: null }])
    renderHome()
    expect(await screen.findByText(/Сейчас всё спокойно/)).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Всё спокойно' })).toBeInTheDocument()
    expect(await screen.findByText('Диск почти полон')).toBeInTheDocument()
    expect(screen.getByText('C: 95%')).toBeInTheDocument()
  })

  it('invites to add the first machine when there are none', async () => {
    backend([])
    renderHome()
    expect(await screen.findByRole('link', { name: 'Добавить первую' })).toHaveAttribute('href', '/servers')
  })
})
