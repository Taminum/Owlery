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

const hours = (bans: number[]) => bans.map((b, i) => ({ at: new Date(Date.UTC(2026, 10, 3, i)).toISOString(), bans: b, changes: 0, rdp: 0, alerts: 0, access: 0 }))
const summary = (over: object = {}) => ({
  from: '2026-11-03T00:00:00Z', to: '2026-11-04T00:00:00Z', hourly: hours([0, 0, 0]), top_ips: [], jails: [], recent: [],
  win: { machines: 0, rdp_failed: 0, rdp_ok: 0, threats: 0, defender_off: 0 },
  bans: { total: 0, servers: [] }, changes: { total: 0, items: [] }, tls: { problems: 0, nearest_end: null, nearest_host: '' },
  owlery: { logins: 3, failed_logins: 1, terminals: 1, screens: 0, desktops: 0 }, ...over,
})

function backend(servers: object[], sum: object = summary(), alerts: object[] = []) {
  mockApi({
    me: owner,
    handler: (r: Req) => {
      if (r.path === '/api/v1/servers') return { status: 200, body: { servers } }
      if (r.path === '/api/v1/alerts') return { status: 200, body: { alerts, open: alerts.length } }
      if (r.path === '/api/v1/summary') return { status: 200, body: sum }
    },
  })
}

describe('Home', () => {
  it('says how the farm is, and lists the machines with the ones that need attention first', async () => {
    backend([
      server({ id: 'a', name: 'calm-box' }),
      server({ id: 'b', name: 'warn-box', status: 'warn', reason: 'alerts', alerts_open: 2 }),
      server({ id: 'c', name: 'dead-box', status: 'bad', reason: 'offline', host: null }),
      server({ id: 'd', name: 'bare-box', status: 'unknown', reason: 'no_agent', host: null }),
    ])
    renderHome()
    expect(await screen.findByText('Нужно внимание')).toBeInTheDocument() // one dead machine makes the whole state red
    expect(screen.getByText(/без связи: 1/)).toBeInTheDocument()
    const table = (await screen.findByRole('heading', { name: 'Машины, сначала те, кому нужно внимание' })).closest('section') as HTMLElement
    const names = within(table).getAllByRole('link').map((l) => l.textContent ?? '').filter((x) => /-box$/.test(x))
    expect(names).toEqual(['dead-box', 'warn-box', 'bare-box', 'calm-box'])
    expect(screen.getByText('1 / 4')).toBeInTheDocument()
  })

  it('turns the night into numbers and lists: bans, the busiest machine, who was banned, what was hit, what changed', async () => {
    const soon = new Date(Date.now() + 21 * 86_400_000 + 3_600_000).toISOString()
    backend([server({})], summary({
      hourly: hours([20, 90, 10]),
      bans: { total: 120, servers: [{ name: 'exit-2', count: 80 }, { name: 'exit-nl', count: 30 }] },
      top_ips: [{ ip: '185.220.101.4', jail: 'sshd', count: 38, country: 'DE', country_name: 'Германия' }],
      jails: [{ name: 'sshd', count: 100 }, { name: 'odd-jail', count: 20 }],
      recent: [{ server: 'exit-nl', type: 'firewall.rules_changed', severity: 'warning', at: new Date().toISOString() }],
      changes: { total: 1, items: [] },
      tls: { problems: 0, nearest_end: soon, nearest_host: 'vm.example.com' },
    }))
    renderHome()
    const bans = (await screen.findAllByText('Атаки за сутки'))[0].closest('a') as HTMLElement
    expect(within(bans).getByText('120')).toBeInTheDocument()
    expect(screen.getByText('185.220.101.4')).toBeInTheDocument()
    expect(screen.getByText('Германия')).toBeInTheDocument()
    expect(screen.getByText('SSH')).toBeInTheDocument() // a known jail is named for what it protects
    expect(screen.getByText('odd-jail')).toBeInTheDocument() // an unknown one keeps its own name
    expect(screen.getByText('остальные')).toBeInTheDocument() // bans not on the top machines are one line, not lost
    expect(screen.getByText('правка брандмауэра')).toBeInTheDocument()
    expect(screen.getByText('21 день')).toBeInTheDocument()
    expect(screen.getByText('vm.example.com')).toBeInTheDocument()
  })

  it('says nothing happened when nothing did, and shows no access tile to someone who is not the owner', async () => {
    backend([server({})], summary({ owlery: null }))
    renderHome()
    expect(await screen.findByText('Ночью было спокойно')).toBeInTheDocument()
    expect(screen.getByText('За сутки ничего не происходило.')).toBeInTheDocument()
    expect(screen.queryByText('Доступ к машинам')).toBeNull()
  })

  it('shows the Windows tiles only when some machine reports them, and marks a Defender find in red', async () => {
    backend([server({})], summary({
      win: { machines: 2, rdp_failed: 41, rdp_ok: 3, threats: 1, defender_off: 0 },
      jails: [{ name: 'rdp', count: 41 }],
    }))
    renderHome()
    const rdp = (await screen.findByText('Неудачные входы по RDP')).closest('a') as HTMLElement
    expect(within(rdp).getByText('41')).toBeInTheDocument()
    expect(within(rdp).getByText('успешных входов: 3')).toBeInTheDocument()
    const def = screen.getByText('Защитник Windows').closest('a') as HTMLElement
    expect(within(def).getByText('находки за сутки')).toBeInTheDocument()
    expect(screen.getByText('Удалённый рабочий стол (RDP)')).toBeInTheDocument() // the jail list names it too
  })

  it('has no Windows tiles on a farm of Linux machines', async () => {
    backend([server({})], summary())
    renderHome()
    expect(await screen.findByText('Атаки за сутки')).toBeInTheDocument()
    expect(screen.queryByText('Защитник Windows')).toBeNull()
  })

  it('invites to add the first machine when there are none', async () => {
    backend([])
    renderHome()
    expect(await screen.findByRole('link', { name: 'Добавить первую' })).toHaveAttribute('href', '/servers')
  })
})
