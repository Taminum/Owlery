import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Servers from '../pages/Servers'
import { mockApi, owner } from './helpers'

afterEach(() => vi.unstubAllGlobals())

const disk = (pct: number, m = 'C:') => ({ m, t: 100, u: pct })
const host = (cpu: number, memPct: number, diskPct: number, over: object = {}) => ({
  id: 'x', name: 'x', online: true, has_data: true, updated_at: null, os: 'Ubuntu 24.04', kernel: '', arch: '', cpu_model: '', cpus: 4, mem_total: 100, swap_total: 0,
  cpu, load1: 0, load5: 0, load15: 0, mem_used: memPct, swap_used: 0, uptime: 90_000, estab: 0, syn_recv: 0, rx_bps: 1000, tx_bps: 500, rx_pps: 0,
  disks: [disk(diskPct, '/')], procs: [], units: [], cpu_spark: [], mem_spark: [], ...over,
})
const srv = (id: string, name: string, over: object = {}) => ({
  id, name, origin: 'manual', enabled: true, note: '', created_at: '', updated_at: '', addresses: [{ id: id + 'a', address: `203.0.113.${id.length + 10}` }], links: [], can_edit: true,
  status: 'ok', reason: '', host: host(10, 30, 50), nodes: [], alerts_open: 0, alerts_critical: 0, agent: { version: 'v0.5.22', online: true, can_update: false }, ...over,
})
const fleet = [
  srv('a', 'owlery'),
  srv('bb', 'home-pc', { os: 'Windows 11', status: 'warn', host: host(28, 67, 96, { os: 'Microsoft Windows 11 Pro', disks: [disk(40, 'D:'), disk(96, 'C:')] }) }),
  srv('ccc', 'Alice-box', { status: 'unknown', host: null, agent: null }),
]
const secItems = [
  { id: 'a', name: 'owlery', summary: { agent: 'online', fail2ban: { state: 'ok', banned: 1, total_banned: 4867, jails: 2, observed_at: null }, checks: { ports_total: 3, ports_unexpected: 1, ports_down: 0, tls_total: 1, tls_problems: 0, tls_nearest_end: new Date(Date.now() + 20.5 * 86_400_000).toISOString() } } },
  { id: 'bb', name: 'home-pc', summary: { agent: 'online', fail2ban: { state: 'waiting', banned: 0, total_banned: 0, jails: 0, observed_at: null }, win: { rdp_failed: 120, rdp_ok: 2, blocked_now: 4, block_mode: 'block' } } },
  { id: 'ccc', name: 'Alice-box', summary: { agent: 'none', fail2ban: { state: 'agent_required', banned: 0, total_banned: 0, jails: 0, observed_at: null } } },
]

function open(path = '/servers') {
  setCsrf('')
  mockApi({ me: owner, handler: (r) => {
    if (r.path === '/api/v1/servers') return { status: 200, body: { servers: fleet } }
    if (r.path === '/api/v1/security/vps') return { status: 200, body: { items: secItems, can_create: true } }
    if (r.path === '/api/v1/agent/latest') return { status: 200, body: { version: 'v0.5.22' } }
    if (r.path === '/api/v1/modules') return { status: 200, body: { modules: [] } }
    return undefined
  } })
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="servers" element={<Servers />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const views = () => within(screen.getByRole('group', { name: 'Что показать' })).getAllByRole('button').map((b) => b.textContent)
const names = () => screen.getAllByRole('row').slice(1).map((r) => within(r).getAllByRole('cell')[0].textContent)

describe('servers: one page, four views', () => {
  it('offers the list, the load, the protection and the journal, and opens on the list', async () => {
    open()
    await screen.findByText('owlery')
    expect(views()).toEqual(['Машины', 'Нагрузка', 'Защита', 'Журнал'])
    expect(screen.getByRole('button', { name: 'Машины', pressed: true })).toBeInTheDocument()
  })

  it('shows the load as a table with the fullest disk first, and sorts by another column on a click', async () => {
    open('/servers?view=load')
    await screen.findByRole('table')
    expect(names()).toEqual(['home-pc', 'owlery', 'Alice-box']) // the fullest disk (96%) first; the machine with no data last
    await userEvent.click(screen.getByRole('button', { name: 'Процессор' }))
    expect(names()[0]).toBe('home-pc') // 28% against 10%: largest first on the first click
    await userEvent.click(screen.getByRole('button', { name: /^Процессор/ }))
    expect(names()[0]).toBe('owlery') // turned round
    const row = screen.getByRole('link', { name: 'home-pc' })
    expect(row).toHaveAttribute('href', '/servers/bb?view=resources')
    expect(within(row.closest('tr')!).getByRole('meter', { name: 'Диск C:: home-pc' })).toHaveAttribute('aria-valuenow', '96')
  })

  it('shows the protection: Fail2ban where it exists, the blocker on Windows, and the reason where there is nothing', async () => {
    open('/servers?view=protect')
    await screen.findByRole('table')
    const row = (n: string) => screen.getByRole('link', { name: n }).closest('tr')!
    expect(within(row('owlery')).getByText('Fail2ban')).toBeInTheDocument()
    expect(within(row('owlery')).getByText('4867')).toBeInTheDocument()
    expect(within(row('home-pc')).getByText(/Защита RDP · неудачных входов: 120/)).toBeInTheDocument()
    expect(within(row('home-pc')).getByText('4')).toBeInTheDocument() // the blocker's addresses stand where Fail2ban's bans do
    expect(within(row('owlery')).getByText('лишних: 1')).toBeInTheDocument()
    expect(within(row('owlery')).getByText('20 дн.')).toBeInTheDocument()
    expect(within(row('Alice-box')).getAllByText('—').length).toBeGreaterThanOrEqual(2)
    expect(within(row('Alice-box')).getByText('нужен агент')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'owlery' })).toHaveAttribute('href', '/servers/a?view=security')
  })

  it('narrows the machines by a search and by a filter, in every view', async () => {
    open('/servers?view=load')
    await screen.findByRole('table')
    expect(screen.getByRole('button', { name: 'Все · 3' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'С проблемами · 1' }))
    expect(names()).toEqual(['home-pc'])
    await userEvent.click(screen.getByRole('button', { name: 'Без агента · 1' }))
    expect(names()).toEqual(['Alice-box'])
    await userEvent.click(screen.getByRole('button', { name: /^Все/ }))
    await userEvent.type(screen.getByLabelText('Поиск по имени или адресу'), 'owl')
    expect(names()).toEqual(['owlery'])
    await userEvent.clear(screen.getByLabelText('Поиск по имени или адресу'))
    await userEvent.type(screen.getByLabelText('Поиск по имени или адресу'), 'нет такой')
    await waitFor(() => expect(screen.getByText('Такие машины не нашлись.')).toBeInTheDocument())
  })

  it('moves between the views and puts the choice in the address', async () => {
    open()
    await userEvent.click(await screen.findByRole('button', { name: 'Защита' }))
    expect(await screen.findByRole('table')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Защита', pressed: true })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Машины' }))
    expect(await screen.findByText('owlery')).toBeInTheDocument()
  })
})
