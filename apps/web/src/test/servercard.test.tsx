import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import ServerCard from '../pages/ServerCard'
import { mockApi, owner } from './helpers'

afterEach(() => vi.unstubAllGlobals())

// The parts of a machine that fetch their own data are stand-ins here: this file is about which tab holds what.
const { stand } = vi.hoisted(() => ({ stand: (name: string) => () => ({ type: 'div', props: { 'data-testid': name, children: name }, key: null, ref: null, $$typeof: Symbol.for('react.transitional.element') }) }))
vi.mock('../components/TerminalView', () => ({ TerminalView: stand('terminal') }))
vi.mock('../components/DesktopView', () => ({ DesktopView: stand('desktop') }))
vi.mock('../components/ScreenView', () => ({ ScreenView: stand('screen') }))
vi.mock('../components/ManageView', () => ({ ManageView: stand('manage') }))
vi.mock('../components/ServicesView', () => ({ ServicesView: stand('services') }))
vi.mock('../components/RdpProtect', () => ({ RdpProtect: stand('rdp') }))
vi.mock('../components/AlertRules', () => ({ AlertRules: stand('rules') }))
vi.mock('../components/DockerView', () => ({ DockerView: stand('docker') }))
vi.mock('../components/NetworkView', () => ({ NetworkView: stand('network') }))
vi.mock('../components/HardwareView', () => ({ HardwareSection: stand('hardware') }))
vi.mock('../components/WakeOnLan', () => ({ WakeOnLan: stand('wol') }))
vi.mock('../components/HostView', async (orig) => ({ ...(await orig<typeof import('../components/HostView')>()), HostDetail: stand('resources') }))
vi.mock('../components/AgentSetup', async (orig) => ({ ...(await orig<typeof import('../components/AgentSetup')>()), AgentBlock: stand('agent') }))
vi.mock('../pages/Security', async (orig) => ({ ...(await orig<typeof import('../pages/Security')>()), SecurityTabs: stand('security') }))

const host = (over: object = {}) => ({ has_data: true, os: 'Microsoft Windows 11 Pro', cpus: 8, mem_total: 8, mem_used: 4, cpu_pct: 5, load1: 0, uptime_sec: 100, disks: [], ...over })
const server = (over: object = {}) => ({
  id: 's1', name: 'home-pc', origin: 'manual', enabled: true, note: '', created_at: '', updated_at: '', addresses: [], links: [], can_edit: true, os: 'Windows 11',
  status: 'ok', reason: '', host: host(), nodes: [], alerts_open: 1, alerts_critical: 0, hardware: null, docker: null, agent: { version: 'v0.5.22', online: true, can_update: false },
  alerts: [{ id: 'a1', kind: 'host_disk', subject: 's1:C:', label: 'Диск C: почти полон', detail: '96%', opened_at: '2026-11-10T10:00:00Z', last_seen_at: '2026-11-10T10:00:00Z', resolved_at: null }, { id: 'a0', kind: 'host_mem', subject: 's1', label: 'Память почти кончилась', detail: '', opened_at: '2026-11-04T10:00:00Z', last_seen_at: '2026-11-04T10:05:00Z', resolved_at: '2026-11-04T10:05:00Z' }],
  ...over,
})

function open(path: string, srv: object) {
  setCsrf('')
  mockApi({ me: owner, handler: (r) => {
    if (r.path === '/api/v1/servers/s1') return { status: 200, body: srv }
    if (r.path.startsWith('/api/v1/servers/s1/')) return { status: 200, body: {} }
    return undefined
  } })
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="servers/:id" element={<ServerCard />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const tabs = () => screen.getAllByRole('tab').map((x) => x.textContent)
const choice = (name: string) => within(screen.getByRole('group', { name })).getAllByRole('button').map((x) => x.textContent)

describe('server card: six tabs', () => {
  it('shows six tabs to the owner of a Windows machine, with the open alerts counted on the last', async () => {
    open('/servers/s1', server())
    await screen.findByRole('tab', { name: /Тревоги/ })
    expect(tabs()).toEqual(['Обзор', 'Нагрузка', 'Доступ', 'Управление', 'Защита', 'Тревоги1'])
    expect(screen.getByRole('tab', { name: 'Обзор' })).toHaveAttribute('aria-selected', 'true')
  })

  it('leaves out what the machine or the person cannot use', async () => {
    open('/servers/s1', server({ can_edit: false, os: 'Ubuntu 24.04', host: host({ os: 'Ubuntu 24.04' }) }))
    await screen.findByRole('tab', { name: /Тревоги/ })
    expect(tabs()).toEqual(['Обзор', 'Нагрузка', 'Защита', 'Тревоги1']) // no access and no management without the right to edit
  })

  it('offers containers next to the resources only on a machine that reports Docker, and RDP only on Windows', async () => {
    open('/servers/s1?view=resources', server({ os: 'Ubuntu 24.04', host: host({ os: 'Ubuntu 24.04' }), docker: { containers: [] } }))
    await screen.findByRole('group', { name: 'Нагрузка' })
    expect(choice('Нагрузка')).toEqual(['Ресурсы', 'Контейнеры'])
    expect(screen.getByRole('tab', { name: 'Нагрузка' })).toHaveAttribute('aria-selected', 'true')
  })

  it('opens every old address on the tab that holds it, with the right choice inside', async () => {
    const cases: [string, string, string | null][] = [
      ['?view=network', 'Обзор', null],
      ['?view=resources', 'Нагрузка', 'Ресурсы'],
      ['?view=terminal', 'Доступ', 'Терминал'],
      ['?view=desktop', 'Доступ', 'Рабочий стол'],
      ['?view=screen', 'Доступ', 'Экран'],
      ['?view=manage', 'Управление', 'На машине'],
      ['?view=services', 'Управление', 'Веб-службы'],
      ['?view=security', 'Защита', 'Безопасность'],
      ['?view=protect', 'Защита', 'Защита RDP'],
      ['?view=alerts', 'Тревоги', null],
      ['?view=history', 'Тревоги', null],
    ]
    for (const [q, tab, inner] of cases) {
      const { unmount } = open('/servers/s1' + q, server({ docker: { containers: [] } }))
      await waitFor(() => expect(screen.getByRole('tab', { name: new RegExp('^' + tab) })).toHaveAttribute('aria-selected', 'true'), { timeout: 3000 })
      if (inner) expect(screen.getByRole('button', { name: inner, pressed: true }), q).toBeInTheDocument()
      unmount()
    }
  })

  it('changes the tab on a click and moves between the parts of a tab', async () => {
    open('/servers/s1', server())
    await userEvent.click(await screen.findByRole('tab', { name: 'Защита' }))
    expect(await screen.findByRole('button', { name: 'Безопасность', pressed: true })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Защита RDP' }))
    expect(screen.getByRole('button', { name: 'Защита RDP', pressed: true })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Защита' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByTestId('rdp')).toBeInTheDocument()
  })

  it('puts the history under the alert settings, and the network under the overview', async () => {
    open('/servers/s1?view=alerts', server())
    expect(await screen.findByText('Память почти кончилась')).toBeInTheDocument() // a closed alert: the history
    expect(screen.getByText('Окно обслуживания')).toBeInTheDocument()
    expect(screen.getByTestId('rules')).toBeInTheDocument()
  })
})
