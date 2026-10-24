import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import Hosts from '../pages/Hosts'
import { mockApi, owner, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

function renderHosts() {
  setCsrf('')
  return render(
    <MemoryRouter initialEntries={['/hosts']}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="hosts" element={<Hosts />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const GB = 1024 ** 3
const host = (over: object) => ({
  id: 'h1', name: 'exit-nl', online: true, has_data: true, updated_at: new Date().toISOString(), os: 'Ubuntu 24.04.3 LTS', kernel: '6.8.0-147-generic', arch: 'amd64',
  cpu_model: 'Test CPU', cpus: 2, mem_total: 4 * GB, swap_total: 0, cpu: 12.4, load1: 0.31, load5: 0.2, load15: 0.1, mem_used: 2 * GB, swap_used: 0, uptime: 90000,
  disks: [{ m: '/', fs: 'ext4', t: 100 * GB, u: 93 * GB }], cpu_spark: [10, 12, null, 14], mem_spark: [50, 50, 50, 51], ...over,
})

describe('Server resources', () => {
  it('shows how much processor, memory and disk is used, and marks a nearly full disk', async () => {
    mockApi({ me: owner, handler: (r: Req) => (r.path === '/api/v1/hosts' ? { status: 200, body: { hosts: [host({})] } } : undefined) })
    renderHosts()
    expect(await screen.findByText('exit-nl')).toBeInTheDocument()
    expect(screen.getByText(/Ubuntu 24.04.3 LTS/)).toBeInTheDocument()
    expect(screen.getByRole('meter', { name: 'Процессор' })).toHaveAttribute('aria-valuenow', '12')
    expect(screen.getByRole('meter', { name: 'Память' })).toHaveAttribute('aria-valuenow', '50')
    const disk = screen.getByRole('meter', { name: 'Диск /' })
    expect(disk).toHaveAttribute('aria-valuenow', '93')
    expect(disk.firstElementChild?.className).toMatch(/bg-red/) // more than 90% is not shown in a calm colour
    expect(screen.getByText('на связи')).toBeInTheDocument()
  })

  it('says there is no data instead of showing zeros for a server whose agent has not reported', async () => {
    mockApi({ me: owner, handler: (r: Req) => (r.path === '/api/v1/hosts' ? { status: 200, body: { hosts: [host({ name: 'new-vps', has_data: false, online: false, updated_at: null, disks: [], cpu_spark: [], mem_spark: [] })] } } : undefined) })
    renderHosts()
    const card = (await screen.findByText('new-vps')).closest('section') as HTMLElement
    expect(within(card).getByText('нет данных')).toBeInTheDocument()
    expect(within(card).queryByRole('meter')).toBeNull()
  })

  it('opens the details with the machine and a period choice', async () => {
    const mock = mockApi({ me: owner, handler: (r: Req) => {
      if (r.path === '/api/v1/hosts') return { status: 200, body: { hosts: [host({})] } }
      if (r.path === '/api/v1/hosts/h1/series') return { status: 200, body: { hours: 24, points: [{ at: new Date(Date.now() - 60000).toISOString(), cpu: 10, load1: 0.3, mem_pct: 50, disk_pct: 93, rx_bps: 1000, tx_bps: 2000 }, { at: new Date().toISOString(), cpu: 20, load1: 0.4, mem_pct: 51, disk_pct: 93, rx_bps: 1500, tx_bps: 2500 }] } }
      return undefined
    } })
    renderHosts()
    await userEvent.click(await screen.findByRole('button', { name: 'подробнее' }))
    expect(await screen.findByText('6.8.0-147-generic', { exact: false })).toBeInTheDocument()
    expect(screen.getByText('Test CPU')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'неделя' }))
    expect(mock.calls.some((c) => c.url.includes('/hosts/h1/series?hours=168'))).toBe(true)
  })
})
