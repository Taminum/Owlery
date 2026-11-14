import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { setCsrf } from '../lib/api'
import { Layout } from '../components/Layout'
import ProxmoxPage from '../pages/Proxmox'
import { mockApi, owner, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

function renderIt(handler: (r: Req) => { status: number; body: unknown } | undefined) {
  setCsrf('')
  mockApi({ me: owner, handler })
  return render(
    <MemoryRouter initialEntries={['/proxmox']}>
      <AuthProvider>
        <Routes><Route element={<Layout />}><Route path="proxmox" element={<ProxmoxPage />} /></Route></Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

const host = {
  vps_id: 'v1', name: 'pve', version: '9.2.21', updated_at: '2026-11-14T12:00:00Z', fresh: true, online: true, cpus: 12, cpu: 4, mem: 5e9, mem_max: 63e9, disk: 18e9, disk_max: 100e9, up: 300000,
  ts: '100.114.204.78', lxc: 2, vms: 1, running: 2, storages: [{ name: 'local', used: 10e9, total: 50e9, backups: true, active: true }],
  guests: [
    { id: 205, kind: 'lxc', name: 'cloud', status: 'running', cpu: 2, mem: 3e9, mem_max: 6e9, disk: 88e9, disk_max: 100e9, lan: '192.168.1.205', ts: '100.81.225.100', ts_up: false, backup: 1, days_to_full: 19 },
    { id: 300, kind: 'qemu', name: 'vm1', status: 'stopped', cpu: 0, mem: 0, mem_max: 0, disk: 0, disk_max: 0 },
  ],
}

describe('Домашний сервер', () => {
  it('tells where to switch the module on while it is off', async () => {
    renderIt((r) => (r.path === '/api/v1/home/proxmox' ? { status: 200, body: { enabled: false, hosts: [] } } : undefined))
    expect(await screen.findByText(/Модуль выключен/)).toBeInTheDocument()
  })

  it('shows how to connect a host while none has reported', async () => {
    renderIt((r) => (r.path === '/api/v1/home/proxmox' ? { status: 200, body: { enabled: true, hosts: [] } } : undefined))
    expect(await screen.findByText('Подключите Proxmox')).toBeInTheDocument()
    expect(screen.getByText(/PVEAuditor/, { selector: 'pre' })).toBeInTheDocument()
  })

  it('lists the host with both kinds of guest and opens one to show its addresses and the way out of Tailscale', async () => {
    renderIt((r) => {
      if (r.path === '/api/v1/home/proxmox') return { status: 200, body: { enabled: true, hosts: [host] } }
      if (r.path === '/api/v1/alerts') return { status: 200, body: { open: 1, alerts: [{ id: 'a1', panel_id: '', panel_name: '', kind: 'pve_disk', subject: 'v1:g:205', label: 'Диск гостя почти полон: cloud (205)', detail: 'занято 88%', opened_at: '2026-11-14T11:00:00Z', last_seen_at: '2026-11-14T12:00:00Z', resolved_at: null }] } }
      return undefined
    })
    expect(await screen.findByText('cloud')).toBeInTheDocument()
    expect(screen.getByText('LXC')).toBeInTheDocument()
    expect(screen.getByText('VM')).toBeInTheDocument()
    expect(screen.getByText('остановлен')).toBeInTheDocument()
    expect(await screen.findByText(/Диск гостя почти полон/)).toBeInTheDocument()
    await userEvent.click(screen.getByText('cloud'))
    expect(screen.getByText('не в сети')).toBeInTheDocument()
    expect(screen.getByText(/кончится через ~19 дн/)).toBeInTheDocument()
  })
})
