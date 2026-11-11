import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { RdpProtect } from '../components/RdpProtect'
import { setCsrf } from '../lib/api'
import { mockApi, owner, type Req } from './helpers'

afterEach(() => vi.unstubAllGlobals())

const settings = { mode: 'watch', threshold: 5, window_min: 10, ttl_hours: 24, whitelist: ['203.0.113.0/24'], share: true }
const view = (over: object = {}) => ({
  settings, supported: true, can_block: false, updated: true, online: true, can_edit: true,
  state: { mode: 'watch', threshold: 5, window_min: 10, ttl_hours: 24, total: 0, active: [], would: [{ ip: '198.51.100.7', since: '2026-11-04T10:00:00Z', failed: 6 }] },
  ...over,
})

function backend(v: object, extra?: (r: Req) => { status: number; body?: unknown } | undefined) {
  setCsrf('')
  return mockApi({ me: owner, handler: (r) => {
    if (r.method === 'GET' && r.path === '/api/v1/servers/s1/block') return { status: 200, body: v }
    return extra?.(r)
  } })
}

describe('Защита RDP', () => {
  it('shows what the blocker would have done and warns that this machine may not block', async () => {
    backend(view({ settings: { ...settings, mode: 'block' } }))
    render(<RdpProtect serverId="s1" />)
    expect(await screen.findByText('198.51.100.7')).toBeInTheDocument()
    expect(screen.getByText('6 неудач за 10 мин')).toBeInTheDocument()
    expect(screen.getByText(/не разрешает блокировку/)).toBeInTheDocument()
    expect(screen.getByText('203.0.113.0/24')).toBeInTheDocument()
  })

  it('saves what was changed, with the whitelist as it was edited', async () => {
    const api = backend(view(), (r) => (r.method === 'PUT' ? { status: 200, body: view() } : undefined))
    render(<RdpProtect serverId="s1" />)
    await screen.findByText('198.51.100.7')
    fireEvent.click(screen.getByRole('radio', { name: 'Блокирует' }))
    fireEvent.change(screen.getByLabelText('неудач за'), { target: { value: '3' } })
    fireEvent.change(screen.getByLabelText('Белый список'), { target: { value: '198.51.100.9' } })
    fireEvent.click(screen.getByRole('button', { name: 'Добавить' }))
    fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
    await waitFor(() => expect(api.find('PUT', '/api/v1/servers/s1/block')).toHaveLength(1))
    expect(api.find('PUT', '/api/v1/servers/s1/block')[0].body).toMatchObject({ mode: 'block', threshold: 3, whitelist: ['203.0.113.0/24', '198.51.100.9'] })
  })

  it('lets only someone who can edit change it, and lifts a block through the agent', async () => {
    const blocked = { mode: 'block', threshold: 5, window_min: 10, ttl_hours: 24, total: 1, would: [], active: [{ ip: '198.51.100.8', since: '2026-11-04T10:00:00Z', failed: 5 }] }
    const api = backend(view({ state: blocked, can_block: true }), (r) => (r.method === 'POST' ? { status: 200, body: { ok: true } } : undefined))
    render(<RdpProtect serverId="s1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Разблокировать' }))
    await waitFor(() => expect(api.find('POST', '/api/v1/servers/s1/block/unblock')).toHaveLength(1))
    expect(api.find('POST', '/api/v1/servers/s1/block/unblock')[0].body).toEqual({ ip: '198.51.100.8' })
  })

  it('is read-only for somebody who cannot edit', async () => {
    backend(view({ can_edit: false }))
    render(<RdpProtect serverId="s1" />)
    await screen.findByText('198.51.100.7')
    expect(screen.queryByRole('button', { name: 'Сохранить' })).toBeNull()
    expect(screen.getByRole('radio', { name: 'Блокирует' })).toBeDisabled()
  })
})

describe('Защита RDP, an agent that is too old', () => {
  it('says the agent must be updated instead of pretending the settings reach it', async () => {
    backend(view({ updated: false }))
    render(<RdpProtect serverId="s1" />)
    expect(await screen.findByText(/старой версии/)).toBeInTheDocument()
  })
})

describe('Защита RDP, the shared list', () => {
  it('counts what other machines passed on, says so in the table, and saves the choice to take part', async () => {
    const shared = { mode: 'block', threshold: 5, window_min: 10, ttl_hours: 24, total: 0, would: [], active: [{ ip: '198.51.100.9', since: '2026-11-04T10:00:00Z', failed: 0, shared: true }] }
    const api = backend(view({ state: shared, can_block: true }), (r) => (r.method === 'PUT' ? { status: 200, body: view() } : undefined))
    render(<RdpProtect serverId="s1" />)
    expect(await screen.findByText('заблокирован на другой машине парка')).toBeInTheDocument()
    expect(screen.getByText('Получено от других машин').nextSibling).toHaveTextContent('1')
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: 'Сохранить' }))
    await waitFor(() => expect(api.find('PUT', '/api/v1/servers/s1/block')).toHaveLength(1))
    expect(api.find('PUT', '/api/v1/servers/s1/block')[0].body).toMatchObject({ share: false })
  })
})

describe('Защита RDP: точное время блокировки', () => {
  it('shows when an address was blocked down to the second, and when it would have been', async () => {
    const blocked = { mode: 'block', threshold: 5, window_min: 10, ttl_hours: 24, total: 1, would: [{ ip: '198.51.100.7', since: '2026-11-04T10:00:07Z', failed: 6 }], active: [{ ip: '198.51.100.8', since: '2026-11-04T10:30:41Z', failed: 5 }] }
    backend(view({ state: blocked }))
    render(<RdpProtect serverId="s1" />)
    const row = (await screen.findByText('198.51.100.8')).closest('tr')!
    expect(within(row).getByText(/10:30:41|\d{2}:\d{2}:41/)).toBeInTheDocument() // the second is there; the hour depends on the time zone of the machine running the test
    expect(row.querySelector('td[title="2026-11-04T10:30:41.000Z"]')).not.toBeNull() // and the exact moment in UTC for whoever hovers
    expect(screen.getByRole('columnheader', { name: 'Заблокирован' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Заблокировала бы' })).toBeInTheDocument()
    const would = screen.getByText('198.51.100.7').closest('tr')!
    expect(within(would).getByText(/:07$/)).toBeInTheDocument()
  })
})
